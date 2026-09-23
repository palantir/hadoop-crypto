#!/usr/bin/env bash
#
# (c) Copyright 2026 Palantir Technologies Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

usage() {
    cat <<'EOF'
Run the comparable AES-CTR benchmark matrix serially on JDK 21 and JDK 25.

Usage:
  JAVA_HOME_21=/path/to/jdk-21 JAVA_HOME_25=/path/to/jdk-25 \
    ./benchmark-encryption.sh [output-directory]

The default output directory is:
  benchmark-results/encryption/<host>-<UTC timestamp>

Optional environment variables:
  HOST_LABEL        Name used in output filenames (defaults to short hostname)
  GRADLE_USER_HOME  Gradle cache location (defaults to Gradle's normal location)
  LD_LIBRARY_PATH   Additional native-library locations for Commons Crypto/OpenSSL

The run takes approximately five minutes per JDK and produces:
  <host>-jdk21-blackhole-chunked.txt
  <host>-jdk21-blackhole-chunked.json
  <host>-jdk25-blackhole-chunked.txt
  <host>-jdk25-blackhole-chunked.json
  <host>-metadata.txt

Run on an otherwise idle host. Do not compare results produced from different
repository revisions or with different CPU power/frequency policies.
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    usage
    exit 0
fi

if (( $# > 1 )); then
    usage >&2
    exit 2
fi

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repo_dir="$script_dir"
readonly wrapper_jar="$repo_dir/gradle/wrapper/gradle-wrapper.jar"

if [[ ! -f "$wrapper_jar" || ! -f "$repo_dir/settings.gradle" ]]; then
    echo "Run this script from a complete hadoop-crypto checkout." >&2
    exit 1
fi

if [[ -z ${JAVA_HOME_21:-} || -z ${JAVA_HOME_25:-} ]]; then
    echo "JAVA_HOME_21 and JAVA_HOME_25 must both be set." >&2
    usage >&2
    exit 2
fi

raw_host_label="${HOST_LABEL:-$(hostname -s 2>/dev/null || hostname)}"
host_label="$(printf '%s' "$raw_host_label" | tr -cs '[:alnum:]_.-' '-')"
host_label="${host_label#-}"
host_label="${host_label%-}"
if [[ -z "$host_label" ]]; then
    echo "HOST_LABEL must contain at least one letter or number." >&2
    exit 2
fi
readonly host_label

readonly timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
output_dir="${1:-$repo_dir/benchmark-results/encryption/$host_label-$timestamp}"

# build.gradle currently splits the JMH argument string on spaces.
if [[ "$output_dir" == *[[:space:]]* ]]; then
    echo "The output directory cannot contain whitespace: $output_dir" >&2
    exit 2
fi

validate_jdk() {
    local expected_major=$1
    local java_home=$2
    local java_bin="$java_home/bin/java"
    local actual_major

    if [[ ! -x "$java_bin" ]]; then
        echo "JDK $expected_major java executable not found: $java_bin" >&2
        exit 1
    fi

    actual_major="$("$java_bin" -XshowSettings:properties -version 2>&1 \
        | awk -F'= ' '/java.specification.version =/{print $2; exit}')"
    if [[ "$actual_major" != "$expected_major" ]]; then
        echo "Expected JDK $expected_major at $java_home, found Java $actual_major." >&2
        exit 1
    fi
}

validate_jdk 21 "$JAVA_HOME_21"
validate_jdk 25 "$JAVA_HOME_25"

if ! git -C "$repo_dir" diff --quiet || ! git -C "$repo_dir" diff --cached --quiet; then
    echo "WARNING: The checkout has tracked modifications." >&2
    echo "Only compare hosts that use identical source; details are recorded in metadata." >&2
fi

mkdir -p "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd -P)"
readonly output_dir
readonly metadata_file="$output_dir/$host_label-metadata.txt"
for output_file in \
    "$metadata_file" \
    "$output_dir/$host_label-jdk21-blackhole-chunked.txt" \
    "$output_dir/$host_label-jdk21-blackhole-chunked.json" \
    "$output_dir/$host_label-jdk25-blackhole-chunked.txt" \
    "$output_dir/$host_label-jdk25-blackhole-chunked.json"; do
    if [[ -e "$output_file" ]]; then
        echo "Refusing to overwrite existing output: $output_file" >&2
        exit 1
    fi
done

{
    echo "timestamp_utc=$timestamp"
    echo "host_label=$host_label"
    echo "git_commit=$(git -C "$repo_dir" rev-parse HEAD)"
    echo "git_describe=$(git -C "$repo_dir" describe --always --dirty)"
    echo "git_status:"
    git -C "$repo_dir" status --short
    echo "uname=$(uname -a)"
    echo
    echo "JDK 21:"
    "$JAVA_HOME_21/bin/java" -version 2>&1
    echo
    echo "JDK 25:"
    "$JAVA_HOME_25/bin/java" -version 2>&1
    echo
    echo "OpenSSL:"
    if command -v openssl >/dev/null 2>&1; then
        openssl version -a
    else
        echo "openssl command not found; Commons Crypto may still use a system library"
    fi
    echo
    echo "CPU:"
    if command -v lscpu >/dev/null 2>&1; then
        lscpu
    elif [[ -r /proc/cpuinfo ]]; then
        sed -n '1,80p' /proc/cpuinfo
    else
        echo "CPU metadata unavailable"
    fi
} >"$metadata_file"

run_benchmark() {
    local major=$1
    local java_home=$2
    local stem="$output_dir/$host_label-jdk$major-blackhole-chunked"
    local text_file="$stem.txt"
    local json_file="$stem.json"
    local jmh_args
    local -a gradle_command

    if [[ -e "$text_file" || -e "$json_file" ]]; then
        echo "Refusing to overwrite existing results for JDK $major in $output_dir." >&2
        exit 1
    fi

    # Invoke the wrapper JAR directly. The checked-in ./gradlew intentionally
    # pins the Gradle daemon to JDK 21, which would otherwise make the JDK 25
    # benchmark run on JDK 21 as well.
    gradle_command=(
        "$java_home/bin/java"
        "-Dorg.gradle.appname=gradlew"
        "-Dorg.gradle.java.home=$java_home"
        -classpath "$wrapper_jar"
        org.gradle.wrapper.GradleWrapperMain
    )

    jmh_args="com.palantir.crypto2.jmh.EncryptionBenchmark.(jdk|openssl)(Encrypt|Decrypt)"
    jmh_args+=" -bm thrpt -t 1 -f 1"
    jmh_args+=" -wi 3 -w 3s -i 4 -r 4s -to 10m"
    jmh_args+=" -p numBytes=1048576,10485760,104857600"
    jmh_args+=" -p writeStrategy=CHUNKED -prof gc"
    jmh_args+=" -rf json -rff $json_file"

    echo "Running JDK $major benchmark; output: $stem.{txt,json}"
    (
        cd "$repo_dir"
        JAVA_HOME="$java_home" "${gradle_command[@]}" \
            --no-daemon --console=plain -q \
            :crypto-core:benchmarks "-Pjmh=$jmh_args"
    ) | tee "$text_file"

    if [[ ! -s "$json_file" ]]; then
        echo "JMH did not produce JSON output for JDK $major: $json_file" >&2
        exit 1
    fi
}

echo "Writing host metadata to $metadata_file"
echo "Runs are serial and should take approximately ten minutes total."
run_benchmark 21 "$JAVA_HOME_21"
run_benchmark 25 "$JAVA_HOME_25"

echo "Benchmark runs complete: $output_dir"
