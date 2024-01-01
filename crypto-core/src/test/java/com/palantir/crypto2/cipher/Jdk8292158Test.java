/*
 * (c) Copyright 2022 Palantir Technologies Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.palantir.crypto2.cipher;

import static com.palantir.logsafe.testing.Assertions.assertThatLoggableExceptionThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.palantir.logsafe.Arg;
import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.exceptions.SafeIllegalStateException;
import java.lang.ProcessHandle.Info;
import java.lang.Runtime.Version;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;

class Jdk8292158Test {
    private static final Version AFFECTED_JDK_11 = Version.parse("11.0.17");
    private static final Version FIXED_JDK_11 = Version.parse("11.0.18");
    private static final Version AFFECTED_JDK_17 = Version.parse("17.0.5");
    private static final Version FIXED_JDK_17 = Version.parse("17.0.6");
    private static final ImmutableList<String> architectures = ImmutableList.of("aarch64", "amd64", "x64", "x86");

    private final Info info = mock(Info.class);

    @Test
    void aesCbcIsNotAffected() {
        assertThat(Jdk8292158.isAffectedByJdkAesCtrCorruption("AES/CBC/PKCS5Padding"))
                .isFalse();
    }

    @Test
    void throwsWhenAffected() {
        assumeTrue(Jdk8292158.isAesCtrBroken());
        assumeThatThrownBy(() -> Jdk8292158.isAffectedByJdkAesCtrCorruption(AesCtrCipher.ALGORITHM))
                .isInstanceOf(SafeIllegalStateException.class)
                .hasMessageContaining("JVM and CPU architecture is affected by JDK-8292158");
    }

    @Test
    void doesNotThrowWhenNotAffected() {
        assumeFalse(Jdk8292158.isAesCtrBroken());
        assertThat(Jdk8292158.isAffectedByJdkAesCtrCorruption(AesCtrCipher.ALGORITHM))
                .isFalse();
    }

    @Test
    void aesCtrMayBeAffected() {
        assumeThatThrownBy(() -> assertThat(Jdk8292158.isAffectedByJdkAesCtrCorruption(AesCtrCipher.ALGORITHM))
                        .isFalse())
                .isInstanceOf(SafeIllegalStateException.class)
                .hasMessageContaining("JVM and CPU architecture is affected by JDK-8292158");
    }

    @Test
    void aarch64() {
        when(info.arguments()).thenReturn(Optional.empty());
        assertThat(Jdk8292158.isAffectedByJdkAesCtrCorruption(AFFECTED_JDK_11, "aarch64", info))
                .isFalse();
        assertThat(Jdk8292158.isAffectedByJdkAesCtrCorruption(AFFECTED_JDK_17, "aarch64", info))
                .isFalse();
    }

    @Test
    void unaffectedVersion() {
        when(info.arguments()).thenReturn(Optional.empty());
        architectures.forEach(arch -> {
            assertThat(Jdk8292158.isAffectedByJdkAesCtrCorruption(FIXED_JDK_11, arch, info))
                    .isFalse();
            assertThat(Jdk8292158.isAffectedByJdkAesCtrCorruption(FIXED_JDK_17, arch, info))
                    .isFalse();
        });
    }

    @Test
    void unaffectedAvx2() {
        when(info.arguments()).thenReturn(Optional.of(new String[] {"-XX:UseAVX=2"}));
        assertThat(Jdk8292158.isAffectedByJdkAesCtrCorruption(AFFECTED_JDK_11, "x64", info))
                .isFalse();
    }

    @Test
    void affected() {
        when(info.arguments()).thenReturn(Optional.empty());
        BooleanSupplier hasVectorizedAesAvx512 = () -> true;

        assertThatLoggableExceptionThrownBy(() -> Jdk8292158.isAffectedByJdkAesCtrCorruption(
                        AFFECTED_JDK_11, "x64", info, hasVectorizedAesAvx512))
                .isInstanceOf(SafeIllegalStateException.class)
                .hasMessageContaining("JVM and CPU architecture is affected by JDK-8292158. Add JVM arguments "
                        + "`-XX:+UnlockDiagnosticVMOptions -XX:-UseAESCTRIntrinsics`")
                .args()
                .satisfies(args -> {
                    assertThat(args).hasSize(3);
                    assertThat(args).allSatisfy(arg -> assertThat(arg)
                            .isInstanceOf(SafeArg.class)
                            .extracting(Arg::isSafeForLogging)
                            .asInstanceOf(InstanceOfAssertFactories.BOOLEAN)
                            .isTrue());
                })
                .extracting(Arg::getName)
                .containsExactlyInAnyOrder("architecture", "version", "jvmArgs");

        assertThatLoggableExceptionThrownBy(() -> Jdk8292158.isAffectedByJdkAesCtrCorruption(
                        AFFECTED_JDK_17, "x64", info, hasVectorizedAesAvx512))
                .isInstanceOf(SafeIllegalStateException.class)
                .hasMessageContaining("JVM and CPU architecture is affected by JDK-8292158. Add JVM arguments "
                        + "`-XX:+UnlockDiagnosticVMOptions -XX:-UseAESCTRIntrinsics`")
                .args()
                .satisfies(args -> {
                    assertThat(args).hasSize(3);
                    assertThat(args).allSatisfy(arg -> assertThat(arg)
                            .isInstanceOf(SafeArg.class)
                            .extracting(Arg::isSafeForLogging)
                            .asInstanceOf(InstanceOfAssertFactories.BOOLEAN)
                            .isTrue());
                })
                .extracting(Arg::getName)
                .containsExactlyInAnyOrder("architecture", "version", "jvmArgs");
    }

    @Test
    void cascadeLakeIsUnaffected() {
        assertThat(Jdk8292158.hasVectorizedAesCpu(Stream.of("flags\t\t: "
                        + "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat "
                        + "pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm "
                        + "constant_tsc rep_good nopl xtopology nonstop_tsc cpuid aperfmperf "
                        + "tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic "
                        + "movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor "
                        + "lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase tsc_adjust bmi1 avx2 "
                        + "smep bmi2 erms invpcid mpx avx512f avx512dq rdseed adx smap clflushopt clwb "
                        + "avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves ida arat pku ospke ")))
                .isFalse();
        assertThat(Paths.get("src/test/resources/proc-info-cascade-lake.txt")).satisfies(path -> {
            assertThat(path).isReadable().isNotEmptyFile();
            assertThat(Jdk8292158.hasVectorizedAesCpu(path)).isFalse();
        });
    }

    @Test
    void iceLakeIsAffected() {
        assertThat(Jdk8292158.hasVectorizedAesCpu(Stream.of("flags\t\t: "
                        + "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat "
                        + "pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm "
                        + "constant_tsc rep_good nopl xtopology nonstop_tsc aperfmperf eagerfpu "
                        + "pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt "
                        + "tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm "
                        + "3dnowprefetch invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced "
                        + "fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid "
                        + "avx512f avx512dq rdseed adx smap avx512ifma clflushopt clwb avx512cd sha_ni "
                        + "avx512bw avx512vl xsaveopt xsavec xgetbv1 ida arat avx512vbmi pku ospke "
                        + "avx512_vbmi2 gfni vaes vpclmulqdq avx512_vnni avx512_bitalg avx512_vpopcntdq "
                        + "md_clear spec_ctrl intel_stibp flush_l1d arch_capabilities")))
                .isTrue();

        assertThat(Paths.get("src/test/resources/proc-info-ice-lake.txt")).satisfies(path -> {
            assertThat(path).isReadable().isNotEmptyFile();
            assertThat(Jdk8292158.hasVectorizedAesCpu(path)).isTrue();
        });
    }

    @Test
    void affectedWhenAllCpuFlags() {
        assertThat(Jdk8292158.hasVectorizedAesCpu(Stream.of("flags : avx512bw avx512vl vaes vpclmulqdq")))
                .as("Affected when all four CPU flags exist: %s", Jdk8292158.jdk8292158ImpactedCpuFlags)
                .isTrue();

        assertThat(Jdk8292158.hasVectorizedAesCpu(Stream.of("flags : aes avx512")))
                .as("not affected with just aes and avx512")
                .isFalse();

        // must have all 4 flags to be affected
        assertThat(Jdk8292158.hasVectorizedAesCpu(Stream.of("flags : avx512bw")))
                .isFalse();
        assertThat(Jdk8292158.hasVectorizedAesCpu(Stream.of("flags : avx512vl")))
                .isFalse();
        assertThat(Jdk8292158.hasVectorizedAesCpu(Stream.of("flags : vaes"))).isFalse();
        assertThat(Jdk8292158.hasVectorizedAesCpu(Stream.of("flags : vpclmulqdq")))
                .isFalse();
    }

    @Test
    void cpuFlagsNoAesAndAvx512() {
        assertThat(Jdk8292158.hasVectorizedAesCpu(Stream.of("flags  : aes avx avx2 sse2")))
                .isFalse();
        assertThat(Jdk8292158.hasVectorizedAesCpu(Stream.of("flags  : fpu avx avx2 avx512")))
                .isFalse();

        assertThat(Paths.get("src/test/resources/proc-info-no-avx512.txt")).satisfies(path -> {
            assertThat(path).isReadable().isNotEmptyFile();
            assertThat(Jdk8292158.hasVectorizedAesCpu(path)).isFalse();
        });
    }
}
