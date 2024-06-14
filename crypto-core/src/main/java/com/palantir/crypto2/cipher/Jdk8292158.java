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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Splitter;
import com.google.common.base.Suppliers;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.io.BaseEncoding;
import com.palantir.logsafe.Preconditions;
import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.UnsafeArg;
import com.palantir.logsafe.exceptions.SafeIllegalStateException;
import com.palantir.logsafe.logger.SafeLogger;
import com.palantir.logsafe.logger.SafeLoggerFactory;
import java.io.IOException;
import java.lang.ProcessHandle.Info;
import java.lang.Runtime.Version;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Determine if JVM is impacted by https://bugs.openjdk.org/browse/JDK-8292158 which can corrupt AES-CTR encryption
 * streams. This bug impacts JDKs up to 11.0.18, 15.0.10, 17.0.6, 19.0.2 and when running on CPUs with AVX-512
 * vectorized AES support.
 */
public final class Jdk8292158 {
    private static final SafeLogger log = SafeLoggerFactory.get(Jdk8292158.class);
    private static final ImmutableSet<String> argsToDisableAesCtrIntrinsics =
            ImmutableSet.of("-XX:UseAVX=2", "-XX:-UseAES", "-XX:-UseAESCTRIntrinsics", "-XX:-UseAESIntrinsics");

    // see StubGenerator::generate_aes_stubs in
    // https://github.com/openjdk/jdk/blob/master/src/hotspot/cpu/x86/stubGenerator_x86_64_aes.cpp#L160
    @VisibleForTesting
    static final ImmutableSet<String> jdk8292158ImpactedCpuFlags =
            ImmutableSet.of("vaes", "avx512bw", "avx512vl", "vpclmulqdq");

    private static final Supplier<Boolean> isAffectedByJdkAesCtrCorruption =
            Suppliers.memoize(() -> isAffectedByJdkAesCtrCorruption(
                    Runtime.version(), architecture(), ProcessHandle.current().info()));

    private Jdk8292158() {}

    public static SafeIllegalStateException cannotEncryptAesCtrSafely() {
        throw cannotEncryptAesCtrSafely(
                Runtime.version(),
                architecture(),
                getJvmArgs(ProcessHandle.current().info()));
    }

    private static SafeIllegalStateException cannotEncryptAesCtrSafely(
            Version version, String architecture, ImmutableSet<String> args) {
        throw new SafeIllegalStateException(
                "JVM and CPU architecture is affected by JDK-8292158."
                        + " Add JVM arguments `-XX:+UnlockDiagnosticVMOptions -XX:-UseAESCTRIntrinsics`"
                        + " to disable AES-CTR intrinsics until a fixed JVM is available.",
                SafeArg.of("architecture", architecture),
                SafeArg.of("version", version),
                SafeArg.of("jvmArgs", args));
    }

    /**
     * Determines if this JVM and CPU is affected by JDK-8292158 AES-CTR corruption.
     * @param algorithm cipher algorithm
     * @return false if this JVM and CPU is not affected by JDK-8292158 AES-CTR corruption
     * @throws SafeIllegalStateException is this JVM and CPU is affected by JDK-8292158 AES-CTR corruption
     */
    public static boolean isAffectedByJdkAesCtrCorruption(@Nullable String algorithm) {
        return algorithm != null && algorithm.contains("AES/CTR") && isAffectedByJdkAesCtrCorruption.get();
    }

    @VisibleForTesting
    static boolean isAffectedByJdkAesCtrCorruption(Version version, String architecture, Info info) {
        BooleanSupplier cpuHasAvx512 = () -> hasVectorizedAesCpu(Paths.get("/proc/cpuinfo"));
        return isAffectedByJdkAesCtrCorruption(version, architecture, info, cpuHasAvx512);
    }

    @VisibleForTesting
    @SuppressWarnings("checkstyle:CyclomaticComplexity")
    static boolean isAffectedByJdkAesCtrCorruption(
            Version version, String architecture, Info info, BooleanSupplier cpuHasAvx512) {
        if (isAesCtrBroken()) {
            return true;
        }
        int featureVersion = version.feature();
        if (featureVersion >= 20) {
            // https://git.openjdk.org/jdk/commit/9d76ac8a4453bc51d9dca2ad6c60259cfb2c4203 in jdk-20+17
            return false;
        }
        if (featureVersion < 11) {
            // introduced in JDK 14 for https://bugs.openjdk.org/browse/JDK-8233741 /
            // https://github.com/openjdk/jdk/commit/a6649eb089e4c9beb8b7f654db454710b4c7ef4a
            // backported to JDK 11.0.9 in
            // https://github.com/openjdk/jdk11u/commit/68b8506ad817d97738735ef1f3acdead9fb6e222
            return false;
        }

        // fixed versions
        if (featureVersion == 11 && version.compareTo(Version.parse("11.0.18")) >= 0) {
            // https://bugs.openjdk.org/browse/JDK-8295297
            return false;
        }
        if (featureVersion == 15 && version.compareTo(Version.parse("15.0.10")) >= 0) {
            // https://bugs.openjdk.org/browse/JDK-8295781
            return false;
        }
        if (featureVersion == 17 && version.compareTo(Version.parse("17.0.6")) >= 0) {
            // https://bugs.openjdk.org/browse/JDK-8295296
            return false;
        }
        if (featureVersion == 19 && version.compareTo(Version.parse("19.0.2")) >= 0) {
            // https://bugs.openjdk.org/browse/JDK-8295905
            return false;
        }

        if (!"amd64".equals(architecture) && !"x64".equals(architecture) && !"x86".equals(architecture)) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Architecture is not affected by JDK-8292158",
                        SafeArg.of("architecture", architecture),
                        SafeArg.of("version", version));
            }
            return false;
        }

        ImmutableSet<String> jvmArgs = getJvmArgs(info);
        if (cpuHasAvx512.getAsBoolean()
                && argsToDisableAesCtrIntrinsics.stream().noneMatch(jvmArgs::contains)) {
            throw cannotEncryptAesCtrSafely(version, architecture, jvmArgs);
        }

        if (log.isDebugEnabled()) {
            log.debug(
                    "JVM is not affected by JDK-8292158",
                    SafeArg.of("architecture", architecture),
                    SafeArg.of("version", version),
                    SafeArg.of("jvmArgs", jvmArgs),
                    SafeArg.of("cpuHasAvx512", cpuHasAvx512.getAsBoolean()));
        }
        return false;
    }

    private static String architecture() {
        return System.getProperty("os.arch");
    }

    private static ImmutableSet<String> getJvmArgs(Info info) {
        return info.arguments().stream()
                .flatMap(Arrays::stream)
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(arg -> arg.startsWith("-XX:"))
                .collect(ImmutableSortedSet.toImmutableSortedSet(Comparator.naturalOrder()));
    }

    @VisibleForTesting
    static boolean hasVectorizedAesCpu(Path path) {
        if (!Files.isReadable(path)) {
            return false;
        }

        try (Stream<String> lines = Files.lines(path)) {
            return hasVectorizedAesCpu(lines);
        } catch (IOException e) {
            return false;
        }
    }

    @VisibleForTesting
    static boolean hasVectorizedAesCpu(Stream<String> lines) {
        // See https://en.wikipedia.org/wiki/AVX-512#CPUs_with_AVX-512
        Splitter splitter = Splitter.onPattern("\\s+").trimResults().omitEmptyStrings();
        Set<String> flags = lines.filter(Objects::nonNull)
                .map(String::trim)
                .filter(line -> line.startsWith("flags"))
                .map(String::toLowerCase)
                .flatMap(splitter::splitToStream)
                .collect(ImmutableSortedSet.toImmutableSortedSet(Comparator.naturalOrder()));
        return flags.containsAll(jdk8292158ImpactedCpuFlags);
    }

    @VisibleForTesting
    static boolean isAesCtrBroken() {
        try {
            for (int i = 8; i <= 32; i++) {
                testEncryptDecrypt(i);
            }
            return false;
        } catch (NoSuchProviderException e) {
            log.warn("AES-CTR test failed due to no such provider", e);
            return false;
        } catch (GeneralSecurityException | Error | RuntimeException e) {
            log.error("AES-CTR AES-CTR encryption/decryption round-trip failed", e);
            return true;
        }
    }

    static void testEncryptDecrypt(int length) throws GeneralSecurityException {
        Preconditions.checkArgument(length > 4, "length must be at least 4");

        long seed = ThreadLocalRandom.current().nextLong();
        if (log.isDebugEnabled()) {
            log.debug(
                    "Testing AES-CTR encryption/decryption for JDK-829158",
                    SafeArg.of("seed", seed),
                    SafeArg.of("length", length));
        }

        Random random = new Random(seed);

        byte[] key = new byte[32];
        random.nextBytes(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
        encrypt.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");
        decrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] cleartext = new byte[length];
        byte[] encrypted = new byte[length];
        byte[] decrypted = new byte[length];

        for (int i = 0; i < 10_000; i++) {
            random.nextBytes(cleartext);
            encrypt.doFinal(cleartext, 0, length, encrypted);

            // use decrypt cipher at least 3 times
            decrypt.update(encrypted, 0, 1, decrypted, 0);
            decrypt.update(encrypted, 1, 1, decrypted, 1);
            decrypt.doFinal(encrypted, 2, length - 2, decrypted, 2);

            if (!Arrays.equals(cleartext, decrypted)) {
                throw new SafeIllegalStateException(
                        "AES-CTR encryption/decryption round trip failed",
                        cannotEncryptAesCtrSafely(),
                        SafeArg.of("seed", seed),
                        SafeArg.of("length", length),
                        SafeArg.of("iteration", i),
                        UnsafeArg.of("cleartext", BaseEncoding.base16().encode(cleartext)),
                        UnsafeArg.of("decrypted", BaseEncoding.base16().encode(decrypted)),
                        UnsafeArg.of("encrypted", BaseEncoding.base16().encode(encrypted)),
                        UnsafeArg.of("key", BaseEncoding.base16().encode(key)),
                        UnsafeArg.of("iv", BaseEncoding.base16().encode(iv)));
            }
        }
    }
}
