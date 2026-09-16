/*
 * (c) Copyright 2018 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.crypto2.jmh;

import com.palantir.crypto2.cipher.ApacheCiphers;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.serialization.KeyMaterials;
import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.exceptions.SafeIllegalStateException;
import com.palantir.logsafe.exceptions.SafeRuntimeException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.crypto.stream.CtrCryptoInputStream;
import org.apache.commons.crypto.stream.CtrCryptoOutputStream;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@Warmup(iterations = 3, time = 3)
@Measurement(iterations = 4, time = 4)
@Fork(1)
public class EncryptionBenchmark {

    private static final String JDK_PROVIDER = "SunJCE";

    @org.openjdk.jmh.annotations.State(Scope.Benchmark)
    @SuppressWarnings("DesignForExtension") // JMH needs public non-final State classes
    public static class State {
        private static final Random random = new Random();

        @Param({"1048576", "10485760", "104857600"})
        public int numBytes;

        @Param
        public WriteStrategy writeStrategy;

        public byte[] data;

        public byte[] encryptedData;

        public KeyMaterial key;

        @SuppressWarnings("RegexpSinglelineJava")
        @Setup
        public void setup()
                throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
            data = new byte[numBytes];
            random.nextBytes(data);
            key = KeyMaterials.generateKeyMaterial("AES", 256, 16);
            for (WriteStrategy strategy : WriteStrategy.values()) {
                validateWriteStrategy(data, strategy);
            }
            encryptedData = createEncryptedData(data, key);
            validateDecryption(data, jdkDecrypt(writeStrategy, encryptedData, key), "JDK");
            validateDecryption(data, opensslDecrypt(writeStrategy, encryptedData, key), "OpenSSL");
        }
    }

    private static void validateWriteStrategy(byte[] data, WriteStrategy strategy) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        strategy.writeTo(data, baos);
        byte[] copy = baos.toByteArray();
        if (!Arrays.equals(data, copy)) {
            throw new SafeIllegalStateException("WriteStrategy failed", SafeArg.of("strategy", strategy));
        }
    }

    private static void validateDecryption(byte[] expected, byte[] actual, String provider) {
        if (!Arrays.equals(expected, actual)) {
            throw new SafeIllegalStateException("Decryption failed", SafeArg.of("provider", provider));
        }
    }

    public enum WriteStrategy {
        ENTIRE_BUFFER() {
            @Override
            void writeTo(byte[] input, OutputStream output) throws IOException {
                output.write(input);
            }

            @Override
            byte[] readFrom(InputStream input, int numBytes) throws IOException {
                return input.readNBytes(numBytes);
            }
        },
        CHUNKED() {
            private static final int BUFFER_SIZE = 16 * 1024;

            // Simulate a buffered write with relatively large buffers
            @Override
            void writeTo(byte[] input, OutputStream output) throws IOException {
                for (int i = 0; i < input.length; i += BUFFER_SIZE) {
                    output.write(input, i, Math.min(BUFFER_SIZE, input.length - i));
                }
            }

            @Override
            byte[] readFrom(InputStream input, int numBytes) throws IOException {
                byte[] result = new byte[numBytes];
                int offset = 0;
                while (offset < numBytes) {
                    int bytesRead = input.read(result, offset, Math.min(BUFFER_SIZE, numBytes - offset));
                    if (bytesRead < 0) {
                        return Arrays.copyOf(result, offset);
                    }
                    offset += bytesRead;
                }
                return result;
            }
        };

        abstract void writeTo(byte[] input, OutputStream output) throws IOException;

        abstract byte[] readFrom(InputStream input, int numBytes) throws IOException;
    }

    @Benchmark
    public final void gcmEncrypt(State state, Blackhole blackhole)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(8 * 16, state.key.getIv());

        encrypt(state.writeStrategy, state.data, cipher, state.key.getSecretKey(), gcmSpec, blackhole);
    }

    @Benchmark
    public final void jdkEncrypt(State state, Blackhole blackhole)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        jdkEncrypt(state.writeStrategy, state.data, state.key, blackhole);
    }

    private static void jdkEncrypt(WriteStrategy writeStrategy, byte[] data, KeyMaterial key, Blackhole blackhole)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", JDK_PROVIDER);
        IvParameterSpec ivSpec = new IvParameterSpec(key.getIv());
        encrypt(writeStrategy, data, cipher, key.getSecretKey(), ivSpec, blackhole);
    }

    @Benchmark
    public final void opensslEncrypt(State state, Blackhole blackhole) throws IOException {
        opensslEncrypt(state.writeStrategy, state.data, state.key, blackhole);
    }

    private static void opensslEncrypt(WriteStrategy writeStrategy, byte[] data, KeyMaterial key, Blackhole blackhole)
            throws IOException {
        Properties props = ApacheCiphers.forceOpenSsl(new Properties());

        try (CtrCryptoOutputStream output = new CtrCryptoOutputStream(
                props, new BlackholeOutputStream(blackhole), key.getSecretKey().getEncoded(), key.getIv())) {
            writeStrategy.writeTo(data, output);
        }
    }

    @Benchmark
    public final byte[] jdkDecrypt(State state)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        return jdkDecrypt(state.writeStrategy, state.encryptedData, state.key);
    }

    private static byte[] jdkDecrypt(WriteStrategy writeStrategy, byte[] encryptedData, KeyMaterial key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", JDK_PROVIDER);
        try {
            cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), new IvParameterSpec(key.getIv()));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new SafeRuntimeException(e);
        }
        try (CipherInputStream input = new CipherInputStream(new ByteArrayInputStream(encryptedData), cipher)) {
            return writeStrategy.readFrom(input, encryptedData.length);
        }
    }

    @Benchmark
    public final byte[] opensslDecrypt(State state) throws IOException {
        return opensslDecrypt(state.writeStrategy, state.encryptedData, state.key);
    }

    private static byte[] opensslDecrypt(WriteStrategy writeStrategy, byte[] encryptedData, KeyMaterial key)
            throws IOException {
        Properties props = ApacheCiphers.forceOpenSsl(new Properties());
        try (CtrCryptoInputStream input = new CtrCryptoInputStream(
                props,
                new ByteArrayInputStream(encryptedData),
                key.getSecretKey().getEncoded(),
                key.getIv())) {
            return writeStrategy.readFrom(input, encryptedData.length);
        }
    }

    private static byte[] createEncryptedData(byte[] data, KeyMaterial key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", JDK_PROVIDER);
        return encryptToByteArray(
                WriteStrategy.ENTIRE_BUFFER, data, cipher, key.getSecretKey(), new IvParameterSpec(key.getIv()));
    }

    private static void encrypt(
            WriteStrategy writeStrategy,
            byte[] bytes,
            Cipher cipher,
            Key key,
            AlgorithmParameterSpec spec,
            Blackhole blackhole) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            try (CipherOutputStream os = new CipherOutputStream(new BlackholeOutputStream(blackhole), cipher)) {
                writeStrategy.writeTo(bytes, os);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IOException e) {
            throw new SafeRuntimeException(e);
        }
    }

    private static byte[] encryptToByteArray(
            WriteStrategy writeStrategy, byte[] bytes, Cipher cipher, Key key, AlgorithmParameterSpec spec) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (CipherOutputStream os = new CipherOutputStream(baos, cipher)) {
                writeStrategy.writeTo(bytes, os);
            }
            return baos.toByteArray();
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IOException e) {
            throw new SafeRuntimeException(e);
        }
    }

    private static final class BlackholeOutputStream extends OutputStream {
        private final Blackhole blackhole;

        BlackholeOutputStream(Blackhole blackhole) {
            this.blackhole = blackhole;
        }

        @Override
        public void write(int value) {
            blackhole.consume(value);
        }

        @Override
        public void write(byte[] bytes, int off, int len) {
            blackhole.consume(bytes);
            blackhole.consume(off);
            blackhole.consume(len);
        }
    }

    public static void main(String[] _args) throws RunnerException {
        new Runner(new OptionsBuilder()
                        .include(EncryptionBenchmark.class.getSimpleName())
                        .build())
                .run();
    }
}
