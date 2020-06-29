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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.crypto.stream.CtrCryptoOutputStream;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.Warmup;

@Warmup(iterations = 2, time = 1)
@Measurement(iterations = 3, time = 2)
@Fork(1)
public class EncryptionBenchmark {

    @org.openjdk.jmh.annotations.State(Scope.Benchmark)
    @SuppressWarnings("DesignForExtension") // JMH needs public non-final State classes
    public static class State {
        private static final Random random = new Random();

        @Param({"1048576", "10485760", "104857600"})
        public int numBytes;

        public byte[] data;

        public KeyMaterial key;

        @SuppressWarnings("RegexpSinglelineJava")
        @Setup
        public void setup() {
            data = new byte[numBytes];
            random.nextBytes(data);
            key = KeyMaterials.generateKeyMaterial("AES", 256, 16);
        }
    }

    @Benchmark
    public final void gcmEncrypt(State state) throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(8 * 16, state.key.getIv());

        encrypt(state.data, cipher, state.key.getSecretKey(), gcmSpec);
    }

    @Benchmark
    public final void ctrEncrypt(State state) throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(state.key.getIv());

        encrypt(state.data, cipher, state.key.getSecretKey(), ivSpec);
    }

    @Benchmark
    public final void apacheEncrypt(State state) throws IOException {
        Properties props = ApacheCiphers.forceOpenSsl(new Properties());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CtrCryptoOutputStream output = new CtrCryptoOutputStream(
                props, baos, state.key.getSecretKey().getEncoded(), state.key.getIv());

        output.write(state.data);
    }

    private void encrypt(byte[] bytes, Cipher cipher, Key key, AlgorithmParameterSpec spec) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CipherOutputStream os = new CipherOutputStream(baos, cipher);
            os.write(bytes);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
