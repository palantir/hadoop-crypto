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

@Warmup(iterations = 5)
@Measurement(iterations = 5)
@Fork(1)
public class EncryptionBenchmark {

    @org.openjdk.jmh.annotations.State(Scope.Benchmark)
    public static class State {
        private static final Random random = new Random();

        @Param({"1048576", "10485760", "104857600"})
        public int numBytes;

        public byte[] data;

        @Setup
        public void setup() {
            data = new byte[numBytes];
            random.nextBytes(data);
        }
    }

    @Benchmark
    public void gcmEncrypt(State state) throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        KeyMaterial key = KeyMaterials.generateKeyMaterial("AES", 256, 16);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(8 * 16, key.getIv());

        encrypt(state.data, cipher, key.getSecretKey(), gcmSpec);
    }

    @Benchmark
    public void ctrEncrypt(State state) throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        KeyMaterial key = KeyMaterials.generateKeyMaterial("AES", 256, 16);
        IvParameterSpec ivSpec = new IvParameterSpec(key.getIv());

        encrypt(state.data, cipher, key.getSecretKey(), ivSpec);
    }

    @Benchmark
    public void apacheEncrypt(State state) throws IOException {
        Properties props = ApacheCiphers.forceOpenSsl(new Properties());
        KeyMaterial key = KeyMaterials.generateKeyMaterial("AES", 256, 16);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CtrCryptoOutputStream output = new CtrCryptoOutputStream(
                props, baos, key.getSecretKey().getEncoded(), key.getIv());

        output.write(state.data);
    }

    public void encrypt(byte[] bytes, Cipher cipher, Key key, AlgorithmParameterSpec spec) {
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
