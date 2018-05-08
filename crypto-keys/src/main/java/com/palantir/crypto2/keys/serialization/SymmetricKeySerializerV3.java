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

package com.palantir.crypto2.keys.serialization;

import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;
import com.palantir.crypto2.keys.KeyMaterial;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Serializer for wrapping and unwrapping {@link KeyMaterial}. The {@link #wrap} method returns the KeyMaterial
 * serialized as follows, which is the same format the {@link #unwrap} method expects:
 *
 * <pre>
 *  +--------------------------------------------------------------+
 *  | version | wrapping iv | key algorithm length | key algorithm |
 *  |   byte  |    byte[]   |          int         |     byte[]    |
 *  +--------------------------------------------------------------+
 *  +-------------------------------------------------------+
 *  | wrapped key length | wrapped key | iv length |   iv   |
 *  |        int         |    byte[]   |    int    | byte[] |
 *  +-------------------------------------------------------+
 * </pre>
 */
enum SymmetricKeySerializerV3 implements SymmetricKeySerializer {
    INSTANCE;

    private static final String AES_CTR_NO_PADDING = "AES/CTR/NoPadding";
    private static final int IV_SIZE = 16;

    static final int VERSION = 3;

    @Override
    public byte[] wrap(KeyMaterial keyMaterial, SecretKey key) {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream stream = new DataOutputStream(byteStream);

        byte[] wrappingIv = KeyMaterials.generateIv(IV_SIZE);
        Cipher keyWrappingCipher = getCipher(Cipher.WRAP_MODE, key, wrappingIv);
        SecretKey secretKey = keyMaterial.getSecretKey();

        try {
            stream.write(VERSION);

            stream.write(wrappingIv);

            String keyAlgorithm = secretKey.getAlgorithm();
            stream.writeInt(keyAlgorithm.length());
            stream.write(keyAlgorithm.getBytes(StandardCharsets.UTF_8));

            byte[] encryptedKey = keyWrappingCipher.wrap(secretKey);
            stream.writeInt(encryptedKey.length);
            stream.write(encryptedKey);

            byte[] iv = keyMaterial.getIv();
            stream.writeInt(iv.length);
            stream.write(iv);

            stream.close();
            return byteStream.toByteArray();
        } catch (IOException | InvalidKeyException | IllegalBlockSizeException e) {
            throw new RuntimeException("Unable to wrap key", e);
        }
    }

    @Override
    public KeyMaterial unwrap(byte[] wrappedKeyMaterial, SecretKey key) {
        DataInputStream stream = new DataInputStream(new ByteArrayInputStream(wrappedKeyMaterial));

        try {
            int version = stream.read();
            Preconditions.checkArgument(VERSION == version,
                    "Invalid serialization format version. Expected %s but found %s", VERSION, version);

            byte[] wrappingIv = new byte[IV_SIZE];
            stream.read(wrappingIv);
            Cipher keyUnwrappingCipher = getCipher(Cipher.UNWRAP_MODE, key, wrappingIv);

            int algorithmLength = stream.readInt();
            byte[] algorithmBytes = new byte[algorithmLength];
            stream.readFully(algorithmBytes);

            int keyLength = stream.readInt();
            byte[] secretKeyBytes = new byte[keyLength];
            stream.readFully(secretKeyBytes);

            int ivLength = stream.readInt();
            byte[] iv = new byte[ivLength];
            stream.readFully(iv);

            String algorithm = new String(algorithmBytes, StandardCharsets.UTF_8);
            SecretKey secretKey = (SecretKey) keyUnwrappingCipher.unwrap(secretKeyBytes, algorithm, Cipher.SECRET_KEY);
            return KeyMaterial.of(secretKey, iv);
        } catch (InvalidKeyException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException("Unable to unwrap key", e);
        }
    }

    @Override
    public int getVersion() {
        return VERSION;
    }

    static Cipher getCipher(int cipherMode, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(AES_CTR_NO_PADDING);
            cipher.init(cipherMode, key, new IvParameterSpec(iv));
            return cipher;
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidKeyException
                | InvalidAlgorithmParameterException e) {
            throw Throwables.propagate(e);
        }
    }
}
