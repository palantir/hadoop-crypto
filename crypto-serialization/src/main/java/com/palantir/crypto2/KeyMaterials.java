/*
 * Copyright 2016 Palantir Technologies, Inc. All rights reserved.
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

package com.palantir.crypto2;

import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utilities for {@link KeyMaterial} generation and serialization. The KeyMaterial is securely serialized by wrapping
 * the {@link SecretKey} using the given {@link PublicKey} and deserialized by unwrapping the SecretKey using the given
 */
public final class KeyMaterials {

    private static final Logger log = LoggerFactory.getLogger(KeyMaterials.class);
    private static final Map<Integer, ? extends KeySerializer> SERIALIZERS = KeySerializers.getSerializers();

    private KeyMaterials() {}

    public static SecretKey generateKey(String keyAlgorithm, int keySize) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgorithm);
            keyGen.init(getSafeKeyLength(keyAlgorithm, keySize));
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw Throwables.propagate(e);
        }
    }

    public static byte[] generateIv(int ivSize) {
        byte[] iv = new byte[ivSize];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(iv);
        return iv;
    }

    public static KeyMaterial generateKeyMaterial(String keyAlgorithm, int keySize, int ivSize) {
        SecretKey key = generateKey(keyAlgorithm, keySize);
        byte[] iv = generateIv(ivSize);
        return KeyMaterial.of(key, iv);
    }

    public static SerializableKeyMaterial serialize(KeyMaterial keyMaterial) {
        SecretKey key = keyMaterial.getSecretKey();
        return SerializableKeyMaterial.of(key.getAlgorithm(), key.getEncoded(), keyMaterial.getIv());
    }

    public static KeyMaterial deserialize(SerializableKeyMaterial keyMaterial) {
        String algorithm = keyMaterial.getAlgorithm();
        byte[] encodedKey = keyMaterial.getEncodedKey();
        byte[] iv = keyMaterial.getIv();
        return KeyMaterial.of(new SecretKeySpec(encodedKey, algorithm), iv);
    }

    public static byte[] wrap(KeyMaterial keyMaterial, PublicKey key) {
        return KeySerializerV2.INSTANCE.wrap(keyMaterial, key);
    }

    public static KeyMaterial unwrap(byte[] wrappedKeyMaterial, PrivateKey key) {
        DataInputStream stream = new DataInputStream(new ByteArrayInputStream(wrappedKeyMaterial));

        try {
            int version = stream.read();
            Preconditions.checkArgument(SERIALIZERS.containsKey(version),
                    "Invalid serialization format version. Expected version in %s but found %s",
                    SERIALIZERS.keySet(), version);

            return SERIALIZERS.get(version).unwrap(wrappedKeyMaterial, key);
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
    }

    /**
     * Returns a key length for the provided algorithm that is at most the desired length but not more than this JVM
     * supports.
     *
     * @param algorithm the key algorithm to be used
     * @param desiredLength the desired key length
     * @return a length that is the smaller of provided key size and the maximum allowed for that algorithm on this JVM
     * @throws InvalidKeyException when desired key length exceeds maximum allowable unless environmental variable
     * {@code OVERRIDE_KEY_SAFETY_PROTECTIONS} is set and true
     */
    public static int getSafeKeyLength(String algorithm, int desiredLength) throws InvalidKeyException {
        int maxAllowedKeyLength;
        try {
            maxAllowedKeyLength = Cipher.getMaxAllowedKeyLength(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw Throwables.propagate(e);
        }
        int safeSize = Math.min(maxAllowedKeyLength, desiredLength);
        if (safeSize < desiredLength) {
            if (!Boolean.valueOf(System.getenv("OVERRIDE_KEY_SAFETY_PROTECTIONS"))) {
                throw new InvalidKeyException(String.format(
                        "Requested key length %d exceeds JVM allowable key length %d for %s",
                        desiredLength, maxAllowedKeyLength, algorithm));
            }
            log.warn("Requested key length {} exceeds JVM allowable key length for algorithm {}, using key size: {}",
                    desiredLength, algorithm, maxAllowedKeyLength);
        }
        return safeSize;
    }

}
