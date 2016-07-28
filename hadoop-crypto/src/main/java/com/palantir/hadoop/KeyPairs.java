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

package com.palantir.hadoop;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Optional;
import com.google.common.base.Throwables;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.annotation.Nullable;
import org.apache.commons.net.util.Base64;

public final class KeyPairs {

    public static final int DEFAULT_KEYSIZE = 1024;

    private KeyPairs() {}

    public static KeyPair fromStrings(@Nullable String privateKeyString, String publicKeyString, String algorithm) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            // Private key is only required for decryption, can be null
            Optional<PrivateKey> privateKey = Optional.absent();
            if (privateKeyString != null) {
                KeySpec privateKs = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyString));
                privateKey = Optional.of(keyFactory.generatePrivate(privateKs));
            }

            KeySpec publicKs = new X509EncodedKeySpec(Base64.decodeBase64(publicKeyString));

            return new KeyPair(keyFactory.generatePublic(publicKs), privateKey.orNull());
        } catch (GeneralSecurityException e) {
            throw Throwables.propagate(e);
        }
    }

    @VisibleForTesting
    public static KeyPair generateKeyPair() {
        return generateKeyPair(DEFAULT_KEYSIZE);
    }

    public static KeyPair generateKeyPair(int keysize) {
        KeyPairGenerator keyGen;
        SecureRandom random;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw Throwables.propagate(e);
        }
        keyGen.initialize(keysize, random);
        return keyGen.generateKeyPair();
    }

}
