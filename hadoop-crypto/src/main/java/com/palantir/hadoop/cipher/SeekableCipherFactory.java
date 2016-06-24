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

package com.palantir.hadoop.cipher;

import com.palantir.hadoop.KeyMaterial;

/**
 * Constructs the proper {@link SeekableCipher} for a given {@code cipherAlgorithm} string. The {@link KeyMaterial} will
 * be generated if it is not provided.
 */
public final class SeekableCipherFactory {

    private SeekableCipherFactory() {}

    public static SeekableCipher getCipher(String cipherAlgorithm) {
        if (cipherAlgorithm.equals(AesCtrCipher.ALGORITHM)) {
            KeyMaterial keyMaterial = AesCtrCipher.generateKeyMaterial();
            return getCipher(cipherAlgorithm, keyMaterial);
        } else if (cipherAlgorithm.equals(AesCbcCipher.ALGORITHM)) {
            KeyMaterial keyMaterial = AesCbcCipher.generateKeyMaterial();
            return getCipher(cipherAlgorithm, keyMaterial);
        } else {
            throw new IllegalArgumentException(
                    String.format("No known SeekableCipher with algorithm: %s", cipherAlgorithm));
        }
    }

    public static SeekableCipher getCipher(String cipherAlgorithm, KeyMaterial keyMaterial) {
        if (cipherAlgorithm.equals(AesCtrCipher.ALGORITHM)) {
            return new AesCtrCipher(keyMaterial);
        } else if (cipherAlgorithm.equals(AesCbcCipher.ALGORITHM)) {
            return new AesCbcCipher(keyMaterial);
        } else {
            throw new IllegalArgumentException(
                    String.format("No known SeekableCipher with algorithm: %s", cipherAlgorithm));
        }
    }

}
