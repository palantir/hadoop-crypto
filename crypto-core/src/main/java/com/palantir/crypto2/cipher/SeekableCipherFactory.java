/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.cipher;

import com.palantir.crypto2.keys.KeyMaterial;

public final class SeekableCipherFactory {

    private SeekableCipherFactory() {}

    /**
     * Generates {@link KeyMaterial} appropriate for the given cipher algorithm. Currently only supports
     * {@value AesCtrCipher#ALGORITHM} and {@value AesCbcCipher#ALGORITHM}.
     */
    public static KeyMaterial generateKeyMaterial(String cipherAlgorithm) {
        switch (cipherAlgorithm) {
            case AesCtrCipher.ALGORITHM:
                return AesCtrCipher.generateKeyMaterial();
            case AesCbcCipher.ALGORITHM:
                return AesCbcCipher.generateKeyMaterial();
            default:
                throw new IllegalArgumentException(
                        String.format("No known SeekableCipher with algorithm: %s", cipherAlgorithm));
        }
    }

    /**
     * @deprecated This method has been found to be error prone because consumers are not forced to handle the generated
     * {@link KeyMaterial} explicitly. Use {@link #generateKeyMaterial(String)} and {@link #getCipher(String,
     * KeyMaterial)} directly.
     * <p>
     * ex: https://github.com/palantir/hadoop-crypto/pull/77
     */
    @Deprecated
    public static SeekableCipher getCipher(String cipherAlgorithm) {
        switch (cipherAlgorithm) {
            case AesCtrCipher.ALGORITHM:
                return getCipher(cipherAlgorithm, AesCtrCipher.generateKeyMaterial());
            case AesCbcCipher.ALGORITHM:
                return getCipher(cipherAlgorithm, AesCbcCipher.generateKeyMaterial());
            default:
                throw new IllegalArgumentException(
                        String.format("No known SeekableCipher with algorithm: %s", cipherAlgorithm));
        }
    }

    /**
     * Constructs the proper {@link SeekableCipher} for the given {@code cipherAlgorithm} and initializes it with the
     * given {@link KeyMaterial}.
     */
    public static SeekableCipher getCipher(String cipherAlgorithm, KeyMaterial keyMaterial) {
        switch (cipherAlgorithm) {
            case AesCtrCipher.ALGORITHM:
                return new AesCtrCipher(keyMaterial);
            case AesCbcCipher.ALGORITHM:
                return new AesCbcCipher(keyMaterial);
            default:
                throw new IllegalArgumentException(
                        String.format("No known SeekableCipher with algorithm: %s", cipherAlgorithm));
        }
    }

}
