/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.hadoop;

import com.google.common.base.Throwables;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public final class TestKeyPairs {

    public static final int DEFAULT_KEYSIZE = 1024;

    private TestKeyPairs() {}

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
