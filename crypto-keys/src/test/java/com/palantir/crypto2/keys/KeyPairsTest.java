/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import org.junit.Before;
import org.junit.Test;

public final class KeyPairsTest {

    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    @Before
    public void before() {
        keyPair = TestKeyPairs.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    @Test
    public void testDeserialization() {
        String privateEncoded = encode(privateKey.getEncoded());
        String publicEncoded = encode(publicKey.getEncoded());
        KeyPair deserialized = KeyPairs.fromStrings(privateEncoded, publicEncoded, "RSA");

        // KeyPair does not implement equals so check each key individually
        assertThat(deserialized.getPrivate()).isEqualTo(privateKey);
        assertThat(deserialized.getPublic()).isEqualTo(publicKey);
    }

    private static String encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

}
