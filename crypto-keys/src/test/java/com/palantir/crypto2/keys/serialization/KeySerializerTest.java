/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys.serialization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.TestKeyPairs;
import java.security.KeyPair;
import java.util.Set;
import org.junit.Test;

public abstract class KeySerializerTest {

    private static final String KEY_ALG = "AES";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    private KeyPair keyPair;

    public abstract KeySerializer getSerializer();

    @Test
    public final void testIncorrectVersion() {
        keyPair = TestKeyPairs.generateKeyPair();
        KeyMaterial keyMaterial = KeyMaterials.generateKeyMaterial(KEY_ALG, KEY_SIZE, IV_SIZE);

        byte[] wrapped = getSerializer().wrap(keyMaterial, keyPair.getPublic());
        wrapped[0] = 0x00;

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> getSerializer().unwrap(wrapped, keyPair.getPrivate()))
                .withMessage("Invalid serialization format version. Expected %s but found 0",
                        getSerializer().getVersion());
    }

    final void testWrapAndUnwrap(Set<Integer> symmetricKeySizes, Set<Integer> wrappingKeySizes) {
        for (Integer symmetricKeySize : symmetricKeySizes) {
            for (Integer wrappingKeySize : wrappingKeySizes) {
                testWrapAndUnwrap(symmetricKeySize, wrappingKeySize);
            }
        }
    }

    final void testWrapAndUnwrap(int symmetricKeySize, int wrappingKeySize) {
        keyPair = TestKeyPairs.generateKeyPair(wrappingKeySize);
        KeyMaterial keyMaterial = KeyMaterials.generateKeyMaterial(KEY_ALG, symmetricKeySize, IV_SIZE);

        byte[] wrapped = getSerializer().wrap(keyMaterial, keyPair.getPublic());
        KeyMaterial unwrapped = getSerializer().unwrap(wrapped, keyPair.getPrivate());
        assertThat(keyMaterial).isEqualTo(unwrapped);
    }

}
