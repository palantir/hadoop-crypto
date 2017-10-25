/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys.serialization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.TestKeyPairs;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.SecretKey;
import org.junit.Before;
import org.junit.Test;

public final class KeyMaterialsTest {

    private static final String KEY_ALG = "AES";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    private KeyMaterial keyMaterial;
    private KeyPair keyPair;

    @Before
    public void before() throws NoSuchAlgorithmException, NoSuchProviderException {
        keyPair = TestKeyPairs.generateKeyPair();
        SecretKey secretKey = KeyMaterials.generateKey(KEY_ALG, KEY_SIZE);
        byte[] iv = KeyMaterials.generateIv(IV_SIZE);
        keyMaterial = KeyMaterial.of(secretKey, iv);
    }

    @Test
    public void testGenerateKey() {
        SecretKey secretKey = KeyMaterials.generateKey(KEY_ALG, KEY_SIZE);
        assertThat(secretKey.getAlgorithm()).isEqualTo(KEY_ALG);
    }

    @Test
    public void testGenerateIv() {
        byte[] iv = KeyMaterials.generateIv(IV_SIZE);
        assertThat(iv.length).isEqualTo(IV_SIZE);
    }

    @Test
    public void testUsingLastestSerializer() {
        byte[] wrapped = KeyMaterials.wrap(keyMaterial, keyPair.getPublic());
        KeyMaterial unwrapped = KeySerializerV2.INSTANCE.unwrap(wrapped, keyPair.getPrivate());

        assertThat(unwrapped).isEqualTo(keyMaterial);
    }

    @Test
    public void testWrapAndUnwrap() {
        byte[] wrapped = KeyMaterials.wrap(keyMaterial, keyPair.getPublic());
        KeyMaterial unwrapped = KeyMaterials.unwrap(wrapped, keyPair.getPrivate());

        assertThat(unwrapped).isEqualTo(keyMaterial);
    }

    @Test
    public void testWrapAndUnwrap_serializedByAllVersions() {
        for (KeySerializer keySerializer : KeySerializers.getSerializers().values()) {
            testUnwrapWhenSerializedBy(keySerializer);
        }
    }

    private void testUnwrapWhenSerializedBy(KeySerializer keySerializer) {
        byte[] wrapped = keySerializer.wrap(keyMaterial, keyPair.getPublic());
        KeyMaterial unwrapped = KeyMaterials.unwrap(wrapped, keyPair.getPrivate());
        assertThat(unwrapped).isEqualTo(keyMaterial);
    }

    @Test
    public void testUnwrap_wrongVersion() {
        byte[] wrapped = KeyMaterials.wrap(keyMaterial, keyPair.getPublic());
        wrapped[0] = 0x00;

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> KeyMaterials.unwrap(wrapped, keyPair.getPrivate()))
                .withMessage("Invalid serialization format version. Expected version in %s but found 0",
                    KeySerializers.getSerializers().keySet());
    }

    @Test
    public void testSerializeDeserialize() {
        SecretKey secretKey = keyMaterial.getSecretKey();
        String algorithm = secretKey.getAlgorithm();
        byte[] encoded = secretKey.getEncoded();
        byte[] iv = keyMaterial.getIv();
        assertThat(KeyMaterials.from(algorithm, encoded, iv)).isEqualTo(keyMaterial);
    }

}
