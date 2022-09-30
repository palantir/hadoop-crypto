/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.crypto2.cipher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

import com.palantir.crypto2.keys.KeyMaterial;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public final class SeekableCipherFactoryTest {

    private static final String AES_CTR = AesCtrCipher.ALGORITHM;
    private static final String AES_CBC = AesCbcCipher.ALGORITHM;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testGenerateKeyMaterial_aesCtr() {
        KeyMaterial keyMaterial = SeekableCipherFactory.generateKeyMaterial(AES_CTR);
        String algorithm = keyMaterial.getSecretKey().getAlgorithm();
        assertThat(algorithm).isEqualTo("AES");
    }

    @Test
    public void testGenerateKeyMaterial_aesCbc() {
        KeyMaterial keyMaterial = SeekableCipherFactory.generateKeyMaterial(AES_CBC);
        String algorithm = keyMaterial.getSecretKey().getAlgorithm();
        assertThat(algorithm).isEqualTo("AES");
    }

    @Test
    public void testGetAesCtr_noKeyMaterial() {
        SeekableCipher cipher = SeekableCipherFactory.getCipher(AES_CTR);
        assertThat(cipher).isInstanceOf(AesCtrCipher.class);
        assertThat(cipher.getKeyMaterial()).isNotNull();
    }

    @Test
    public void testGetAesCtr_keyMaterial() {
        KeyMaterial keyMaterial = mock(KeyMaterial.class);
        SeekableCipher cipher = SeekableCipherFactory.getCipher(AES_CTR, keyMaterial);
        assertThat(cipher).isInstanceOf(AesCtrCipher.class);
        assertThat(cipher.getKeyMaterial()).isEqualTo(keyMaterial);
    }

    @Test
    public void testGetAesCbc_noKeyMaterial() {
        SeekableCipher cipher = SeekableCipherFactory.getCipher(AES_CBC);
        assertThat(cipher).isInstanceOf(AesCbcCipher.class);
        assertThat(cipher.getKeyMaterial()).isNotNull();
    }

    @Test
    public void testGetAesCbc_keyMaterial() {
        KeyMaterial keyMaterial = mock(KeyMaterial.class);
        SeekableCipher cipher = SeekableCipherFactory.getCipher(AES_CBC, keyMaterial);
        assertThat(cipher).isInstanceOf(AesCbcCipher.class);
        assertThat(cipher.getKeyMaterial()).isEqualTo(keyMaterial);
    }

    @Test
    public void testGetCipher_invalidName() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> SeekableCipherFactory.getCipher("doesnt_exist"))
                .withMessage("No known SeekableCipher with algorithm: doesnt_exist");
    }

    @Test
    public void testGetCipher_invalidNameKeyMaterial() {
        KeyMaterial keyMaterial = mock(KeyMaterial.class);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> SeekableCipherFactory.getCipher("doesnt_exist", keyMaterial))
                .withMessage("No known SeekableCipher with algorithm: %s", "doesnt_exist");
    }
}
