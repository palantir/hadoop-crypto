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

package com.palantir.crypto.cipher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import com.palantir.crypto.KeyMaterial;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public final class SeekableCipherFactoryTest {

    private static final String AES_CTR = AesCtrCipher.ALGORITHM;
    private static final String AES_CBC = AesCbcCipher.ALGORITHM;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testGetAesCtr_noKeyMaterial() {
        SeekableCipher cipher = SeekableCipherFactory.getCipher(AES_CTR);
        assertTrue(cipher instanceof AesCtrCipher);
        assertNotEquals(cipher.getKeyMaterial(), null);
    }

    @Test
    public void testGetAesCtr_keyMaterial() {
        KeyMaterial keyMaterial = mock(KeyMaterial.class);
        SeekableCipher cipher = SeekableCipherFactory.getCipher(AES_CTR, keyMaterial);
        assertTrue(cipher instanceof AesCtrCipher);
        assertEquals(cipher.getKeyMaterial(), keyMaterial);
    }

    @Test
    public void testGetAesCbc_noKeyMaterial() {
        SeekableCipher cipher = SeekableCipherFactory.getCipher(AES_CBC);
        assertTrue(cipher instanceof AesCbcCipher);
        assertNotEquals(cipher.getKeyMaterial(), null);
    }

    @Test
    public void testGetAesCbc_keyMaterial() {
        KeyMaterial keyMaterial = mock(KeyMaterial.class);
        SeekableCipher cipher = SeekableCipherFactory.getCipher(AES_CBC, keyMaterial);
        assertTrue(cipher instanceof AesCbcCipher);
        assertEquals(cipher.getKeyMaterial(), keyMaterial);
    }

    @Test
    public void testGetCipher_invalidName() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage(
                    String.format("No known SeekableCipher with algorithm: %s", "doesnt_exist"));
        SeekableCipherFactory.getCipher("doesnt_exist");
    }

    @Test
    public void testGetCipher_invalidNameKeyMaterial() {
        KeyMaterial keyMaterial = mock(KeyMaterial.class);
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage(
                    String.format("No known SeekableCipher with algorithm: %s", "doesnt_exist"));
        SeekableCipherFactory.getCipher("doesnt_exist", keyMaterial);
    }

}
