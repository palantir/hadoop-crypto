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

package com.palantir.hadoop.serializer;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import com.palantir.hadoop.KeyMaterial;
import com.palantir.hadoop.KeyMaterials;
import com.palantir.hadoop.KeyPairs;
import java.security.KeyPair;
import java.util.Set;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public abstract class KeySerializerTest {

    private static final String KEY_ALG = "AES";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16;

    private KeyPair keyPair;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    public abstract KeySerializer getSerializer();

    @Test
    public final void testIncorrectVersion() {
        keyPair = KeyPairs.generateKeyPair();
        KeyMaterial keyMaterial = KeyMaterials.generateKeyMaterial(KEY_ALG, KEY_SIZE, IV_SIZE);

        byte[] wrapped = getSerializer().wrap(keyMaterial, keyPair.getPublic());
        wrapped[0] = 0x00;

        try {
            getSerializer().unwrap(wrapped, keyPair.getPrivate());
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(),
                    is(String.format("Invalid serialization format version. Expected %s but found 0",
                            getSerializer().getVersion())));
        }
    }

    public final void testWrapAndUnwrap(Set<Integer> symmetricKeySizes, Set<Integer> wrappingKeySizes) {
        for (Integer symmetricKeySize : symmetricKeySizes) {
            for (Integer wrappingKeySize : wrappingKeySizes) {
                testWrapAndUnwrap(symmetricKeySize, wrappingKeySize);
            }
        }
    }

    public final void testWrapAndUnwrap(int symmetricKeySize, int wrappingKeySize) {
        keyPair = KeyPairs.generateKeyPair(wrappingKeySize);
        KeyMaterial keyMaterial = KeyMaterials.generateKeyMaterial(KEY_ALG, symmetricKeySize, IV_SIZE);

        byte[] wrapped = getSerializer().wrap(keyMaterial, keyPair.getPublic());
        KeyMaterial unwrapped = getSerializer().unwrap(wrapped, keyPair.getPrivate());
        assertThat(keyMaterial, is(unwrapped));
    }

}
