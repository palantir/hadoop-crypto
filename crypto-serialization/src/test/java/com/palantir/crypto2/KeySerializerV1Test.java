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

package com.palantir.crypto2;

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import com.google.common.collect.ImmutableSet;
import java.security.InvalidKeyException;
import java.util.Set;
import org.junit.Test;

public final class KeySerializerV1Test extends KeySerializerTest {

    @Override
    public KeySerializer getSerializer() {
        return KeySerializerV1.INSTANCE;
    }

    @Test
    public void testWrapAndUnwrap() {
        Set<Integer> symmetricKeySizes = ImmutableSet.of(128, 256);
        Set<Integer> wrappingKeySizes = ImmutableSet.of(1024);
        testWrapAndUnwrap(symmetricKeySizes, wrappingKeySizes);
    }

    @Test // Expected to fail due to array length bug where only a single byte was written
    public void testWrapAndUnwrap_2048bitKeyFails() {
        try {
            testWrapAndUnwrap(128, 2048);
            fail();
        } catch (Exception e) {
            assertThat(e.getCause(), instanceOf(InvalidKeyException.class));
            assertThat(e.getCause().getMessage(), is("Unwrapping failed"));
        }
    }

}
