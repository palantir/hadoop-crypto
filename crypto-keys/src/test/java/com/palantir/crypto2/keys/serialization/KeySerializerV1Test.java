/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys.serialization;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

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
        assertThatExceptionOfType(Exception.class)
                .isThrownBy(() -> testWrapAndUnwrap(128, 2048))
                .withCauseInstanceOf(InvalidKeyException.class)
                .withMessageContaining("Unwrapping failed");
    }

}
