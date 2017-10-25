/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys.serialization;

import com.google.common.collect.ImmutableSet;
import java.util.Set;
import org.junit.Test;

public final class KeySerializerV2Test extends KeySerializerTest {

    @Override
    public KeySerializer getSerializer() {
        return KeySerializerV2.INSTANCE;
    }

    @Test
    public void testWrapAndUnwrap() {
        Set<Integer> symmetricKeySizes = ImmutableSet.of(128, 256);
        Set<Integer> wrappingKeySizes = ImmutableSet.of(1024, 2048);
        testWrapAndUnwrap(symmetricKeySizes, wrappingKeySizes);
    }

}
