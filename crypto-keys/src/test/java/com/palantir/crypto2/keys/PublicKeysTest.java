/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.PublicKey;
import org.junit.Test;

public final class PublicKeysTest {

    @Test
    public void testFrom_generatesEquivalent() {
        PublicKey expectedKey = TestKeyPairs.generateKeyPair().getPublic();
        PublicKey actualKey = PublicKeys.from(expectedKey.getAlgorithm(), expectedKey.getEncoded());
        assertThat(actualKey).isEqualTo(expectedKey);
    }

}
