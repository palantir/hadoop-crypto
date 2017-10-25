/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.cipher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import com.google.common.collect.ImmutableList;
import org.junit.Test;

public final class CiphersTest {

    @Test
    public void testProvider_exists() {
        assertThat(Ciphers.getProvider()).isIn("SunJCE", "IBMJCE");
    }

    @Test
    public void testProvider_ignoresUnavailable() {
        assertThat(Ciphers.getProvider(ImmutableList.of("Invalid", "SunJCE", "IBMJCE"))).doesNotContain("Invalid");
    }

    @Test
    public void testProvider_noneAvailable() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> Ciphers.getProvider(ImmutableList.of("Invalid")))
                .withMessage("None of the acceptable JCE providers are available: [Invalid]");
    }

}
