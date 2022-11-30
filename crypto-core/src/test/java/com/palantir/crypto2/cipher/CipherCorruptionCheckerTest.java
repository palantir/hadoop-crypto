package com.palantir.crypto2.cipher;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

public class CipherCorruptionCheckerTest {

    @Test
    void testCipherCorruptionChecker() {
        assertThat(CipherCorruptionChecker.isCorruptionPresent()).isFalse();
    }
}
