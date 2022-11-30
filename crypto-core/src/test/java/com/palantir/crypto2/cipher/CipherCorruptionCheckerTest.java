package com.palantir.crypto2.cipher;

import org.junit.jupiter.api.Test;

public class CipherCorruptionCheckerTest {

    @Test
    void testCipherCorruptionChecker() {
        CipherCorruptionChecker.isCorruptionPresent();
    }
}
