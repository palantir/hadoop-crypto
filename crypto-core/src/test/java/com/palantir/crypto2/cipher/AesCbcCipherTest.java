/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.cipher;

import com.palantir.crypto2.keys.KeyMaterial;

public final class AesCbcCipherTest extends AbstractSeekableCipherTest {

    @Override
    KeyMaterial generateKeyMaterial() {
        return AesCbcCipher.generateKeyMaterial();
    }

    @Override
    SeekableCipher getCipher(KeyMaterial initKeyMaterial) {
        return new AesCbcCipher(initKeyMaterial);
    }

}
