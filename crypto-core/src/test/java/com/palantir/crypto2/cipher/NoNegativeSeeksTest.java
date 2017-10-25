/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.cipher;

import static org.junit.Assert.fail;

import com.palantir.crypto2.io.DecryptingSeekableInput;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.SeekableInput;
import java.io.IOException;
import org.junit.Test;

public final class NoNegativeSeeksTest {

    @Test
    public void testDecryptingSeekableInput_doesNotSeekNegatively() throws IOException {
        KeyMaterial keyMaterial = SeekableCipherFactory.generateKeyMaterial(AesCtrCipher.ALGORITHM);
        SeekableCipher cipher = SeekableCipherFactory.getCipher(AesCtrCipher.ALGORITHM, keyMaterial);

        for (int increment = 16; increment < 2048; increment += 16) {
            try (DecryptingSeekableInput stream = new DecryptingSeekableInput(
                    new DisallowNegativeSeeksSeekableInput(), cipher)) {
                for (int i = 0; i < 1024 * 1024; i += increment) {
                    stream.seek(i);
                }
            }
        }
    }

    private static class DisallowNegativeSeeksSeekableInput implements SeekableInput {
        private long pos = 0;

        @Override
        public void close() throws IOException {}

        @Override
        public void seek(long offset) throws IOException {
            if (offset < pos) {
                fail();
            }
            pos = offset;
        }

        @Override
        public long getPos() throws IOException {
            return pos;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            pos += length;
            return length;
        }
    }

}
