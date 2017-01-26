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

package com.palantir.crypto2.cipher;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import com.palantir.crypto2.KeyMaterial;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import org.junit.Before;
import org.junit.Test;

public abstract class AbstractSeekableCipherTest {

    private static final int NUM_BLOCKS = 1000;
    private static final Random random = new Random(0);

    private KeyMaterial keyMaterial;
    private SeekableCipher seekableCipher;
    private Cipher encryptCipher;
    private Cipher decryptCipher;

    abstract KeyMaterial generateKeyMaterial();

    abstract SeekableCipher getCipher(KeyMaterial initKeyMaterial);

    @Before
    public final void before() {
        keyMaterial = generateKeyMaterial();
        seekableCipher = getCipher(keyMaterial);
        encryptCipher = seekableCipher.initCipher(Cipher.ENCRYPT_MODE);
        decryptCipher = seekableCipher.initCipher(Cipher.DECRYPT_MODE);
    }

    @Test
    public final void testEncryptDecrypt_noSeek() throws BadPaddingException, IllegalBlockSizeException {
        testEncryptDecrypt(encryptCipher, decryptCipher);
    }

    @Test
    public final void testEncryptDecrypt_seekMaxValue() throws BadPaddingException, IllegalBlockSizeException {
        long offset = Long.MAX_VALUE / seekableCipher.getBlockSize() * seekableCipher.getBlockSize();

        seekableCipher.initCipher(Cipher.ENCRYPT_MODE);
        encryptCipher = seekableCipher.seek(offset);
        seekableCipher.initCipher(Cipher.DECRYPT_MODE);
        decryptCipher = seekableCipher.seek(offset);

        testEncryptDecrypt(encryptCipher, decryptCipher);
    }

    @Test
    public final void testSeek() throws BadPaddingException, IllegalBlockSizeException, ShortBufferException {
        int blockSize = seekableCipher.getBlockSize();
        byte[] data = new byte[blockSize * NUM_BLOCKS];
        byte val = 0x01;

        int lastBlock = NUM_BLOCKS - 1;
        int lastBlockOffset = lastBlock * blockSize;
        int prevBlockOffset = lastBlockOffset - blockSize;

        // Create large array of form { 0x00, 0x00, ... , 0x00, 0x01, ... blockSize - 2 ... ,0x01 }
        Arrays.fill(data, (byte) 0x00);
        Arrays.fill(data, lastBlockOffset, lastBlockOffset + blockSize, val);

        byte[] encryptedData = encryptCipher.doFinal(data);

        seekableCipher.initCipher(Cipher.DECRYPT_MODE);
        decryptCipher = seekableCipher.seek(prevBlockOffset);

        // Decrypt from block n - 1 to the end of the encrypted data
        byte[] lastBlocksData = decryptCipher.doFinal(
                encryptedData, prevBlockOffset, encryptedData.length - prevBlockOffset);
        byte[] lastBlockData = Arrays.copyOfRange(lastBlocksData, blockSize, 2 * blockSize);

        byte[] expected = new byte[blockSize];
        Arrays.fill(expected, val);

        assertThat(lastBlockData, is(expected));
    }

    @Test
    public final void testSeek_seekNegativeValue() {
        long negPos = -1;
        try {
            seekableCipher.seek(negPos);
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is(String.format("Cannot seek to negative position: %d", negPos)));
        }
    }

    @Test
    public final void testSeek_notInitialized() {
        try {
            getCipher(keyMaterial).seek(0);
            fail();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage(), is("Cipher not initialized"));
        }
    }

    @Test
    public final void testGetKeyMaterial() {
        assertThat(seekableCipher.getKeyMaterial(), is(keyMaterial));
    }

    public final void testEncryptDecrypt(Cipher encryptingCipher, Cipher decryptingCipher)
            throws BadPaddingException, IllegalBlockSizeException {
        byte[] data = new byte[NUM_BLOCKS * encryptingCipher.getBlockSize()];
        random.nextBytes(data);
        byte[] encryptedData = encryptingCipher.doFinal(data);
        byte[] decryptedData = decryptingCipher.update(encryptedData);

        assertThat(data, is(not(encryptedData)));
        assertThat(data, is(decryptedData));
    }

}
