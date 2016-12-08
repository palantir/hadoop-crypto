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

package com.palantir.crypto.io;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.io.ByteStreams;
import com.palantir.crypto.cipher.AesCbcCipher;
import com.palantir.crypto.cipher.AesCtrCipher;
import com.palantir.crypto.cipher.SeekableCipher;
import com.palantir.crypto.cipher.SeekableCipherFactory;
import com.palantir.seekio.SeekableInput;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public final class DecryptingSeekableInputTest {

    private static final int NUM_BYTES = 1024 * 1024;
    private static final Random random = new Random(0);
    private static byte[] data;

    private SeekableCipher seekableCipher;
    private DecryptingSeekableInput cis;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @BeforeClass
    public static void beforeClass() throws IOException {
        data = new byte[NUM_BYTES];
        random.nextBytes(data);
    }

    @Parameterized.Parameters
    public static Collection<String> ciphers() {
        return ImmutableList.of(AesCtrCipher.ALGORITHM, AesCbcCipher.ALGORITHM);
    }

    public DecryptingSeekableInputTest(String cipher) {
        try {
            seekableCipher = SeekableCipherFactory.getCipher(cipher);
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            CipherOutputStream cos = new CipherOutputStream(os, seekableCipher.initCipher(Cipher.ENCRYPT_MODE));
            cos.write(data);
            cos.close();
            cis = new DecryptingSeekableInput(new ByteArraySeekableInput(os.toByteArray()), seekableCipher);
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
    }

    @Test
    public void testDecrypt() throws IOException {
        assertThat(cis.getPos(), is(0L));

        byte[] decrypted = new byte[NUM_BYTES];
        readFully(cis, decrypted);

        assertThat(cis.getPos(), is((long) NUM_BYTES));
        assertThat(decrypted, is(data));
    }

    @Test
    public void testSeek_firstBlock() throws IOException {
        testSeek(0);
    }

    @Test
    public void testSeek_firstBlockAndOffset() throws IOException {
        testSeek(1);
    }

    @Test
    public void testSeek_manyBlocks() throws IOException {
        int pos = seekableCipher.getBlockSize() * 10;
        testSeek(pos);
    }

    @Test
    public void testSeek_manyBlocksAndOffset() throws IOException {
        int pos = seekableCipher.getBlockSize() * 10 + 1;
        testSeek(pos);
    }

    @Test
    public void testSeek_onePastEndOfData() throws IOException {
        cis.seek(NUM_BYTES);
        assertThat(cis.read(new byte[1], 0, 1), is(-1));
    }

    @Test
    public void testSeek_manyBlocksAndNegativeOffset() throws IOException {
        int pos = seekableCipher.getBlockSize() * 10 - 1;
        testSeek(pos);
    }

    public void testSeek(int seekPos) throws IOException {
        cis.seek(seekPos);

        assertThat(cis.getPos(), is((long) seekPos));

        byte[] decrypted = new byte[NUM_BYTES - seekPos];
        readFully(cis, decrypted);

        byte[] expected = Arrays.copyOfRange(data, seekPos, NUM_BYTES);

        assertThat(decrypted.length, is(expected.length));
        assertThat(decrypted, is(expected));
    }

    @Test
    public void testBulkRead() throws IOException {
        long startPos = cis.getPos();
        byte[] buffer = new byte[NUM_BYTES];
        int offset = 0;
        int read;
        while ((read = cis.read(buffer, offset, buffer.length)) != -1) {
            offset += read;
        }

        assertThat(cis.getPos(), is(startPos + buffer.length));
        assertThat(buffer, is(data));
        assertThat(offset, is(NUM_BYTES));
        cis.close();
    }

    private static void readFully(SeekableInput input, byte[] decrypted) throws IOException {
        ByteStreams.readFully(new DefaultSeekableInputStream(input), decrypted);
    }

}
