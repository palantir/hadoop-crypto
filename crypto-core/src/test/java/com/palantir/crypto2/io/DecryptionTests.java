/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.crypto2.io;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.io.ByteStreams;
import com.palantir.crypto2.cipher.AesCbcCipher;
import com.palantir.crypto2.cipher.AesCtrCipher;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.InMemorySeekableDataInput;
import com.palantir.seekio.SeekableInput;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public final class DecryptionTests {

    private static final String AES_CTR = AesCtrCipher.ALGORITHM;
    private static final String AES_CBC = AesCbcCipher.ALGORITHM;
    private static final int BLOCK_SIZE = 16;
    private static final int NUM_BYTES = 1024 * 1024;
    private static final Random random = new Random(0);
    private static byte[] data;

    private SeekableInput cis;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @BeforeClass
    public static void beforeClass() throws IOException {
        data = new byte[NUM_BYTES];
        random.nextBytes(data);
    }

    @Parameterized.Parameters
    public static Collection<TestCase> ciphers() {
        return ImmutableList.of(
                new TestCase(AES_CTR),
                new TestCase(AES_CTR),
                new TestCase(AES_CTR),
                new TestCase(AES_CTR),
                new TestCase(AES_CBC));
    }

    public DecryptionTests(TestCase testCase) {
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            KeyMaterial keyMaterial = SeekableCipherFactory.generateKeyMaterial(testCase.alg);
            OutputStream cos = CryptoStreamFactory.encrypt(os, keyMaterial, testCase.alg);
            cos.write(data);
            cos.close();

            InMemorySeekableDataInput input = new InMemorySeekableDataInput(os.toByteArray());
            cis = CryptoStreamFactory.decrypt(input, keyMaterial, testCase.alg);
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
    }

    @Test
    public void testDecrypt() throws IOException {
        assertThat(cis.getPos()).isZero();

        byte[] decrypted = new byte[NUM_BYTES];
        readFully(cis, decrypted);

        assertThat(cis.getPos()).isEqualTo(NUM_BYTES);
        assertThat(decrypted).isEqualTo(data);
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
        int pos = BLOCK_SIZE * 10;
        testSeek(pos);
    }

    @Test
    public void testSeek_manyBlocksAndOffset() throws IOException {
        int pos = BLOCK_SIZE * 10 + 1;
        testSeek(pos);
    }

    @Test
    public void testSeek_onePastEndOfData() throws IOException {
        cis.seek(NUM_BYTES);
        assertThat(cis.read(new byte[1], 0, 1)).isEqualTo(-1);
    }

    @Test
    public void testSeek_manyBlocksAndNegativeOffset() throws IOException {
        int pos = BLOCK_SIZE * 10 - 1;
        testSeek(pos);
    }

    private void testSeek(int seekPos) throws IOException {
        cis.seek(seekPos);

        assertThat(cis.getPos()).isEqualTo(seekPos);

        byte[] decrypted = new byte[NUM_BYTES - seekPos];
        readFully(cis, decrypted);

        byte[] expected = Arrays.copyOfRange(data, seekPos, NUM_BYTES);

        assertThat(decrypted).hasSameSizeAs(expected);
        assertThat(decrypted).isEqualTo(expected);
    }

    @Test
    public void testBulkRead() throws IOException {
        long startPos = cis.getPos();
        byte[] buffer = new byte[NUM_BYTES];
        int offset = 0;

        while (offset < buffer.length) {
            int read = cis.read(buffer, offset, buffer.length - offset);
            if (read == -1) {
                break;
            }
            offset += read;
        }

        assertThat(cis.getPos()).isEqualTo(startPos + buffer.length);
        assertThat(buffer).isEqualTo(data);
        assertThat(offset).isEqualTo(NUM_BYTES);
        cis.close();
    }

    private static void readFully(SeekableInput input, byte[] decrypted) throws IOException {
        ByteStreams.readFully(new DefaultSeekableInputStream(input), decrypted);
    }

    @SuppressWarnings("VisibilityModifier")
    private static final class TestCase {
        String alg;

        TestCase(String alg) {
            this.alg = alg;
        }
    }
}
