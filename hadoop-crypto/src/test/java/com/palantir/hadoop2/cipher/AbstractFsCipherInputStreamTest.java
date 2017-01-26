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

package com.palantir.hadoop2.cipher;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import com.palantir.crypto2.cipher.SeekableCipher;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.Random;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.RawLocalFileSystem;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public abstract class AbstractFsCipherInputStreamTest {

    private static final int NUM_BYTES = 1024 * 1024;
    private static final Random random = new Random(0);
    private static final FileSystem fs = new RawLocalFileSystem();
    private static byte[] data;

    private boolean dataWritten = false;
    private Path path;
    private SeekableCipher seekableCipher;
    private FsCipherInputStream cis;

    abstract SeekableCipher getSeekableCipher();

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @BeforeClass
    public static void beforeClass() throws IOException {
        fs.initialize(URI.create("file:///"), new Configuration());

        data = new byte[NUM_BYTES];
        random.nextBytes(data);
    }

    @Before
    public final void before() throws IOException {
        // Only write data once. Cannot be in beforeClass since getSeekableCipher cannot be made static
        if (!dataWritten) {
            seekableCipher = getSeekableCipher();
            path = new Path(tempFolder.newFile().getAbsolutePath());
            FSDataOutputStream fos = fs.create(path);
            OutputStream os = new FsCipherOutputStream(fos, seekableCipher);
            os.write(data);
            os.close();
            dataWritten = true;
        }

        FSDataInputStream is = fs.open(path);
        cis = new FsCipherInputStream(is, seekableCipher);
    }

    @Test
    public final void testDecrypt() throws IOException {
        assertThat(cis.getPos(), is(0L));

        byte[] decrypted = new byte[NUM_BYTES];
        IOUtils.readFully(cis, decrypted);

        assertThat(cis.getPos(), is((long) NUM_BYTES));
        assertThat(decrypted, is(data));
    }

    @Test
    public final void testSeek_firstBlock() throws IOException {
        testSeek(0);
    }

    @Test
    public final void testSeek_firstBlockAndOffset() throws IOException {
        testSeek(1);
    }

    @Test
    public final void testSeek_manyBlocks() throws IOException {
        int pos = seekableCipher.getBlockSize() * 10;
        testSeek(pos);
    }

    @Test
    public final void testSeek_manyBlocksAndOffset() throws IOException {
        int pos = seekableCipher.getBlockSize() * 10 + 1;
        testSeek(pos);
    }

    @Test
    public final void testSeek_onePastEndOfData() throws IOException {
        cis.seek(NUM_BYTES);
        assertThat(cis.read(), is(-1));
    }

    @Test
    public final void testSeek_manyBlocksAndNegativeOffset() throws IOException {
        int pos = seekableCipher.getBlockSize() * 10 - 1;
        testSeek(pos);
    }

    public final void testSeek(int seekPos) throws IOException {
        cis.seek(seekPos);

        assertThat(cis.getPos(), is((long) seekPos));

        byte[] decrypted = new byte[NUM_BYTES - seekPos];
        IOUtils.readFully(cis, decrypted);

        byte[] expected = Arrays.copyOfRange(data, seekPos, NUM_BYTES);

        assertThat(decrypted.length, is(expected.length));
        assertThat(decrypted, is(expected));
    }

    @Test
    public final void testSeekToNewSource_fail() throws IOException {
        long targetPos = NUM_BYTES / seekableCipher.getBlockSize() + 1;
        long startPos = cis.getPos();

        boolean seeked = cis.seekToNewSource(targetPos);

        assertThat(seeked, is(false));
        assertThat(cis.getPos(), is(startPos));
    }

    @Test
    public final void testRead() throws IOException {
        long startPos = cis.getPos();
        byte val = (byte) cis.read();

        assertThat(cis.getPos(), is(startPos + 1));
        assertThat(val, is(data[0]));
    }

    @Test
    public final void testBulkRead() throws IOException {
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

}
