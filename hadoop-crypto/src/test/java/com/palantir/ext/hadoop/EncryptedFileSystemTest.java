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

package com.palantir.ext.hadoop;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Random;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public final class EncryptedFileSystemTest {

    private static final int MB = 1024 * 1024;
    private static final Random random = new Random();

    private EncryptedFileSystem efs;
    private FileSystem delegateFs;
    private Path path;

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Before
    public void before()
            throws NoSuchAlgorithmException, NoSuchProviderException, IOException, URISyntaxException {
        delegateFs = FileSystem.get(new URI(folder.getRoot().getAbsolutePath()), new Configuration());
        efs = new EncryptedFileSystem(delegateFs, new InMemoryKeyStorageStrategy());
        path = new Path(folder.newFile().getAbsolutePath());
    }

    @Test
    public void testDelegateStreamIsClosed() throws IOException {
        FileSystem mockFs = mock(FileSystem.class);
        EncryptedFileSystem fs = new EncryptedFileSystem(mockFs, new InMemoryKeyStorageStrategy());

        when(mockFs.getConf()).thenReturn(new Configuration());
        fs.create(path); // populate key store

        FSDataInputStream is = mock(FSDataInputStream.class);
        when(mockFs.open(path, 4096)).thenReturn(is);

        FSDataInputStream myIs = fs.open(path);
        myIs.close();
        fs.close();

        verify(is, times(1)).close();
    }

    @Test
    public void testEncryptDecrypt_sucess() throws IllegalArgumentException, IOException {
        byte[] data = new byte[MB];
        byte[] readData = new byte[MB];
        random.nextBytes(data);

        OutputStream os = efs.create(path);
        IOUtils.write(data, os);
        os.close();

        // Read using EncryptedFileSystem yields input data
        InputStream is = efs.open(path);
        IOUtils.readFully(is, readData);
        is.close();

        assertThat(data, is(readData));

        // Read using delegate FileSystem does not yield input data
        is = delegateFs.open(path);
        IOUtils.readFully(is, readData);
        is.close();

        assertThat(data, is(not(readData)));
    }

    @Test
    public void testEncryptDecrypt_decryptSeek() throws IllegalArgumentException, IOException {
        byte[] data = new byte[MB];
        int seekPos = MB / 2;
        byte[] readData = new byte[MB - seekPos];
        random.nextBytes(data);

        OutputStream os = efs.create(path);
        IOUtils.write(data, os);
        os.close();

        FSDataInputStream is = efs.open(path);
        is.seek(seekPos);
        IOUtils.readFully(is, readData);

        byte[] actualReadData = Arrays.copyOfRange(data, seekPos, MB);
        assertThat(actualReadData, is(readData));
    }

    @Test
    public void testGetCipherAlgorithm_default() {
        assertThat(efs.getCipherAlgorithm(), is("AES/CTR/NoPadding"));
    }

    @Test
    public void testGetCipherAlgorithm_nonDefault() throws IOException, URISyntaxException {
        String cipherAlg = "cipherAlg";

        Configuration conf = new Configuration();
        conf.set(EncryptedFileSystem.CIPHER_ALGORITHM_KEY, cipherAlg);
        delegateFs = FileSystem.newInstance(new URI(folder.getRoot().getAbsolutePath()), conf);
        efs = new EncryptedFileSystem(delegateFs, new InMemoryKeyStorageStrategy());

        assertThat(efs.getCipherAlgorithm(), is(cipherAlg));
    }

}
