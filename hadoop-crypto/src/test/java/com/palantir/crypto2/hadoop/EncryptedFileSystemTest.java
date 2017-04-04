/*
 * Copyright 2017 Palantir Technologies, Inc. All rights reserved.
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

package com.palantir.crypto2.hadoop;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.palantir.crypto2.cipher.AesCtrCipher;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.KeyStorageStrategy;
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
    private Path newPath;
    private InMemoryKeyStorageStrategy keyStore;
    private KeyMaterial keyMaterial;
    private FileSystem mockFs;
    private KeyStorageStrategy mockKeyStore;
    private EncryptedFileSystem mockedEfs;

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Before
    public void before()
            throws NoSuchAlgorithmException, NoSuchProviderException, IOException, URISyntaxException {
        delegateFs = FileSystem.get(new URI(folder.getRoot().getAbsolutePath()), new Configuration());
        keyStore = new InMemoryKeyStorageStrategy();
        efs = new EncryptedFileSystem(delegateFs, keyStore);
        path = new Path(folder.newFile().getAbsolutePath());
        newPath = path.suffix("renamed");

        OutputStream os = efs.create(path);
        os.write(0x00);
        os.close();

        keyMaterial = AesCtrCipher.generateKeyMaterial();
        mockFs = mock(FileSystem.class);
        mockKeyStore = mock(KeyStorageStrategy.class);

        // Mock a successful rename operation
        when(mockFs.getConf()).thenReturn(new Configuration());
        when(mockFs.rename(any(Path.class), any(Path.class))).thenReturn(true);
        when(mockKeyStore.get(anyString())).thenReturn(keyMaterial);

        mockedEfs = new EncryptedFileSystem(mockFs, mockKeyStore);
    }

    @Test
    public void testDelegateStreamIsClosed() throws IOException {
        EncryptedFileSystem fs = new EncryptedFileSystem(mockFs, new InMemoryKeyStorageStrategy());

        fs.create(path); // populate key store

        FSDataInputStream is = mock(FSDataInputStream.class);
        when(mockFs.open(path, 4096)).thenReturn(is);

        FSDataInputStream myIs = fs.open(path);
        myIs.close();
        fs.close();

        verify(is).close();
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
    public void testCreate_normalizePathPassedToKeyStore() throws IOException {
        mockedEfs.create(new Path("foo//bar"));

        verify(mockKeyStore).put(eq("foo/bar"), any(KeyMaterial.class));
        verifyNoMoreInteractions(mockKeyStore);
    }

    @Test
    public void testOpen_normalizePathPassedToKeyStore() throws IOException {
        mockedEfs.open(new Path("foo//bar"));

        verify(mockKeyStore).get("foo/bar");
        verifyNoMoreInteractions(mockKeyStore);
    }

    @Test
    public void testRename_normalizePathPassedToKeyStore() throws IOException {
        mockedEfs.rename(new Path("src//foo"), new Path("dst//bar"));

        verify(mockKeyStore).get("src/foo");
        verify(mockKeyStore).put("dst/bar", keyMaterial);
        verify(mockKeyStore).remove("src/foo");
        verifyNoMoreInteractions(mockKeyStore);
    }

    @Test
    public void testRename_successful() throws IOException {
        KeyMaterial actualKeyMaterial = keyStore.get(path.toString());

        efs.rename(path, newPath);

        assertFalse(efs.exists(path));
        assertTrue(efs.exists(newPath));

        assertThat(keyStore.get(path.toString()), is(nullValue()));
        assertThat(keyStore.get(newPath.toString()), is(actualKeyMaterial));
    }

    @Test
    public void testRename_failedGet() throws IOException {
        doThrow(new IllegalArgumentException()).when(mockKeyStore).get(path.toString());

        try {
            mockedEfs.rename(path, newPath);
            fail();
        } catch (Exception e) {
            verify(mockFs, never()).rename(path, newPath);
            verify(mockKeyStore, never()).remove(path.toString());
        }
    }

    @Test
    public void testRename_failedPut() throws IOException {
        doThrow(new IllegalArgumentException()).when(mockKeyStore).put(newPath.toString(), keyMaterial);

        try {
            mockedEfs.rename(path, newPath);
            fail();
        } catch (Exception e) {
            verify(mockFs, never()).rename(path, newPath);
            verify(mockKeyStore, never()).remove(path.toString());
        }
    }

    @Test
    public void testRename_failedRename() throws IOException {
        when(mockFs.rename(path, newPath)).thenReturn(false);

        boolean renamed = mockedEfs.rename(path, newPath);

        assertFalse(renamed);
        verify(mockKeyStore, never()).remove(path.toString());
        verify(mockKeyStore).remove(newPath.toString());
    }

    @Test
    public void testRename_successfulRenameFailedRemoveIsIgnored() throws IOException {
        when(mockFs.rename(path, newPath)).thenReturn(true);
        doThrow(new IllegalArgumentException()).when(mockKeyStore).remove(anyString());

        assertTrue(mockedEfs.rename(path, newPath));
    }

    @Test
    public void testRename_failedRenameFailedRemoveIsIgnored() throws IOException {
        when(mockFs.rename(path, newPath)).thenReturn(false);
        doThrow(new IllegalArgumentException()).when(mockKeyStore).remove(anyString());

        assertFalse(mockedEfs.rename(path, newPath));
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

    @Test
    public void testGetCipherAlgorithm_deprecated() throws IOException, URISyntaxException {
        String cipherAlg = "cipherAlg";

        Configuration conf = new Configuration();
        conf.set(EncryptedFileSystem.DEPRECATED_CIPHER_ALGORITHM_KEY, cipherAlg);
        delegateFs = FileSystem.newInstance(new URI(folder.getRoot().getAbsolutePath()), conf);
        efs = new EncryptedFileSystem(delegateFs, new InMemoryKeyStorageStrategy());

        assertThat(efs.getCipherAlgorithm(), is(cipherAlg));
    }

    @Test
    public void testGetCipherAlgorithm_bothConfigured() throws IOException, URISyntaxException {
        String cipherAlg = "cipherAlg";
        String deprecatedCipherAlg = "deprecatedCipherAlg";

        Configuration conf = new Configuration();
        conf.set(EncryptedFileSystem.CIPHER_ALGORITHM_KEY, cipherAlg);
        conf.set(EncryptedFileSystem.DEPRECATED_CIPHER_ALGORITHM_KEY, deprecatedCipherAlg);
        delegateFs = FileSystem.newInstance(new URI(folder.getRoot().getAbsolutePath()), conf);

        try {
            efs = new EncryptedFileSystem(delegateFs, new InMemoryKeyStorageStrategy());
            fail();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage(),
                    is("Two incompatible ciphers configured: 'cipherAlg' and 'deprecatedCipherAlg'"));
        }
    }

    @Test
    public void testDelete_successful() throws IOException {
        assertTrue(efs.delete(path, false));

        assertFalse(efs.exists(path));
        assertThat(keyStore.get(path.toString()), is(nullValue()));
    }

    @Test
    public void testDelete_recursiveDelete() throws IOException {
        Path folderPath = new Path(folder.getRoot().getAbsolutePath());
        try {
            efs.delete(folderPath, true);
            fail();
        } catch (UnsupportedOperationException e) {
            assertThat(e.getMessage(), is("EncryptedFileSystem does not support recursive deletes"));
        }
    }

    @Test
    public void testDelete_nonRecursiveDeleteOnDir() throws IOException {
        Path folderPath = new Path(folder.getRoot().getAbsolutePath());
        try {
            efs.delete(folderPath, false);
            fail();
        } catch (IOException e) {
            assertThat(e.getMessage(), is(String.format("Directory %s is not empty", folderPath)));
        }
    }

    @Test
    public void testDelete_keyMaterialAlreadyDeleted() throws IOException {
        keyStore.remove(path.toString());
        assertThat(keyStore.get(path.toString()), is(nullValue()));

        assertTrue(efs.delete(path, false));

        assertFalse(efs.exists(path));
    }

    @Test
    public void testDelete_fileAlreadyDeleted() throws IOException {
        delegateFs.delete(path, false);

        assertThat(keyStore.get(path.toString()), is(not(nullValue())));
        assertFalse(efs.delete(path, false));
        assertThat(keyStore.get(path.toString()), is(nullValue()));
    }
}
