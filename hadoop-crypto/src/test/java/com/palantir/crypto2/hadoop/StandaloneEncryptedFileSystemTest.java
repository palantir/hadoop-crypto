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

package com.palantir.crypto2.hadoop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import com.google.common.io.ByteStreams;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.util.Base64;
import java.util.UUID;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

public final class StandaloneEncryptedFileSystemTest {

    private static final URI EFS_URI = URI.create("efile:///");
    private static final String DATA = "data";
    private static final byte[] DATA_BYTES = DATA.getBytes(StandardCharsets.UTF_8);

    private FileSystem efs;
    private FileSystem rawFs;
    private Configuration conf;
    private Path path;
    private Path pathWithScheme;

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void before() throws IOException {
        KeyPair keyPair = TestKeyPairs.generateKeyPair();
        conf = getBaseConf();
        conf.set(
                StandaloneEncryptedFileSystem.PUBLIC_KEY_CONF,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        conf.set(
                StandaloneEncryptedFileSystem.PRIVATE_KEY_CONF,
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

        efs = FileSystem.newInstance(EFS_URI, conf);
        rawFs = FileSystem.newInstance(URI.create("file:///"), conf);
        path = new Path(folder.newFile().getAbsolutePath());
        pathWithScheme = new Path("efile://", path);
    }

    @Test
    public void testGetUri_schemeIsCorrect() {
        assertThat(efs.getUri().getScheme()).isEqualTo("efile");
    }

    @Test
    public void testReadWrite() throws IOException {
        byte[] readData = new byte[DATA.length()];

        // Write encrypted data
        OutputStream os = efs.create(path);
        IOUtils.write(DATA, os);
        os.close();

        // Read encrypted data
        InputStream dis = efs.open(path);
        IOUtils.readFully(dis, readData);
        assertThat(readData).containsExactly(DATA_BYTES);

        // Raw data is not the same
        dis = rawFs.open(path);
        IOUtils.readFully(dis, readData);
        assertThat(readData).isNotEqualTo(DATA_BYTES);

        // KeyMaterial file exists
        assertThat(rawFs.exists(keyMaterialPath(path))).isTrue();
    }

    @Test
    public void testDelete() throws IOException {
        File rootFolder = folder.newFolder();

        Path path1 = writeData(rootFolder);

        assertThat(efs.exists(path1)).isTrue();
        assertThat(rawFs.exists(path1)).isTrue();
        assertThat(rawFs.exists(keyMaterialPath(path1))).isTrue();

        efs.delete(new Path(path1.toString()), false);

        assertThat(efs.exists(path1)).isFalse();
        assertThat(rawFs.exists(path1)).isFalse();
        assertThat(rawFs.exists(keyMaterialPath(path1))).isFalse();
    }

    @Test
    public void testRecursiveDelete() throws IOException {
        File rootFolder = folder.newFolder();
        Path rootPath = new Path(rootFolder.getAbsolutePath());

        Path path1 = writeData(rootFolder);
        Path path2 = writeData(rootFolder);

        assertThat(efs.exists(path1)).isTrue();
        assertThat(rawFs.exists(path1)).isTrue();
        assertThat(rawFs.exists(keyMaterialPath(path1))).isTrue();

        assertThat(efs.exists(path2)).isTrue();
        assertThat(rawFs.exists(path2)).isTrue();
        assertThat(rawFs.exists(keyMaterialPath(path2))).isTrue();

        efs.delete(rootPath, true);

        assertThat(rawFs.exists(rootPath)).isFalse();

        assertThat(efs.exists(path1)).isFalse();
        assertThat(rawFs.exists(path1)).isFalse();
        assertThat(rawFs.exists(keyMaterialPath(path1))).isFalse();

        assertThat(efs.exists(path2)).isFalse();
        assertThat(rawFs.exists(path2)).isFalse();
        assertThat(rawFs.exists(keyMaterialPath(path2))).isFalse();
    }

    @Test
    public void testRename() throws IOException {
        File rootFolder = folder.newFolder();
        Path rootPath = new Path(rootFolder.getAbsolutePath());
        Path dstPath = new Path(rootPath, UUID.randomUUID().toString());

        Path srcPath = writeData(rootFolder);

        assertThat(efs.exists(srcPath)).isTrue();

        efs.rename(srcPath, dstPath);

        assertThat(efs.exists(srcPath)).isFalse();
        assertThat(readData(dstPath)).isEqualTo(DATA_BYTES);
    }

    @Test
    public void testRecursiveRename() throws IOException {
        File rootFolder = folder.newFolder();
        File dstFolder = folder.newFolder();
        Path rootPath = new Path(rootFolder.getAbsolutePath());
        Path dstPath = new Path(dstFolder.getAbsolutePath());

        Path path1 = writeData(rootFolder);
        Path path2 = writeData(rootFolder);

        // files exist in original position
        assertThat(efs.exists(path1)).isTrue();
        assertThat(efs.exists(path2)).isTrue();

        efs.rename(rootPath, dstPath);

        Path dstPath1 = new Path(dstPath, path1.getName());
        Path dstPath2 = new Path(dstPath, path2.getName());

        // files exist in renamed position
        assertThat(efs.exists(path1)).isFalse();
        assertThat(efs.exists(path2)).isFalse();

        // files are still able to be decrypted
        assertThat(readData(dstPath1)).isEqualTo(DATA_BYTES);
        assertThat(readData(dstPath2)).isEqualTo(DATA_BYTES);
    }

    private byte[] readData(Path readPath) throws IOException {
        return ByteStreams.toByteArray(efs.open(readPath));
    }

    private Path writeData(File rootFolder) throws IOException {
        // Write encrypted data
        java.nio.file.Path filePath = Files.createTempFile(rootFolder.toPath(), "prefix", "suffix");
        Path newPath = new Path(filePath.toAbsolutePath().toString());
        OutputStream os = efs.create(newPath);
        IOUtils.write(DATA, os);
        os.close();

        return newPath;
    }

    @Test
    public void testMakeQualified() throws IOException {
        assertThat(efs.makeQualified(pathWithScheme)).isEqualTo(pathWithScheme);
    }

    @Test
    public void testOnlyPublicKey() throws IOException {
        byte[] dataBytes = DATA.getBytes(StandardCharsets.UTF_8);
        byte[] readData = new byte[DATA.length()];

        conf.unset(StandaloneEncryptedFileSystem.PRIVATE_KEY_CONF);
        FileSystem efsPublic = FileSystem.newInstance(EFS_URI, conf);

        // Write encrypted data
        OutputStream os = efsPublic.create(path);
        IOUtils.write(DATA, os);
        os.close();

        // Raw data is not the same
        InputStream dis = rawFs.open(path);
        IOUtils.readFully(dis, readData);
        assertThat(readData).isNotEqualTo(dataBytes);

        // KeyMaterial file exists
        assertThat(rawFs.exists(keyMaterialPath(path))).isTrue();

        // Unable to open files without Private Key
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> efsPublic.open(path))
                .withMessage("Private key is absent but required to get key material");
    }

    @Test
    public void testNoPublicKey() throws IOException {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> FileSystem.newInstance(EFS_URI, getBaseConf()))
                .withMessage("Public Key must be configured for key %s", StandaloneEncryptedFileSystem.PUBLIC_KEY_CONF);
    }

    @Test
    public void testBackingFsInvalid() throws IOException {
        conf = getBaseConf();
        conf.set("fs.nope.impl", StandaloneEncryptedFileSystem.class.getCanonicalName());

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> FileSystem.newInstance(URI.create("nope:///"), conf))
                .withMessage("URI scheme must begin with 'e' but received: nope");
    }

    @Test
    public void testFileNameCollidesWithKeyMaterial() throws IOException {
        // Write encrypted data
        OutputStream os = efs.create(path);
        IOUtils.write(DATA, os);
        os.close();

        // Write encrypted data
        os = efs.create(keyMaterialPath(path));
        IOUtils.write(DATA, os);
        os.close();

        // NOTE(jellis): IllegalArgumentException is the most likely exception, however if the first byte of the
        // .keymaterial file is the same as the KeyMaterials version then any number of RuntimeExceptions may be thrown.

        assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> efs.open(path));
    }

    @Test
    public void testListStatus_keyMaterialFilesFiltered() throws IOException {
        OutputStream os = efs.create(path);
        os.write(0x00);
        os.close();

        FileStatus[] fileStatus = efs.listStatus(path);
        FileStatus[] fileStatuses = efs.listStatus(path.getParent());
        FileStatus expectedStatus = fileStatus[0];

        assertThat(fileStatus).hasSize(1);
        assertThat(fileStatuses).containsExactly(expectedStatus);
    }

    @Test // https://github.com/palantir/hadoop-crypto/issues/27
    public void testCopyFromLocalFile() throws IOException {
        File file = folder.newFile();
        byte[] readBytes = new byte[DATA_BYTES.length];

        IOUtils.write(DATA_BYTES, new FileOutputStream(file));
        efs.copyFromLocalFile(new Path(file.getAbsolutePath()), path);

        FSDataInputStream input = efs.open(path);
        IOUtils.readFully(input, readBytes);
        assertThat(readBytes).containsExactly(DATA_BYTES);
    }

    private static Configuration getBaseConf() {
        Configuration conf = new Configuration();
        conf.set("fs.efile.impl", StandaloneEncryptedFileSystem.class.getCanonicalName());
        return conf;
    }

    private Path keyMaterialPath(Path dataPath) {
        return new Path(dataPath + FileKeyStorageStrategy.EXTENSION);
    }
}
