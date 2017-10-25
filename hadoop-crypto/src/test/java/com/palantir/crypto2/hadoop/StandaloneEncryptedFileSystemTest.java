/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.hadoop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
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
        conf.set(StandaloneEncryptedFileSystem.PUBLIC_KEY_CONF,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        conf.set(StandaloneEncryptedFileSystem.PRIVATE_KEY_CONF,
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

        efs = FileSystem.newInstance(EFS_URI, conf);
        rawFs = FileSystem.newInstance(URI.create("file:///"), conf);
        path = new Path(folder.newFile().getAbsolutePath());
        pathWithScheme = new Path("efile://", this.path);
    }

    @Test
    public void testGetUri_schemeIsCorrect() {
        assertThat(efs.getUri().getScheme()).isEqualTo("efile");
    }

    @Test
    public void testReadWrite() throws IOException {
        String data = "data";
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] readData = new byte[data.length()];

        // Write encrypted data
        OutputStream os = efs.create(path);
        IOUtils.write(data, os);
        os.close();

        // Read encrypted data
        InputStream dis = efs.open(path);
        IOUtils.readFully(dis, readData);
        assertThat(readData).containsExactly(dataBytes);

        // Raw data is not the same
        dis = rawFs.open(path);
        IOUtils.readFully(dis, readData);
        assertThat(readData).isNotEqualTo(dataBytes);

        // KeyMaterial file exists
        assertThat(rawFs.exists(new Path(path + FileKeyStorageStrategy.EXTENSION))).isTrue();
    }

    @Test
    public void testMakeQualified() throws IOException {
        assertThat(efs.makeQualified(pathWithScheme)).isEqualTo(pathWithScheme);
    }

    @Test
    public void testOnlyPublicKey() throws IOException {
        String data = "data";
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] readData = new byte[data.length()];

        conf.unset(StandaloneEncryptedFileSystem.PRIVATE_KEY_CONF);
        FileSystem efsPublic = FileSystem.newInstance(EFS_URI, conf);

        // Write encrypted data
        OutputStream os = efsPublic.create(path);
        IOUtils.write(data, os);
        os.close();

        // Raw data is not the same
        InputStream dis = rawFs.open(path);
        IOUtils.readFully(dis, readData);
        assertThat(readData).isNotEqualTo(dataBytes);

        // KeyMaterial file exists
        assertTrue(rawFs.exists(new Path(path + FileKeyStorageStrategy.EXTENSION)));

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
        String data = "data";

        // Write encrypted data
        OutputStream os = efs.create(path);
        IOUtils.write(data, os);
        os.close();

        // Write encrypted data
        os = efs.create(new Path(path + FileKeyStorageStrategy.EXTENSION));
        IOUtils.write(data, os);
        os.close();

        // NOTE(jellis): IllegalArgumentException is the most likely exception, however if the first byte of the
        // .keymaterial file is the same as the KeyMaterials version then any number of RuntimeExceptions may be thrown.

        assertThatExceptionOfType(RuntimeException.class)
                .isThrownBy(() -> efs.open(path));
    }

    @Test
    public void testListStatus_keyMaterialFilesFiltered() throws IOException {
        OutputStream os = efs.create(path);
        os.write(0x00);
        os.close();

        FileStatus[] fileStatus = efs.listStatus(path);
        FileStatus[] fileStatuses = efs.listStatus(path.getParent());
        FileStatus expectedStatus = fileStatus[0];

        assertThat(fileStatus.length).isEqualTo(1);
        assertThat(fileStatuses).containsExactly(expectedStatus);
    }

    @Test // https://github.com/palantir/hadoop-crypto/issues/27
    public void testCopyFromLocalFile() throws IOException {
        File file = folder.newFile();
        byte[] data = "data".getBytes(StandardCharsets.UTF_8);
        byte[] readBytes = new byte[data.length];

        IOUtils.write(data, new FileOutputStream(file));
        efs.copyFromLocalFile(new Path(file.getAbsolutePath()), path);

        FSDataInputStream input = efs.open(path);
        IOUtils.readFully(input, readBytes);
        assertThat(readBytes).containsExactly(data);
    }

    private static Configuration getBaseConf() {
        Configuration conf = new Configuration();
        conf.set("fs.efile.impl", StandaloneEncryptedFileSystem.class.getCanonicalName());
        return conf;
    }

}
