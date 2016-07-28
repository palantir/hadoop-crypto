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

package com.palantir.hadoop;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.KeyPair;
import org.apache.commons.io.IOUtils;
import org.apache.commons.net.util.Base64;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.RawLocalFileSystem;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

public final class ConfigurableEncryptedFileSystemTest {

    private static final URI EFS_URI = URI.create("efs:///");

    private FileSystem efsPublic;
    private FileSystem efs;
    private FileSystem rawFs;
    private Path path;

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void before() throws IOException {
        KeyPair keyPair = TestKeyPairs.generateKeyPair();
        Configuration conf = getBaseConf();
        conf.set(ConfigurableEncryptedFileSystem.PUBLIC_KEY_CONF,
                Base64.encodeBase64String(keyPair.getPublic().getEncoded()));
        conf.set(ConfigurableEncryptedFileSystem.BACKING_FILESYSTEM_CONF,
                RawLocalFileSystem.class.getCanonicalName());

        efsPublic = FileSystem.newInstance(EFS_URI, conf);

        conf.set(ConfigurableEncryptedFileSystem.PRIVATE_KEY_CONF,
                Base64.encodeBase64String(keyPair.getPrivate().getEncoded()));

        efs = FileSystem.newInstance(EFS_URI, conf);
        rawFs = FileSystem.newInstance(URI.create("file:///"), conf);
        path = new Path(folder.newFile().getAbsolutePath());
    }

    @Test
    public void testReadWrite() throws IOException {
        String data = "data";

        // Write encrypted data
        OutputStream os = efs.create(path);
        IOUtils.write(data, os);
        os.close();

        // Read encrypted data
        InputStream dis = efs.open(path);
        String readData = IOUtils.toString(dis);
        assertThat(readData, is(data));

        // Raw data is not the same
        dis = rawFs.open(path);
        readData = IOUtils.toString(dis);
        assertThat(readData, is(not(data)));

        // KeyMaterial file exists
        assertTrue(efs.exists(new Path(path + FileKeyStorageStrategy.EXTENSION)));
    }

    @Test
    public void testOnlyPublicKey() throws IOException {
        String data = "data";

        // Write encrypted data
        OutputStream os = efsPublic.create(path);
        IOUtils.write(data, os);
        os.close();

        // Unable to open files without Private Key
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Private key is absent but required to get key material");
        efsPublic.open(path);
    }

    @Test
    public void testNoPublicKey() throws IOException {
        expectedException.expect(NullPointerException.class);
        expectedException.expectMessage(String.format("Public Key must be configured for key %s",
                ConfigurableEncryptedFileSystem.PUBLIC_KEY_CONF));
        FileSystem.newInstance(EFS_URI, getBaseConf());
    }

    @Test
    public void testBackingFsInvalid() throws IOException {
        Configuration conf = getBaseConf();
        conf.set(ConfigurableEncryptedFileSystem.BACKING_FILESYSTEM_CONF, String.class.getCanonicalName());

        expectedException.expect(RuntimeException.class);
        expectedException.expectMessage(
                String.format("%s not %s", String.class.getCanonicalName(), FileSystem.class.getCanonicalName()));
        FileSystem.newInstance(EFS_URI, conf);
    }

    private static Configuration getBaseConf() {
        Configuration conf = new Configuration();
        conf.set("fs.efs.impl", ConfigurableEncryptedFileSystem.class.getCanonicalName());
        return conf;
    }

}
