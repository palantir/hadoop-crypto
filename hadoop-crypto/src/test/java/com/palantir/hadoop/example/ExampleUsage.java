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

package com.palantir.hadoop.example;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import com.palantir.hadoop.EncryptedFileSystem;
import com.palantir.hadoop.FileKeyStorageStrategy;
import com.palantir.hadoop.KeyStorageStrategy;
import com.palantir.hadoop.TestKeyPairs;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public final class ExampleUsage {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void encryptedFileSystem_exampleUse() throws URISyntaxException, IOException {
        // Get a local FileSystem
        FileSystem fs = FileSystem.get(new URI("file:///"), new Configuration());

        // Initialize EFS with random public/private key pair
        KeyPair pair = TestKeyPairs.generateKeyPair();
        KeyStorageStrategy keyStore = new FileKeyStorageStrategy(fs, pair);
        EncryptedFileSystem efs = new EncryptedFileSystem(fs, keyStore);

        // Init data and local path to write to
        byte[] data = "test".getBytes(StandardCharsets.UTF_8);
        byte[] readData = new byte[data.length];
        Path path = new Path(folder.newFile().getAbsolutePath());

        // Write data out to the encrypted stream
        OutputStream eos = efs.create(path);
        eos.write(data);
        eos.close();

        // Reading through the decrypted stream produces the original bytes
        InputStream ein = efs.open(path);
        IOUtils.readFully(ein, readData);
        assertThat(data, is(readData));

        // Reading through the raw stream produces the encrypted bytes
        InputStream in = fs.open(path);
        IOUtils.readFully(in, readData);
        assertThat(data, is(not(readData)));

        // Wrapped symmetric key is stored next to the encrypted file
        assertTrue(fs.exists(new Path(path + FileKeyStorageStrategy.EXTENSION)));
    }

}
