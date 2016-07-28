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

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import com.palantir.hadoop.cipher.AesCtrCipher;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

public final class FileKeyStorageStrategyTest {

    private FileKeyStorageStrategy keyStore;
    private KeyMaterial keyMaterial;
    private FileSystem fs;
    private KeyPair pair;

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void before() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, URISyntaxException {
        pair = TestKeyPairs.generateKeyPair();
        keyMaterial = AesCtrCipher.generateKeyMaterial();
        fs = FileSystem.get(new URI("file:///"), new Configuration());
        keyStore = new FileKeyStorageStrategy(fs, pair);
    }

    @Test
    public void testStoreKeyMaterial() throws IllegalArgumentException, IOException {
        String path = folder.newFile().getAbsolutePath();
        keyStore.put(path, keyMaterial);
        KeyMaterial readKeyMaterial = keyStore.get(path);

        assertThat(readKeyMaterial, equalTo(keyMaterial));
        assertTrue(fs.exists(new Path(path + FileKeyStorageStrategy.EXTENSION)));
    }

    @Test
    public void testMissingPrivateKey() throws IOException {
        FileKeyStorageStrategy strategy = new FileKeyStorageStrategy(fs, pair.getPublic());

        // Put still succeeds with only the public key
        String path = folder.newFile().getAbsolutePath();
        strategy.put(path, keyMaterial);

        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Private key is absent but required to get key material");
        strategy.get("key");
    }

    @Test
    public void testMissingPrivateKeyInKeyPair() throws IOException {
        KeyPair keyPair = new KeyPair(pair.getPublic(), null);
        FileKeyStorageStrategy strategy = new FileKeyStorageStrategy(fs, keyPair);

        // Put still succeeds with only the public key
        String path = folder.newFile().getAbsolutePath();
        strategy.put(path, keyMaterial);

        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Private key is absent but required to get key material");
        strategy.get("key");
    }

}
