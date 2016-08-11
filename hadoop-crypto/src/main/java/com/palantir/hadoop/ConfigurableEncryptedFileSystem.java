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

import com.google.common.base.Preconditions;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.FilterFileSystem;
import org.apache.hadoop.util.ReflectionUtils;

/**
 * A {@link FileSystem} that transparently encrypts and decrypts the streams of an underlying FileSystem and stores
 * encapsulated/wrapped encryption alongside the encrypted data in the same FileSystem as the encrypted data (see {@link
 * FileKeyStorageStrategy}). Unlike the {@link EncryptedFileSystem}, the ConfigurableEncryptedFileSystem is initialized
 * using a {@link Configuration} and can be used as a standalone FileSystem (like {@code s3a://, hdfs://, etc.}).
 */
public final class ConfigurableEncryptedFileSystem extends FilterFileSystem {

    private static final String SCHEME = "efs";
    private static final String DEFAULT_ALGORITHM = "RSA";

    public static final String BACKING_FILESYSTEM_CONF = "fs.efs.backing.fs";
    public static final String PUBLIC_KEY_CONF = "fs.efs.key.public";
    public static final String PRIVATE_KEY_CONF = "fs.efs.key.private";
    public static final String KEY_ALGORITHM_CONF = "fs.efs.key.algorithm";

    @Override
    public void initialize(URI uri, Configuration conf) throws IOException {
        FileSystem backingFileSystem = getBackingFileSystem(uri, conf);

        KeyPair keyPair = getKeyPair(conf);
        KeyStorageStrategy keyStore = new FileKeyStorageStrategy(backingFileSystem, keyPair);

        this.fs = new EncryptedFileSystem(backingFileSystem, keyStore);
        super.initialize(uri, conf);
    }

    private static KeyPair getKeyPair(Configuration conf) {
        String publicKey = Preconditions.checkNotNull(conf.get(PUBLIC_KEY_CONF),
                "Public Key must be configured for key %s", PUBLIC_KEY_CONF);
        String privateKey = conf.get(PRIVATE_KEY_CONF);
        String algorithm = conf.get(KEY_ALGORITHM_CONF, DEFAULT_ALGORITHM);

        return KeyPairs.fromStrings(privateKey, publicKey, algorithm);
    }

    private static FileSystem getBackingFileSystem(URI uri, Configuration conf) throws IOException {
        String backingFileSystemClass = Preconditions.checkNotNull(conf.get(BACKING_FILESYSTEM_CONF),
                "Public Key must be configured for key %s", PUBLIC_KEY_CONF);
        Class<?> clazz = conf.getClassByNameOrNull(backingFileSystemClass);
        Preconditions.checkNotNull(clazz, "%s property must be set when using %s", BACKING_FILESYSTEM_CONF,
                ConfigurableEncryptedFileSystem.class.getSimpleName());
        Preconditions.checkArgument(FileSystem.class.isAssignableFrom(clazz),
                "Expected a %s but found a %s configured as %s",
                FileSystem.class.getCanonicalName(), clazz.getCanonicalName(), BACKING_FILESYSTEM_CONF);
        Class<? extends FileSystem> fileSystemClass = clazz.asSubclass(FileSystem.class);

        FileSystem fileSystem = ReflectionUtils.newInstance(fileSystemClass, conf);
        // Needed because #newInstance sets the conf on the FileSystem but doesn't call #initialize
        fileSystem.initialize(uri, conf);
        return fileSystem;
    }

    @Override
    public String getScheme() {
        return SCHEME;
    }

}
