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

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import javax.ws.rs.core.UriBuilder;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.FilterFileSystem;
import org.apache.hadoop.fs.Path;

/**
 * A {@link FileSystem} that transparently encrypts and decrypts the streams of an underlying FileSystem and stores
 * encapsulated/wrapped encryption alongside the encrypted data in the same FileSystem as the encrypted data (see {@link
 * FileKeyStorageStrategy}). Unlike the {@link EncryptedFileSystem}, the ConfigurableEncryptedFileSystem is initialized
 * using a {@link Configuration} and can be used as a standalone FileSystem (like {@code s3a://, hdfs://, etc.}).
 */
public final class ConfigurableEncryptedFileSystem extends FilterFileSystem {

    private static final String SCHEME = "";
    private static final String DEFAULT_ALGORITHM = "RSA";

    public static final String PUBLIC_KEY_CONF = "fs.efs.key.public";
    public static final String PRIVATE_KEY_CONF = "fs.efs.key.private";
    public static final String KEY_ALGORITHM_CONF = "fs.efs.key.algorithm";

    @Override
    public void initialize(URI uri, Configuration conf) throws IOException {
        FileSystem delegate = getDelegateFileSystem(uri, conf);

        KeyPair keyPair = getKeyPair(conf);
        KeyStorageStrategy keyStore = new FileKeyStorageStrategy(delegate, keyPair);

        this.fs = new EncryptedFileSystem(delegate, keyStore);
        super.initialize(uri, conf);
    }

    private static KeyPair getKeyPair(Configuration conf) {
        String publicKey = Preconditions.checkNotNull(conf.get(PUBLIC_KEY_CONF),
                "Public Key must be configured for key %s", PUBLIC_KEY_CONF);
        String privateKey = conf.get(PRIVATE_KEY_CONF);
        String algorithm = conf.get(KEY_ALGORITHM_CONF, DEFAULT_ALGORITHM);

        return KeyPairs.fromStrings(privateKey, publicKey, algorithm);
    }

    private static FileSystem getDelegateFileSystem(URI uri, Configuration conf) throws IOException {
        String encryptedScheme = uri.getScheme();
        Preconditions.checkArgument(encryptedScheme.startsWith("e"),
                "URI scheme must begin with 'e' but received: %s", encryptedScheme);

        String backingScheme = encryptedScheme.substring(1);
        URI backingUri = setUriSchemeFunc(backingScheme).apply(uri);

        FileSystem backingFs = FileSystem.get(backingUri, conf);
        return new PathConvertingFileSystem(backingFs, setSchemeFunc(backingScheme), setSchemeFunc(encryptedScheme));
    }

    private static Function<Path, Path> setSchemeFunc(final String scheme) {
        return new Function<Path, Path>() {
            @Override
            public Path apply(Path path) {
                return new Path(setUriSchemeFunc(scheme).apply(path.toUri()));
            }
        };
    }

    private static Function<URI, URI> setUriSchemeFunc(final String scheme) {
        return new Function<URI, URI>() {
            @Override
            public URI apply(URI uri) {
                UriBuilder builder = UriBuilder.fromUri(uri);
                if (uri.getScheme() != null) {
                    builder.scheme(scheme);
                }
                return builder.build();
            }
        };
    }

    @Override
    public String getScheme() {
        return SCHEME;
    }

}
