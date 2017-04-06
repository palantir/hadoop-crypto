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

import com.google.common.annotations.VisibleForTesting;
import com.palantir.crypto2.cipher.AesCtrCipher;
import com.palantir.crypto2.cipher.SeekableCipher;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.hadoop.cipher.FsCipherInputStream;
import com.palantir.crypto2.hadoop.cipher.FsCipherOutputStream;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.KeyStorageStrategy;
import java.io.IOException;
import java.util.Optional;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.FilterFileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.util.Progressable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link FileSystem} wrapper that encrypts and decrypts the streams from the underlying {@link FileSystem}. The
 * encryption algorithm may be configured by setting {@link #CIPHER_ALGORITHM_KEY} in the {@link
 * org.apache.hadoop.conf.Configuration} to the desired {@link SeekableCipher} algorithm. If no algorithm is set then
 * {@link #DEFAULT_CIPHER_ALGORITHM} will be used. The symmetric key used to encrypt each file is stored and retrieved
 * using the provided {@link KeyStorageStrategy}.
 */
public final class EncryptedFileSystem extends FilterFileSystem {

    private static final Logger log = LoggerFactory.getLogger(EncryptedFileSystem.class);
    private static final String DEFAULT_CIPHER_ALGORITHM = AesCtrCipher.ALGORITHM;

    @Deprecated
    public static final String DEPRECATED_CIPHER_ALGORITHM_KEY = "fs.cipher";
    public static final String CIPHER_ALGORITHM_KEY = "fs.efs.cipher";

    private final KeyStorageStrategy keyStore;
    private final String cipherAlgorithm;

    public EncryptedFileSystem(FileSystem fs, KeyStorageStrategy keyStore) {
        super(fs);
        this.keyStore = keyStore;
        this.cipherAlgorithm = getCipherAlgorithm();
    }

    @Override
    public FSDataInputStream open(Path path, int bufferSize) throws IOException {
        FSDataInputStream encryptedStream = fs.open(path, bufferSize);

        KeyMaterial keyMaterial = keyStore.get(path.toString());
        SeekableCipher cipher = SeekableCipherFactory.getCipher(cipherAlgorithm, keyMaterial);

        return new FSDataInputStream(new FsCipherInputStream(encryptedStream, cipher));
    }

    @Override
    public FSDataOutputStream create(Path path, FsPermission permission,
            boolean overwrite, int bufferSize, short replication, long blockSize,
            Progressable progress) throws IOException {
        FSDataOutputStream encryptedStream =
                fs.create(path, permission, overwrite, bufferSize, replication, blockSize, progress);

        SeekableCipher cipher = SeekableCipherFactory.getCipher(cipherAlgorithm);

        // Ensure we can open the stream before storing keys that would be irrelevant
        FSDataOutputStream os = new FSDataOutputStream(new FsCipherOutputStream(encryptedStream, cipher), null);
        keyStore.put(path.toString(), cipher.getKeyMaterial());

        return os;
    }

    @Override
    public boolean rename(Path src, Path dst) throws IOException {
        // Copy key material first so the encrypted file always has key material in the key store even if the
        // put or rename fails
        KeyMaterial keyMaterial = keyStore.get(src.toString());
        keyStore.put(dst.toString(), keyMaterial);
        boolean renamed = fs.rename(src, dst);

        if (renamed) {
            tryRemoveKey(src);
        } else {
            tryRemoveKey(dst);
        }

        return renamed;
    }

    private void tryRemoveKey(Path path) {
        try {
            keyStore.remove(path.toString());
        } catch (Exception e) {
            log.warn("Unable to remove KeyMaterial for file: {}", path);
        }
    }

    @Override
    public boolean delete(Path path, boolean recursive) throws IOException {
        if (recursive) {
            throw new UnsupportedOperationException("EncryptedFileSystem does not support recursive deletes");
        }
        keyStore.remove(path.toString());
        return fs.delete(path, false);
    }

    @VisibleForTesting
    String getCipherAlgorithm() {
        Optional<String> cipher = Optional.ofNullable(getConf().get(CIPHER_ALGORITHM_KEY));
        Optional<String> deprecatedCipher = Optional.ofNullable(getConf().get(DEPRECATED_CIPHER_ALGORITHM_KEY));

        if (cipher.isPresent() && deprecatedCipher.isPresent()) {
            if (!cipher.get().equals(deprecatedCipher.get())) {
                throw new IllegalStateException(String.format("Two incompatible ciphers configured: '%s' and '%s'",
                        cipher.get(), deprecatedCipher.get()));
            }
        }

        return findFirst(cipher, deprecatedCipher).orElse(DEFAULT_CIPHER_ALGORITHM);
    }

    private static <T> Optional<T> findFirst(Optional<T> first, Optional<T> second) {
        if (first.isPresent()) {
            return first;
        } else {
            return second;
        }
    }

}
