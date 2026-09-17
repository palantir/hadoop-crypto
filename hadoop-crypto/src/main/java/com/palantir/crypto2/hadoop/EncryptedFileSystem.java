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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableSet;
import com.palantir.crypto2.cipher.AesCtrCipher;
import com.palantir.crypto2.cipher.SeekableCipher;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.hadoop.cipher.FsCipherInputStream;
import com.palantir.crypto2.io.CryptoStreamFactory;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.KeyStorageStrategy;
import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.UnsafeArg;
import com.palantir.logsafe.exceptions.SafeIllegalStateException;
import com.palantir.logsafe.exceptions.SafeUnsupportedOperationException;
import com.palantir.logsafe.logger.SafeLogger;
import com.palantir.logsafe.logger.SafeLoggerFactory;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CreateFlag;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Options.ChecksumOpt;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.util.Progressable;

/**
 * A {@link FileSystem} wrapper that encrypts and decrypts the streams from the underlying {@link FileSystem}. The
 * encryption algorithm may be configured by setting {@link #CIPHER_ALGORITHM_KEY} in the {@link
 * org.apache.hadoop.conf.Configuration} to the desired {@link SeekableCipher} algorithm. If no algorithm is set then
 * {@link #DEFAULT_CIPHER_ALGORITHM} will be used. The symmetric key used to encrypt each file is stored and retrieved
 * using the provided {@link KeyStorageStrategy}.
 */
public final class EncryptedFileSystem extends DelegatingFileSystem {

    private static final SafeLogger log = SafeLoggerFactory.get(EncryptedFileSystem.class);
    private static final String DEFAULT_CIPHER_ALGORITHM = AesCtrCipher.ALGORITHM;

    /**
     * This key has been deprecated.
     *
     * @deprecated use {@link #CIPHER_ALGORITHM_KEY}.
     */
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
    public void initialize(URI name, Configuration conf) throws IOException {
        super.initialize(name, conf);
    }

    @Override
    public FSDataInputStream open(Path path, int bufferSize) throws IOException {
        FSDataInputStream encryptedStream = fs.open(path, bufferSize);

        KeyMaterial keyMaterial = keyStore.get(path.toString());

        return new FSDataInputStream(new FsCipherInputStream(encryptedStream, keyMaterial, cipherAlgorithm));
    }

    @Override
    public FSDataOutputStream create(
            Path path,
            FsPermission permission,
            boolean overwrite,
            int bufferSize,
            short replication,
            long blockSize,
            Progressable progress)
            throws IOException {
        FSDataOutputStream outputStream =
                fs.create(path, permission, overwrite, bufferSize, replication, blockSize, progress);

        return encrypt(outputStream, path);
    }

    @Override
    public FSDataOutputStream create(
            Path path,
            FsPermission permission,
            EnumSet<CreateFlag> flags,
            int bufferSize,
            short replication,
            long blockSize,
            Progressable progress,
            ChecksumOpt checksumOpt)
            throws IOException {
        FSDataOutputStream outputStream =
                fs.create(path, permission, flags, bufferSize, replication, blockSize, progress, checksumOpt);

        return encrypt(outputStream, path);
    }

    private FSDataOutputStream encrypt(FSDataOutputStream encryptedStream, Path path) throws IOException {
        KeyMaterial keyMaterial = SeekableCipherFactory.generateKeyMaterial(cipherAlgorithm);
        SeekableCipher cipher = SeekableCipherFactory.getCipher(cipherAlgorithm, keyMaterial);

        // Ensure we can open the stream before storing keys that would be irrelevant
        OutputStream encryptedOs =
                CryptoStreamFactory.encrypt(encryptedStream, cipher.getKeyMaterial(), cipherAlgorithm);
        FSDataOutputStream os = new FSDataOutputStream(encryptedOs, statistics);
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
        String fileKey = null;
        try {
            fileKey = path.toString();
            keyStore.remove(fileKey);
        } catch (Exception e) {
            log.warn(
                    "Unable to remove KeyMaterial for file",
                    UnsafeArg.of("fileKey", fileKey),
                    UnsafeArg.of("path", path),
                    e);
        }
    }

    /**
     * Deletes {@code path}, removing the {@link KeyMaterial} of every encrypted file that is deleted.
     * <p>
     * A recursive delete enumerates the tree so that the KeyMaterial for each file can be removed from the
     * {@link KeyStorageStrategy} before the data itself is deleted. Removing KeyMaterial is best effort: a failure is
     * logged and the data is deleted regardless, which matches the non recursive behaviour.
     * <p>
     * Strategies which store KeyMaterial inside the FileSystem holding the encrypted data, such as
     * {@link FileKeyStorageStrategy}, have their key files enumerated as well. Removing the KeyMaterial of a key
     * material file is a no-op, and the key files are deleted along with the rest of the tree.
     */
    @Override
    public boolean delete(Path path, boolean recursive) throws IOException {
        // Interrupted deletes should be resumable. They are expected to be retried.
        if (!recursive) {
            tryRemoveKey(path);
            return fs.delete(path, false);
        }

        // The KeyMaterial is removed before the data so that an interrupted delete remains resumable: the encrypted
        // files are still present, so the file keys that are left can be enumerated and removed again on a retry.
        tryRemoveKeys(listFileKeys(path));
        return fs.delete(path, true);
    }

    /**
     * Returns the file key of every file in the tree rooted at {@code path}, or an empty set if {@code path} does not
     * exist.
     * <p>
     * Child paths are resolved against {@code path} rather than taken from the {@link FileStatus}, which reports a
     * fully qualified path. {@link #create} stores KeyMaterial under the path as spelled by the caller, so resolving
     * against {@code path} is what produces the file keys the KeyStorageStrategy was actually populated with.
     */
    private Set<String> listFileKeys(Path path) throws IOException {
        FileStatus status;
        try {
            status = fs.getFileStatus(path);
        } catch (FileNotFoundException e) {
            return ImmutableSet.of();
        }

        if (status.isFile()) {
            return ImmutableSet.of(path.toString());
        }

        ImmutableSet.Builder<String> fileKeys = ImmutableSet.builder();
        Deque<Path> directories = new ArrayDeque<>();
        directories.add(path);
        while (!directories.isEmpty()) {
            Path directory = directories.removeFirst();
            for (FileStatus child : fs.listStatus(directory)) {
                Path childPath = new Path(directory, child.getPath().getName());
                if (child.isDirectory()) {
                    directories.add(childPath);
                } else {
                    fileKeys.add(childPath.toString());
                }
            }
        }
        return fileKeys.build();
    }

    private void tryRemoveKeys(Set<String> fileKeys) {
        if (fileKeys.isEmpty()) {
            return;
        }

        try {
            keyStore.remove(fileKeys);
        } catch (Exception e) {
            log.warn(
                    "Unable to remove KeyMaterial for one or more files",
                    SafeArg.of("numFileKeys", fileKeys.size()),
                    e);
        }
    }

    @Override
    public FSDataOutputStream append(Path _path, int _bufferSize, Progressable _progress) throws IOException {
        throw new SafeUnsupportedOperationException("appending to encrypted files is not supported");
    }

    @VisibleForTesting
    String getCipherAlgorithm() {
        Optional<String> cipher = Optional.ofNullable(getConf().get(CIPHER_ALGORITHM_KEY));
        Optional<String> deprecatedCipher = Optional.ofNullable(getConf().get(DEPRECATED_CIPHER_ALGORITHM_KEY));

        if (cipher.isPresent() && deprecatedCipher.isPresent()) {
            if (!cipher.get().equals(deprecatedCipher.get())) {
                throw new SafeIllegalStateException(
                        "Two incompatible ciphers configured",
                        SafeArg.of("cipher", cipher.get()),
                        SafeArg.of("deprecatedCipher", deprecatedCipher.get()));
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
