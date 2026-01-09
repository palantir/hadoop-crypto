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
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.util.EnumSet;
import java.util.Optional;
import java.util.UUID;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CreateFlag;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FSDataOutputStreamBuilder;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Options.ChecksumOpt;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.fs.s3a.Constants;
import org.apache.hadoop.fs.s3a.impl.CreateFileBuilder;
import org.apache.hadoop.util.Progressable;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;

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
    private static final String S3_METADATA_KEY = "crypto-file-key-suffix";
    private static final String S3_METADATA_KEY_HEADER =
            Constants.FS_S3A_CREATE_HEADER + ".x-amz-meta-" + S3_METADATA_KEY;

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

        KeyMaterial keyMaterial = keyStore.get(toKeyPath(path, getKeyPathSuffix(path)));

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
        FSDataOutputStreamBuilder<?, ?> outputStreamBuilder = fs.createFile(path)
                .recursive() // create parent directory if it does not exist
                .permission(permission)
                .overwrite(overwrite)
                .bufferSize(bufferSize)
                .replication(replication)
                .blockSize(blockSize);
        if (progress != null) {
            outputStreamBuilder.progress(progress);
        }

        return encrypt(outputStreamBuilder, path);
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
        FSDataOutputStreamBuilder<?, ?> outputStreamBuilder = fs.createFile(path)
                .recursive() // create parent directory if it does not exist
                .permission(permission)
                .bufferSize(bufferSize)
                .replication(replication)
                .blockSize(blockSize);
        if (progress != null) {
            outputStreamBuilder.progress(progress);
        }
        if (checksumOpt != null) {
            outputStreamBuilder.checksumOpt(checksumOpt);
        }
        if (flags.contains(CreateFlag.CREATE)) {
            outputStreamBuilder.create();
        }
        if (flags.contains(CreateFlag.APPEND)) {
            outputStreamBuilder.append();
        }
        outputStreamBuilder.overwrite(flags.contains(CreateFlag.OVERWRITE));

        return encrypt(outputStreamBuilder, path);
    }

    private FSDataOutputStream encrypt(FSDataOutputStreamBuilder<?, ?> encryptedStreamBuilder, Path filePath)
            throws IOException {
        Optional<String> keyPathSuffix = Optional.empty();
        if (encryptedStreamBuilder instanceof CreateFileBuilder) {
            CreateFileBuilder createFileBuilder = (CreateFileBuilder) encryptedStreamBuilder;
            String suffix = UUID.randomUUID().toString();
            keyPathSuffix = Optional.of(suffix);
            createFileBuilder.opt(S3_METADATA_KEY_HEADER, suffix);
            if (log.isTraceEnabled()) {
                log.trace("Encrypting with keyPathSuffix", SafeArg.of("path", filePath), SafeArg.of("suffix", suffix));
            }
        }
        FSDataOutputStream encryptedStream = encryptedStreamBuilder.build();
        String keyPath = toKeyPath(filePath, keyPathSuffix);

        KeyMaterial keyMaterial = SeekableCipherFactory.generateKeyMaterial(cipherAlgorithm);
        SeekableCipher cipher = SeekableCipherFactory.getCipher(cipherAlgorithm, keyMaterial);

        // Ensure we can open the stream before storing keys that would be irrelevant
        OutputStream encryptedOs =
                CryptoStreamFactory.encrypt(encryptedStream, cipher.getKeyMaterial(), cipherAlgorithm);
        FSDataOutputStream os = new FSDataOutputStream(encryptedOs, statistics);
        keyStore.put(keyPath, cipher.getKeyMaterial());

        return os;
    }

    @Override
    public boolean rename(Path src, Path dst) throws IOException {
        // Copy key material first so the encrypted file always has key material in the key store even if the
        // put or rename fails
        Optional<String> keyPathSuffix = getKeyPathSuffix(src);
        String srcKeyPath = toKeyPath(src, keyPathSuffix);
        String dstKeyPath = toKeyPath(dst, keyPathSuffix);
        KeyMaterial keyMaterial = keyStore.get(srcKeyPath);
        keyStore.put(dstKeyPath, keyMaterial);
        boolean renamed = fs.rename(src, dst);

        if (renamed) {
            tryRemoveKey(srcKeyPath);
        } else {
            tryRemoveKey(dstKeyPath);
        }

        return renamed;
    }

    private void tryRemoveKey(String fileKey) {
        try {
            keyStore.remove(fileKey);
        } catch (Exception e) {
            log.warn("Unable to remove KeyMaterial for file", UnsafeArg.of("fileKey", fileKey), e);
        }
    }

    @Override
    public boolean delete(Path path, boolean recursive) throws IOException {
        if (recursive) {
            throw new SafeUnsupportedOperationException("EncryptedFileSystem does not support recursive deletes");
        }

        // Interrupted deletes should be resumable. They are expected to be retried.
        tryRemoveKey(toKeyPath(path, getKeyPathSuffix(path)));
        return fs.delete(path, false);
    }

    @Override
    public boolean exists(Path path) throws IOException {
        if (!super.exists(path)) {
            return false;
        }

        try {
            keyStore.get(toKeyPath(path, getKeyPathSuffix(path)));
            return true;
        } catch (RuntimeException ex) {
            log.warn("Raw file exists but missing in key store", SafeArg.of("path", path), ex);
            return false;
        }
    }

    @Override
    public FSDataOutputStream append(Path _path, int _bufferSize, Progressable _progress) throws IOException {
        throw new SafeUnsupportedOperationException("appending to encrypted files is not supported");
    }

    private Optional<String> getKeyPathSuffix(Path path) throws IOException {
        if (fs instanceof PathConvertingFileSystem) {
            PathConvertingFileSystem pathConvertingFs = (PathConvertingFileSystem) fs;
            Optional<HeadObjectResponse> objectMetadata = pathConvertingFs.getObjectMetadata(path);
            if (objectMetadata.isPresent()) {
                String suffix = objectMetadata.get().metadata().get(S3_METADATA_KEY);
                if (log.isTraceEnabled()) {
                    log.trace("Loaded keyPathSuffix", SafeArg.of("path", path), SafeArg.of("suffix", suffix));
                }
                return Optional.ofNullable(suffix);
            }
        }
        return Optional.empty();
    }

    private String toKeyPath(Path path, Optional<String> keyPathSuffix) {
        return path.toString() + keyPathSuffix.map(suffix -> "-crypto" + suffix).orElse("");
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
