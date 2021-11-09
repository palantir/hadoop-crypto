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

package com.palantir.crypto2.io;

import com.palantir.crypto2.cipher.SeekableCipher;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.SeekableInput;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;

public final class CryptoStreamFactory {

    private CryptoStreamFactory() {}

    /**
     * Returns a {@link SeekableInput} that decrypts the given SeekableInput using the given {@link KeyMaterial} and
     * cipher {@code algorithm}. When OpenSSL is available an implementation that uses AES-NI will be returned.
     */
    public static SeekableInput decrypt(SeekableInput encryptedInput, KeyMaterial keyMaterial, String algorithm) {
        return new DecryptingSeekableInput(encryptedInput, SeekableCipherFactory.getCipher(algorithm, keyMaterial));
    }

    /**
     * Returns an {@link InputStream} that decrypts the given InputStream using the given {@link KeyMaterial} and
     * cipher {@code algorithm}. When OpenSSL is available an implementation that uses AES-NI will be returned.
     */
    public static InputStream decrypt(InputStream input, KeyMaterial keyMaterial, String algorithm) {
        return new DefaultSeekableInputStream(decrypt(new StreamSeekableInput(input), keyMaterial, algorithm));
    }

    /**
     * Returns an {@link OutputStream} that encrypts the given OutputStream using the given {@link KeyMaterial} and
     * cipher {@code algorithm}. When OpenSSL is available an implementation that uses AES-NI will be returned.
     */
    public static OutputStream encrypt(OutputStream output, KeyMaterial keyMaterial, String algorithm) {
        return createDefaultEncryptedStream(output, keyMaterial, algorithm);
    }

    private static OutputStream createDefaultEncryptedStream(OutputStream output, KeyMaterial keyMaterial,
            String algorithm) {
        SeekableCipher cipher = SeekableCipherFactory.getCipher(algorithm, keyMaterial);
        return new ChunkingOutputStream(new CipherOutputStream(output, cipher.initCipher(Cipher.ENCRYPT_MODE)));
    }

    private static class StreamSeekableInput implements SeekableInput {
        private final InputStream input;

        StreamSeekableInput(InputStream input) {
            this.input = input;
        }

        @Override
        public void seek(long _offset) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long getPos() {
            throw new UnsupportedOperationException();
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            return input.read(bytes, offset, length);
        }

        @Override
        public void close() throws IOException {
            input.close();
        }
    }

    /**
     * {@link ChunkingOutputStream} limits the size of individual writes to the wrapped {@link OutputStream}
     * in order to prevent degraded performance on large buffers as described in
     * <a href="https://github.com/palantir/hadoop-crypto/pull/586">hadoop-crypto#586</a>.
     */
    static final class ChunkingOutputStream extends FilterOutputStream {

        /**
         * Chunk size of 16 KB is small enough to allow cipher implementations to become hot and optimize properly
         * when given large inputs. Otherwise large array writes into a {@link CipherOutputStream} fail to use
         * intrinsified implementations. If 16 KB chunks aren't enough to produce hot methods, the I/O is small
         * and infrequent enough that performance isn't relevant.
         * For more information, see the details around {@code com.sun.crypto.provider.GHASH::processBlocks} in
         * <a href="https://github.com/palantir/hadoop-crypto/pull/586#issuecomment-964394587">
         * hadoop-crypto#586 (comment)</a>
         */
        private static final int CHUNK_SIZE = 16 * 1024;

        ChunkingOutputStream(OutputStream delegate) {
            super(delegate);
        }

        @Override
        public void write(byte[] buffer, int off, int len) throws IOException {
            validateArgs(buffer, off, len);
            doWrite(buffer, off, len);
        }

        private void doWrite(byte[] buffer, int off, int len) throws IOException {
            int currentOffset = off;
            int remaining = len;
            while (remaining > 0) {
                int toWrite = Math.min(remaining, CHUNK_SIZE);
                out.write(buffer, currentOffset, toWrite);
                currentOffset += toWrite;
                remaining -= toWrite;
            }
        }

        private static void validateArgs(byte[] buffer, int off, int len) {
            if (buffer == null) {
                throw new NullPointerException("buffer is required");
            }
            if (off < 0 || len < 0 || buffer.length < off + len) {
                throw new IndexOutOfBoundsException();
            }
        }
    }
}
