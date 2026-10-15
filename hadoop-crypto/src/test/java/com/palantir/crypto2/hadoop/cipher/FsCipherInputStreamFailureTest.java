/*
 * (c) Copyright 2026 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.crypto2.hadoop.cipher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.palantir.crypto2.cipher.AesCbcCipher;
import com.palantir.crypto2.cipher.AesCtrCipher;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.hadoop.ByteArrayFsInputStream;
import com.palantir.crypto2.io.CryptoStreamFactory;
import com.palantir.crypto2.keys.KeyMaterial;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSInputStream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public final class FsCipherInputStreamFailureTest {

    private static final int READABLE_CIPHERTEXT_BYTES = 64;
    private static final byte[] PLAINTEXT = new byte[128];

    static {
        Arrays.fill(PLAINTEXT, (byte) 42);
    }

    @ParameterizedTest
    @ValueSource(strings = {AesCbcCipher.ALGORITHM, AesCtrCipher.ALGORITHM})
    void positionedReadReturnsPlaintextBeforeExceptionalEof(String algorithm) throws IOException {
        try (FsCipherInputStream input = open(algorithm, READABLE_CIPHERTEXT_BYTES)) {
            byte[] result = new byte[PLAINTEXT.length];
            int bytesRead = input.read(0L, result, 0, result.length);

            // FSInputStream downgrades EOFException to -1. It must not lose a successfully decrypted prefix.
            assertThat(bytesRead).isPositive().isLessThan(result.length);
            assertThat(Arrays.copyOf(result, bytesRead)).isEqualTo(Arrays.copyOf(PLAINTEXT, bytesRead));
            assertThat(input.getPos()).isZero();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {AesCbcCipher.ALGORITHM, AesCtrCipher.ALGORITHM})
    void sequentialReadReturnsPlaintextBeforeExceptionalEof(String algorithm) throws IOException {
        try (FsCipherInputStream input = open(algorithm, READABLE_CIPHERTEXT_BYTES)) {
            byte[] result = new byte[PLAINTEXT.length];
            int bytesRead = input.read(result, 0, result.length);

            assertThat(bytesRead).isPositive().isLessThan(result.length);
            assertThat(Arrays.copyOf(result, bytesRead)).isEqualTo(Arrays.copyOf(PLAINTEXT, bytesRead));
            assertThat(input.getPos()).isEqualTo(bytesRead);
            assertThatThrownBy(() -> input.read(result, 0, result.length)).isInstanceOf(EOFException.class);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {AesCbcCipher.ALGORITHM, AesCtrCipher.ALGORITHM})
    void readFullyStillRejectsExceptionalEofAfterPlaintext(String algorithm) throws IOException {
        try (FsCipherInputStream input = open(algorithm, READABLE_CIPHERTEXT_BYTES)) {
            byte[] result = new byte[PLAINTEXT.length];

            assertThatThrownBy(() -> input.readFully(0L, result)).isInstanceOf(EOFException.class);
            assertThat(input.getPos()).isZero();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {AesCbcCipher.ALGORITHM, AesCtrCipher.ALGORITHM})
    void positionedReadReturnsMinusOneWhenNoPlaintextCanBeRead(String algorithm) throws IOException {
        try (FsCipherInputStream input = open(algorithm, 0)) {
            byte[] result = new byte[PLAINTEXT.length];

            assertThat(input.read(0L, result, 0, result.length)).isEqualTo(-1);
            assertThat(result).containsOnly(0);
            assertThat(input.getPos()).isZero();
        }
    }

    private static FsCipherInputStream open(String algorithm, int failurePosition) throws IOException {
        KeyMaterial key = SeekableCipherFactory.generateKeyMaterial(algorithm);
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        try (OutputStream output = CryptoStreamFactory.encrypt(ciphertext, key, algorithm)) {
            output.write(PLAINTEXT);
        }
        return new FsCipherInputStream(
                new FSDataInputStream(new TruncatedFsInputStream(ciphertext.toByteArray(), failurePosition)),
                key,
                algorithm);
    }

    /** Models a backing file that becomes unreadable partway through, reporting premature EOF as an exception. */
    private static final class TruncatedFsInputStream extends FSInputStream {
        private final ByteArrayFsInputStream delegate;
        private final int failurePosition;

        TruncatedFsInputStream(byte[] ciphertext, int failurePosition) {
            this.delegate = new ByteArrayFsInputStream(ciphertext);
            this.failurePosition = failurePosition;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (length == 0) {
                return 0;
            }
            if (getPos() >= failurePosition) {
                throw new EOFException("Backing file was truncated");
            }
            return delegate.read(buffer, offset, Math.min(length, failurePosition - (int) getPos()));
        }

        @Override
        public int read() throws IOException {
            byte[] singleByte = new byte[1];
            return read(singleByte, 0, 1) == -1 ? -1 : Byte.toUnsignedInt(singleByte[0]);
        }

        @Override
        public void seek(long position) throws IOException {
            delegate.seek(position);
        }

        @Override
        public long getPos() {
            return delegate.getPos();
        }

        @Override
        public boolean seekToNewSource(long _targetPos) {
            return false;
        }
    }
}
