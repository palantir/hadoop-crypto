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
import com.palantir.crypto2.io.CryptoStreamFactory;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.InMemorySeekableDataInput;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSInputStream;
import org.junit.jupiter.api.Test;

public final class FsCipherInputStreamTest {
    @Test
    public void ctrPositionedReadDoesNotSeekBetweenCipherChunks() throws IOException {
        verifyPositionedReads(AesCtrCipher.ALGORITHM);
    }

    @Test
    public void cbcPositionedReadDoesNotSeekBetweenCipherChunks() throws IOException {
        verifyPositionedReads(AesCbcCipher.ALGORITHM);
    }

    private static void verifyPositionedReads(String algorithm) throws IOException {
        byte[] data = new byte[131_079];
        new Random(0).nextBytes(data);
        KeyMaterial key = SeekableCipherFactory.generateKeyMaterial(algorithm);
        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
        try (OutputStream output = CryptoStreamFactory.encrypt(encrypted, key, algorithm)) {
            output.write(data);
        }
        CountingInput source = new CountingInput(encrypted.toByteArray());
        try (FSDataInputStream input =
                new FSDataInputStream(new FsCipherInputStream(new FSDataInputStream(source), key, algorithm))) {
            input.seek(100_003);
            source.seeks = 0;
            byte[] actual = new byte[65_545];
            Arrays.fill(actual, (byte) 91);
            input.readFully(37, actual, 3, 65_539);
            assertThat(Arrays.copyOfRange(actual, 3, 65_542)).isEqualTo(Arrays.copyOfRange(data, 37, 65_576));
            assertThat(Arrays.copyOf(actual, 3)).containsOnly((byte) 91);
            assertThat(Arrays.copyOfRange(actual, 65_542, actual.length)).containsOnly((byte) 91);
            assertThat(input.getPos()).isEqualTo(100_003);
            assertThat(source.seeks).isEqualTo(2);

            input.readFully(0, actual, 0, 0);
            assertThat(input.getPos()).isEqualTo(100_003);
            byte[] tail = new byte[9];
            Arrays.fill(tail, (byte) 91);
            assertThatThrownBy(() -> input.readFully(data.length - 3, tail)).isInstanceOf(EOFException.class);
            assertThat(Arrays.copyOf(tail, 3)).isEqualTo(Arrays.copyOfRange(data, data.length - 3, data.length));
            assertThat(Arrays.copyOfRange(tail, 3, tail.length)).containsOnly((byte) 91);
            assertThat(input.getPos()).isEqualTo(100_003);

            input.readFully(71, tail);
            assertThat(tail).isEqualTo(Arrays.copyOfRange(data, 71, 80));
            assertThat(input.getPos()).isEqualTo(100_003);
        }
    }

    private static final class CountingInput extends FSInputStream {
        private final InMemorySeekableDataInput delegate;
        private int seeks;

        CountingInput(byte[] encrypted) {
            delegate = new InMemorySeekableDataInput(encrypted);
        }

        @Override
        public int read() throws IOException {
            byte[] value = new byte[1];
            return read(value, 0, 1) == -1 ? -1 : Byte.toUnsignedInt(value[0]);
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            return delegate.read(buffer, offset, length);
        }

        @Override
        public void seek(long offset) throws IOException {
            seeks++;
            delegate.seek(offset);
        }

        @Override
        public long getPos() throws IOException {
            return delegate.getPos();
        }

        @Override
        public boolean seekToNewSource(long _position) {
            return false;
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
