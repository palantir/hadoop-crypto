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
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.palantir.crypto2.cipher.AesCbcCipher;
import com.palantir.crypto2.hadoop.ByteArrayFsInputStream;
import com.palantir.crypto2.io.CryptoStreamFactory;
import com.palantir.crypto2.keys.KeyMaterial;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;
import org.apache.hadoop.fs.FSDataInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public final class FsCipherInputStreamTest {

    private static final int MB = 1024 * 1024;
    private static final Random random = new Random();

    private byte[] plaintext;
    private KeyMaterial key;
    private byte[] encrypted;
    private FSDataInputStream underlying;
    private FsCipherInputStream input;

    @BeforeEach
    void beforeEach() throws IOException {
        plaintext = new byte[MB];
        random.nextBytes(plaintext);

        key = AesCbcCipher.generateKeyMaterial();
        encrypted = encrypt(plaintext, key, AesCbcCipher.ALGORITHM);
        underlying = spy(new FSDataInputStream(new ByteArrayFsInputStream(encrypted)));
        input = new FsCipherInputStream(underlying, key, AesCbcCipher.ALGORITHM);
    }

    @Test
    void readFullySeeksOnce() throws IOException {
        byte[] result = new byte[MB];
        input.readFully(0, result, 0, MB);

        assertThat(result).isEqualTo(plaintext);
        verify(underlying).seek(anyLong());
    }

    @Test
    void readFullyAtOffsetSeeksTwice() throws IOException {
        int offset = 1_000;

        byte[] result = new byte[MB - offset];
        input.readFully(offset, result, 0, MB - offset);

        assertThat(result).isEqualTo(Arrays.copyOfRange(plaintext, offset, MB));
        verify(underlying, times(2)).seek(anyLong());
    }

    @Test
    void readFullyEof() {
        byte[] result = new byte[10];
        assertThatThrownBy(() -> input.readFully(MB - 5, result, 0, 10)).isInstanceOf(EOFException.class);
    }

    @Test
    void readZeroBytes() throws IOException {
        byte[] result = new byte[10];
        int bytesRead = input.read(result, 0, 0);

        assertThat(bytesRead).isZero();
        assertThat(result).containsOnly(0);
    }

    @Test
    void readThroughEof() throws IOException {
        byte[] result = new byte[MB + 1];
        int bytesRead = input.read(result, 0, result.length);

        assertThat(bytesRead).isEqualTo(MB);
        assertThat(Arrays.copyOf(result, bytesRead)).isEqualTo(plaintext);
        assertThat(result[MB]).isZero();
    }

    @Test
    void readEof() throws IOException {
        byte[] result = new byte[10];
        input.seek(MB);
        int bytesRead = input.read(result, 0, 10);

        assertThat(bytesRead).isEqualTo(-1);
    }

    private static byte[] encrypt(byte[] plaintext, KeyMaterial key, String algorithm) throws IOException {
        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
        try (OutputStream output = CryptoStreamFactory.encrypt(encrypted, key, algorithm)) {
            output.write(plaintext);
        }
        return encrypted.toByteArray();
    }
}
