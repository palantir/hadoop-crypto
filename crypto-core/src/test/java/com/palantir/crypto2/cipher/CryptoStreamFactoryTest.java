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

package com.palantir.crypto2.cipher;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import com.palantir.crypto2.io.CryptoStreamFactory;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.InMemorySeekableDataInput;
import com.palantir.seekio.SeekableInput;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

public final class CryptoStreamFactoryTest {
    @Test
    public void testEncryptDecrypt() throws IOException {
        byte[] bytes = "data".getBytes(StandardCharsets.UTF_8);
        KeyMaterial keyMaterial = AesCtrCipher.generateKeyMaterial();

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        OutputStream encrypted = CryptoStreamFactory.encrypt(os, keyMaterial, AesCtrCipher.ALGORITHM);

        encrypted.write(bytes);
        encrypted.close();

        SeekableInput decrypted = CryptoStreamFactory.decrypt(
                new InMemorySeekableDataInput(os.toByteArray()), keyMaterial, AesCtrCipher.ALGORITHM);

        byte[] readBytes = new byte[bytes.length];
        int bytesRead = decrypted.read(readBytes, 0, bytes.length);

        assertThat(bytesRead, is(bytes.length));
        assertThat(readBytes, is(bytes));
    }
}
