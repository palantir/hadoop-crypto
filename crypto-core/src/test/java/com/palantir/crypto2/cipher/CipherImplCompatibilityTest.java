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
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import com.palantir.crypto2.io.DecryptingSeekableInput;
import com.palantir.seekio.InMemorySeekableDataInput;
import com.palantir.seekio.SeekableInput;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import org.apache.commons.crypto.stream.CryptoOutputStream;
import org.junit.Test;

public class CipherImplCompatibilityTest {

    @Test
    public void encryptWithJavaxAndDecryptWithApache() throws GeneralSecurityException, IOException {

        byte[] bytes = "0123456789".getBytes(StandardCharsets.UTF_8);
        SeekableCipher seekableCipher = SeekableCipherFactory.getCipher(AesCtrCipher.ALGORITHM);
        seekableCipher.initCipher(Cipher.DECRYPT_MODE);

        // Encrypt using the javax.crypto library
        Cipher encryptCipher = Cipher.getInstance(AesCtrCipher.ALGORITHM);
        encryptCipher.init(Cipher.ENCRYPT_MODE, seekableCipher.getKeyMaterial().getSecretKey(),
                seekableCipher.getCurrIv());

        ByteArrayOutputStream os = new ByteArrayOutputStream(bytes.length);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(os, encryptCipher);
        cipherOutputStream.write(bytes);
        cipherOutputStream.close();
        byte[] encryptedBytes = os.toByteArray();

        // Bytes written to stream are encrypted
        assertThat(encryptedBytes, is(not(bytes)));

        // Decrypt using the commons-crypto library
        SeekableInput is = new InMemorySeekableDataInput(encryptedBytes);
        DecryptingSeekableInput decryptedStream = new DecryptingSeekableInput(is, seekableCipher);

        byte[] decryptedBytes = new byte[bytes.length];
        decryptedStream.read(decryptedBytes, 0, encryptedBytes.length);
        assertThat(bytes, is(decryptedBytes));
    }

    @Test
    public void encryptWithApacheAndDecryptWithJavax() throws GeneralSecurityException, IOException {

        byte[] bytes = "0123456789".getBytes(StandardCharsets.UTF_8);
        SeekableCipher seekableCipher = SeekableCipherFactory.getCipher(AesCtrCipher.ALGORITHM);
        ByteArrayOutputStream os = new ByteArrayOutputStream(bytes.length);
        seekableCipher.initCipher(Cipher.ENCRYPT_MODE);

        // Encrypt using the commons-crypto library
        CryptoOutputStream encryptedStream = new CryptoOutputStream(AesCtrCipher.ALGORITHM,
                new Properties(),
                os,
                seekableCipher.getKeyMaterial().getSecretKey(),
                seekableCipher.getCurrIv());
        encryptedStream.write(bytes);
        encryptedStream.close();
        byte[] encryptedBytes = os.toByteArray();

        // Bytes written to stream are encrypted
        assertThat(encryptedBytes, is(not(bytes)));

        // Decrypt using the javax.crypto library
        Cipher decryptCipher = Cipher.getInstance(AesCtrCipher.ALGORITHM);
        decryptCipher.init(Cipher.DECRYPT_MODE,
                seekableCipher.getKeyMaterial().getSecretKey(),
                seekableCipher.getCurrIv());

        CipherInputStream is = new CipherInputStream(new ByteArrayInputStream(encryptedBytes), decryptCipher);
        byte[] decryptedBytes = new byte[bytes.length];
        is.read(decryptedBytes, 0, encryptedBytes.length);
        assertThat(bytes, is(decryptedBytes));
    }
}
