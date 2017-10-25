/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.example;

import static org.assertj.core.api.Assertions.assertThat;

import com.palantir.crypto2.cipher.AesCtrCipher;
import com.palantir.crypto2.cipher.SeekableCipher;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.io.DecryptingSeekableInput;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.InMemorySeekableDataInput;
import com.palantir.seekio.SeekableInput;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import org.junit.Test;

public final class ExampleUsage {

    @Test
    public void decryptingSeekableInputExample() throws IOException {
        byte[] bytes = "0123456789".getBytes(StandardCharsets.UTF_8);

        // Store this key material for future decryption
        KeyMaterial keyMaterial = SeekableCipherFactory.generateKeyMaterial(AesCtrCipher.ALGORITHM);
        SeekableCipher cipher = SeekableCipherFactory.getCipher(AesCtrCipher.ALGORITHM, keyMaterial);
        ByteArrayOutputStream os = new ByteArrayOutputStream(bytes.length);
        Cipher encrypt = cipher.initCipher(Cipher.ENCRYPT_MODE);

        // Encrypt some bytes
        CipherOutputStream encryptedStream = new CipherOutputStream(os, encrypt);
        encryptedStream.write(bytes);
        encryptedStream.close();
        byte[] encryptedBytes = os.toByteArray();

        // Bytes written to stream are encrypted
        assertThat(encryptedBytes).isNotEqualTo(bytes);

        SeekableInput is = new InMemorySeekableDataInput(encryptedBytes);
        DecryptingSeekableInput decryptedStream = new DecryptingSeekableInput(is, cipher);

        // Seek to the last byte in the decrypted stream and verify its decrypted value
        byte[] readBytes = new byte[bytes.length];
        decryptedStream.seek(bytes.length - 1);
        decryptedStream.read(readBytes, 0, 1);
        assertThat(readBytes[0]).isEqualTo(bytes[bytes.length - 1]);

        // Seek to the beginning of the decrypted stream and verify it's equal to the raw bytes
        decryptedStream.seek(0);
        decryptedStream.read(readBytes, 0, bytes.length);
        assertThat(readBytes).isEqualTo(bytes);
    }

}
