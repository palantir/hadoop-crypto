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

import com.google.common.annotations.VisibleForTesting;
import com.palantir.crypto2.cipher.ApacheCiphers;
import com.palantir.crypto2.cipher.SeekableCipher;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.SeekableInput;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import org.apache.commons.crypto.stream.CtrCryptoOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class CryptoStreamFactory {

    private static final Logger log = LoggerFactory.getLogger(CryptoStreamFactory.class);
    private static final Properties PROPS = ApacheCiphers.forceOpenSsl(new Properties());
    private static final String AES_ALGORITHM = "AES/CTR/NoPadding";
    private static final String OPEN_SSL_INIT_WARNING = "Unable to initialize cipher with OpenSSL, falling back to "
            + "JCE implementation - see github.com/palantir/hadoop-crypto#faq";

    private static volatile boolean fullExceptionLoggedAlready = false;

    private CryptoStreamFactory() {}

    /**
     * Returns a {@link SeekableInput} that decrypts the given SeekableInput using the given {@link KeyMaterial} and
     * cipher {@code algorithm}. When OpenSSL is available an implementation that uses AES-NI will be returned.
     */
    public static SeekableInput decrypt(SeekableInput encryptedInput, KeyMaterial keyMaterial, String algorithm) {
        return decrypt(encryptedInput, keyMaterial, algorithm, false);
    }

    @SuppressWarnings("CatchBlockLogException")
    @VisibleForTesting
    static SeekableInput decrypt(
            SeekableInput encryptedInput, KeyMaterial keyMaterial, String algorithm, boolean forceJce) {
        if (!algorithm.equals(AES_ALGORITHM) || forceJce) {
            return new DecryptingSeekableInput(encryptedInput, SeekableCipherFactory.getCipher(algorithm, keyMaterial));
        }

        try {
            return new ApacheCtrDecryptingSeekableInput(encryptedInput, keyMaterial);
        } catch (IOException e) {
            warningLog(e);
            return new DecryptingSeekableInput(encryptedInput, SeekableCipherFactory.getCipher(algorithm, keyMaterial));
        }
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
        return encrypt(output, keyMaterial, algorithm, false);
    }

    @SuppressWarnings("CatchBlockLogException")
    @VisibleForTesting
    static OutputStream encrypt(OutputStream output, KeyMaterial keyMaterial, String algorithm, boolean forceJce) {
        if (!algorithm.equals(AES_ALGORITHM) || forceJce) {
            return createDefaultEncryptedStream(output, keyMaterial, algorithm);
        }

        try {
            return createApacheEncryptedStream(output, keyMaterial);
        } catch (IOException e) {
            warningLog(e);
            return createDefaultEncryptedStream(output, keyMaterial, algorithm);
        }
    }

    /** To avoid spamming logs with exceptions, we only log the exception once. */
    private static void warningLog(IOException exception) {
        if (fullExceptionLoggedAlready) {
            log.warn(OPEN_SSL_INIT_WARNING);
        } else {
            log.warn(OPEN_SSL_INIT_WARNING, exception);
            fullExceptionLoggedAlready = true;
        }
    }

    private static OutputStream createApacheEncryptedStream(OutputStream output, KeyMaterial keyMaterial)
            throws IOException {
        SecretKey secretKey = keyMaterial.getSecretKey();
        byte[] iv = keyMaterial.getIv();
        return new CtrCryptoOutputStream(PROPS, output, secretKey.getEncoded(), iv);
    }

    private static OutputStream createDefaultEncryptedStream(
            OutputStream output, KeyMaterial keyMaterial, String algorithm) {
        SeekableCipher cipher = SeekableCipherFactory.getCipher(algorithm, keyMaterial);
        return new CipherOutputStream(output, cipher.initCipher(Cipher.ENCRYPT_MODE));
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
}
