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

package com.palantir.crypto2.hadoop;

import com.palantir.crypto2.cipher.SeekableCipher;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.hadoop.cipher.FsCipherOutputStream;
import com.palantir.crypto2.keys.KeyMaterial;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Properties;
import javax.crypto.SecretKey;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.stream.CtrCryptoOutputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class EncryptedOutputStreamFactory {

    private static final Logger log = LoggerFactory.getLogger(EncryptedOutputStreamFactory.class);
    private static final Properties PROPS = initializeProps();
    private static final String AES_ALGORITHM = "AES/CTR/NoPadding";

    private EncryptedOutputStreamFactory() {}

    /**
     * Returns an {@link OutputStream} that encrypts the given {@link FSDataOutputStream} using the given {@link
     * KeyMaterial} and cipher {@code algorithm}. When OpenSSL is available an implementation that uses AES-NI will be
     * returned.
     */
    static OutputStream encrypt(FSDataOutputStream output, KeyMaterial keyMaterial, String algorithm) {
        if (!algorithm.equals(AES_ALGORITHM)) {
            return createDefaultOutputStream(output, algorithm);
        }

        try {
            return createApacheOutputStream(output, keyMaterial);
        } catch (IOException e) {
            log.warn("Unable to initialize cipher with OpenSSL, falling back to JCE implementation");
            return createDefaultOutputStream(output, algorithm);
        }
    }

    private static OutputStream createApacheOutputStream(FSDataOutputStream output, KeyMaterial keyMaterial)
            throws IOException {
        SecretKey secretKey = keyMaterial.getSecretKey();
        byte[] iv = keyMaterial.getIv();
        return new CtrCryptoOutputStream(PROPS, output, secretKey.getEncoded(), iv);
    }

    private static OutputStream createDefaultOutputStream(FSDataOutputStream output, String algorithm) {
        SeekableCipher cipher = SeekableCipherFactory.getCipher(algorithm);
        return new FsCipherOutputStream(output, cipher);
    }

    private static Properties initializeProps() {
        Properties props = new Properties();
        props.setProperty(CryptoCipherFactory.CLASSES_KEY, CryptoCipherFactory.CipherProvider.OPENSSL.getClassName());
        return props;
    }

}
