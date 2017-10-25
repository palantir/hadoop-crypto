/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.cipher;

import java.util.Properties;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;

public final class ApacheCiphers {

    private ApacheCiphers() {}

    /**
     * Configures the provided {@link Properties} such that {@link CryptoCipherFactory#getCryptoCipher(String,
     * Properties)} will only try to use the OpenSSL cipher implementation which uses AES-NI.
     */
    public static Properties forceOpenSsl(Properties properties) {
        properties.setProperty(CryptoCipherFactory.CLASSES_KEY,
                CryptoCipherFactory.CipherProvider.OPENSSL.getClassName());
        return properties;
    }

}
