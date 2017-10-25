/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.cipher;

import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

/**
 * Wraps streams in cryptographic streams for encryption and decryption.
 */
public interface CipherStreamSupplier {

    /**
     * Wraps the {@link InputStream} in a {@link CipherInputStream} which uses the given {@link Cipher} for decryption.
     */
    CipherInputStream getInputStream(InputStream is, Cipher cipher);

    /**
     * Wraps the {@link OutputStream} in a {@link CipherOutputStream} which uses the given {@link Cipher} for
     * encryption.
     */
    CipherOutputStream getOutputStream(OutputStream os, Cipher cipher);

}
