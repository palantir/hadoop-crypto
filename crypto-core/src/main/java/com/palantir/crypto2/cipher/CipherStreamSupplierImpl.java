/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.cipher;

import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

public final class CipherStreamSupplierImpl implements CipherStreamSupplier {

    @Override
    public  CipherInputStream getInputStream(InputStream is, Cipher cipher) {
        return new CipherInputStream(is, cipher);
    }

    @Override
    public CipherOutputStream getOutputStream(OutputStream os, Cipher cipher) {
        return new CipherOutputStream(os, cipher);
    }

}
