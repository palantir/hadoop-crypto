/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.hadoop.cipher;

import com.google.common.annotations.VisibleForTesting;
import com.palantir.crypto2.cipher.CipherStreamSupplier;
import com.palantir.crypto2.cipher.CipherStreamSupplierImpl;
import com.palantir.crypto2.cipher.SeekableCipher;
import java.io.FilterOutputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import org.apache.hadoop.fs.FSDataOutputStream;

/**
 * Encrypts data using the given {@link SeekableCipher} and writes it to the given {@link FSDataOutputStream}.
 * @deprecated use {@link javax.crypto.CipherOutputStream} directly.
 */
@Deprecated
public class FsCipherOutputStream extends FilterOutputStream {

    public FsCipherOutputStream(FSDataOutputStream delegate, SeekableCipher cipher) {
        this(delegate, cipher, new CipherStreamSupplierImpl());
    }

    @VisibleForTesting
    FsCipherOutputStream(FSDataOutputStream delegate, SeekableCipher cipher,
            CipherStreamSupplier supplier) {
        super(supplier.getOutputStream(delegate, cipher.initCipher(Cipher.ENCRYPT_MODE)));
    }

    @Override
    public void write(byte[] bytes, int off, int len) throws IOException {
        out.write(bytes, off, len);
    }

    @Override
    public void write(byte[] bytes) throws IOException {
        out.write(bytes);
    }

}
