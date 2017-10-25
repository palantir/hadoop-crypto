/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.cipher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import org.junit.Before;
import org.junit.Test;

public final class CipherStreamSupplierImplTest {

    private CipherStreamSupplier supplier;
    private InputStream is;
    private OutputStream os;
    private Cipher cipher;

    @Before
    public void before() {
        is = mock(InputStream.class);
        os = mock(OutputStream.class);
        cipher = mock(Cipher.class);
        supplier = new CipherStreamSupplierImpl();
    }

    @Test
    public void testGetCipherInputStream() throws IOException {
        assertThat(supplier.getInputStream(is, cipher)).isInstanceOf(CipherInputStream.class);
    }

    @Test
    public void testGetCipherOutputStream() {
        assertThat(supplier.getOutputStream(os, cipher)).isInstanceOf(CipherOutputStream.class);
    }

}
