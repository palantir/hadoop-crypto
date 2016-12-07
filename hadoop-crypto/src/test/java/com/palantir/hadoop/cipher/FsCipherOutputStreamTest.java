/*
 * Copyright 2016 Palantir Technologies, Inc. All rights reserved.
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

package com.palantir.hadoop.cipher;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.palantir.crypto.cipher.CipherStreamSupplier;
import com.palantir.crypto.cipher.SeekableCipher;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.junit.Before;
import org.junit.Test;

public final class FsCipherOutputStreamTest {

    private FSDataOutputStream os;
    private Cipher initCipher;
    private SeekableCipher seekableCipher;
    private CipherStreamSupplier supplier;
    private CipherOutputStream cos;
    private FsCipherOutputStream scos;

    @Before
    public void before()
            throws ShortBufferException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        initCipher = mock(Cipher.class);
        os = mock(FSDataOutputStream.class);
        cos = mock(CipherOutputStream.class);
        seekableCipher = mock(SeekableCipher.class);
        supplier = mock(CipherStreamSupplier.class);

        when(seekableCipher.initCipher(anyInt())).thenReturn(initCipher);
        when(supplier.getOutputStream(os, initCipher)).thenReturn(cos);

        scos = new FsCipherOutputStream(os, seekableCipher, supplier);
    }

    @Test
    public void testInit() throws IOException {
        verify(seekableCipher).initCipher(Cipher.ENCRYPT_MODE);
        verify(supplier).getOutputStream(os, initCipher);
    }

    @Test
    public void testWrite() throws IOException {
        scos.write(0);
        verify(cos).write(0);
    }

}
