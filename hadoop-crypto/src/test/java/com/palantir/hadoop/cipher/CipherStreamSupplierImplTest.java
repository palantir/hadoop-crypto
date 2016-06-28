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

import static org.junit.Assert.assertEquals;
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
        assertEquals(supplier.getInputStream(is, cipher).getClass(), CipherInputStream.class);
    }

    @Test
    public void testGetCipherOutputStream() {
        assertEquals(supplier.getOutputStream(os, cipher).getClass(), CipherOutputStream.class);
    }

}
