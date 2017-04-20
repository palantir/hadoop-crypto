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

package com.palantir.crypto2.cipher;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.palantir.crypto2.keys.KeyMaterial;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.crypto.stream.CryptoInputStream;
import org.apache.commons.crypto.stream.CryptoOutputStream;
import org.junit.Before;
import org.junit.Test;

public final class CipherStreamSupplierImplTest {

    private CipherStreamSupplier supplier;
    private InputStream is;
    private OutputStream os;
    private SeekableCipher seekableCipher;

    private String algorithm = "AES/CBC/PKCS5Padding";
    private SecretKey key;


    @Before
    public void before() throws NoSuchAlgorithmException {
        is = mock(InputStream.class);
        os = mock(OutputStream.class);
        seekableCipher = mock(SeekableCipher.class);
        supplier = new CipherStreamSupplierImpl();

        byte[] iv = new byte[16];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(iv);
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        this.key = keyGen.generateKey();

        when(seekableCipher.getAlgorithm()).thenReturn(algorithm);
        when(seekableCipher.getKeyMaterial()).thenReturn(KeyMaterial.of(key, iv));
        when(seekableCipher.getCurrIv()).thenReturn(new IvParameterSpec(iv));
    }

    @Test
    public void testGetCryptoInputStream() throws IOException {
        assertEquals(supplier.getInputStream(is, seekableCipher).getClass(), CryptoInputStream.class);
    }

    @Test
    public void testGetCryptoOutputStream() {
        assertEquals(supplier.getOutputStream(os, seekableCipher).getClass(), CryptoOutputStream.class);
    }

}
