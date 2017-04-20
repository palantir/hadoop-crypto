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

import com.google.common.base.Throwables;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.crypto.stream.CryptoInputStream;
import org.apache.commons.crypto.stream.CryptoOutputStream;

public final class CipherStreamSupplierImpl implements CipherStreamSupplier {

    @Override
    public CryptoInputStream getInputStream(InputStream is, SeekableCipher cipher) {
        try {
            return new CryptoInputStream(cipher.getAlgorithm(),
                    new Properties(),
                    is,
                    cipher.getKeyMaterial().getSecretKey(),
                    new IvParameterSpec(cipher.getKeyMaterial().getIv()));
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
    }

    @Override
    public CryptoOutputStream getOutputStream(OutputStream os, SeekableCipher cipher) {
        try {
            return new CryptoOutputStream(cipher.getAlgorithm(),
                    new Properties(),
                    os,
                    cipher.getKeyMaterial().getSecretKey(),
                    new IvParameterSpec(cipher.getKeyMaterial().getIv()));
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
    }

}
