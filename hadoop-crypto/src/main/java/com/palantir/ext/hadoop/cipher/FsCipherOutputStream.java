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

package com.palantir.ext.hadoop.cipher;

import com.google.common.annotations.VisibleForTesting;
import java.io.FilterOutputStream;
import javax.crypto.Cipher;
import org.apache.hadoop.fs.FSDataOutputStream;

/**
 * Encrypts data using the given {@link SeekableCipher} and writes it to the given {@link FSDataOutputStream}.
 */
public class FsCipherOutputStream extends FilterOutputStream {

    public FsCipherOutputStream(FSDataOutputStream delegate, SeekableCipher cipher) {
        this(delegate, cipher, new CipherStreamSupplierImpl());
    }

    @VisibleForTesting
    FsCipherOutputStream(FSDataOutputStream delegate, SeekableCipher cipher,
            CipherStreamSupplier supplier) {
        super(supplier.getOutputStream(delegate, cipher.initCipher(Cipher.ENCRYPT_MODE)));
    }

}
