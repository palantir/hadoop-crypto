/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.crypto2.io;

import com.palantir.crypto2.cipher.ApacheCiphers;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.SeekableInput;
import java.io.IOException;
import java.util.Properties;
import org.apache.commons.crypto.stream.CtrCryptoInputStream;
import org.apache.commons.crypto.stream.input.StreamInput;
import org.apache.commons.crypto.utils.Utils;

/**
 * A {@link SeekableInput} that decrypts AES/CTR encrypted SeekableInputs using the given {@link KeyMaterial}. This
 * implementation uses Apache's {@link CtrCryptoInputStream} which uses OpenSSL and supports AES-NI.
 */
public final class ApacheCtrDecryptingSeekableInput extends CtrCryptoInputStream implements SeekableInput {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int BUFFER_SIZE = 8192;
    // Force OpenSSL for AES-NI support
    private static final Properties PROPS = ApacheCiphers.forceOpenSsl(new Properties());

    /**
     * Creates a new {@link ApacheCtrDecryptingSeekableInput}. This constructor is expected to succeed if and only if
     * the OpenSSL library is able to be loaded.
     */
    ApacheCtrDecryptingSeekableInput(SeekableInput input, KeyMaterial keyMaterial) throws IOException {
        super(new StreamInput(new DefaultSeekableInputStream(input), BUFFER_SIZE),
                Utils.getCipherInstance(ALGORITHM, PROPS),
                BUFFER_SIZE,
                keyMaterial.getSecretKey().getEncoded(),
                keyMaterial.getIv());
    }

    @Override
    public void seek(long offset) throws IOException {
        super.seek(offset);
    }

    @Override
    public long getPos() throws IOException {
        return super.getStreamPosition();
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
        return super.read(bytes, offset, length);
    }

    @Override
    public void close() throws IOException {
        super.close();
    }
}
