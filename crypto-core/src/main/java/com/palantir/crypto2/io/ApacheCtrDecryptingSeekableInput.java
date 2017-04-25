/*
 * Copyright 2017 Palantir Technologies, Inc. All rights reserved.
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

import com.google.common.io.ByteStreams;
import com.palantir.crypto2.cipher.CounterMode;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.SeekableInput;
import java.io.IOException;
import java.util.Properties;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.crypto.stream.CryptoInputStream;

public final class ApacheCtrDecryptingSeekableInput implements SeekableInput {

    private static final String ALGORITHM = "AES/CTR/NoPadding";

    private SeekableInput input;
    private SecretKey key;
    private byte[] iv;
    private CryptoInputStream decryptingStream;
    private Properties properties;
    private long decryptedStreamPos;

    public ApacheCtrDecryptingSeekableInput(SeekableInput input, KeyMaterial keyMaterial) {
        this.input = input;
        this.key = keyMaterial.getSecretKey();
        this.iv = keyMaterial.getIv();
        this.properties = new Properties();
        this.decryptingStream = getCryptoInputStream(input, new IvParameterSpec(iv));
        this.decryptedStreamPos = 0;
    }

    @Override
    public void seek(long offset) throws IOException {
        long blockOffset = offset / CounterMode.BLOCK_SIZE;
        IvParameterSpec newIv = CounterMode.computeIv(iv, blockOffset);
        input.seek(blockOffset);

        decryptingStream = getCryptoInputStream(input, newIv);

        long skip = (int) offset % CounterMode.BLOCK_SIZE;
        ByteStreams.skipFully(decryptingStream, skip);

        decryptedStreamPos = offset;
    }

    @Override
    public long getPos() throws IOException {
        return decryptedStreamPos;
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
        int bytesRead = decryptingStream.read(bytes, offset, length);
        if (bytesRead != -1) {
            decryptedStreamPos += bytesRead;
        }
        return bytesRead;
    }

    @Override
    public void close() throws IOException {
        decryptingStream.close();
    }

    private CryptoInputStream getCryptoInputStream(SeekableInput in, IvParameterSpec ivSpec) {
        try {
            DefaultSeekableInputStream is = new DefaultSeekableInputStream(in);
            return new CryptoInputStream(ALGORITHM, properties, is, key, ivSpec);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
