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

import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.SeekableInput;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Properties;
import org.apache.commons.crypto.stream.CtrCryptoInputStream;
import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.crypto.utils.Utils;

public final class ApacheCtrDecryptingSeekableInput extends CtrCryptoInputStream implements SeekableInput {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int BUFFER_SIZE = 8192;

    private ApacheCtrDecryptingSeekableInput(SeekableInput input, KeyMaterial keyMaterial) throws IOException {
        super(new InputAdapter(input), Utils.getCipherInstance(ALGORITHM, new Properties()), BUFFER_SIZE,
                keyMaterial.getSecretKey().getEncoded(), keyMaterial.getIv());
    }

    public static ApacheCtrDecryptingSeekableInput create(SeekableInput input, KeyMaterial keyMaterial) {
        try {
            return new ApacheCtrDecryptingSeekableInput(input, keyMaterial);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
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

    private static final class InputAdapter implements Input {

        private SeekableInput input;

        private InputAdapter(SeekableInput input) {
            this.input = input;
        }

        @Override
        public int read(long position, byte[] buffer, int offset, int length) throws IOException {
            input.seek(position);
            return input.read(buffer, offset, length);
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            byte[] bytes = new byte[dst.capacity() - dst.position()];
            int read = input.read(bytes, 0, bytes.length);

            if (read != -1) {
                dst.put(bytes, 0, read);
            }

            return read;
        }

        @Override
        public long skip(long bytes) throws IOException {
            input.seek(input.getPos() + bytes);
            return bytes;
        }

        @Override
        public int available() throws IOException {
            return 0;
        }

        @Override
        public void seek(long position) throws IOException {
            input.seek(position);
        }

        @Override
        public void close() throws IOException {
            input.close();
        }
    }

}
