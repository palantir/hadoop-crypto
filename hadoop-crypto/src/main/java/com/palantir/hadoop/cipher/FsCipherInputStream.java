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

import com.palantir.crypto.cipher.SeekableCipher;
import com.palantir.crypto.io.DecryptingInputStream;
import com.palantir.crypto.io.DefaultSeekableInputStream;
import com.palantir.seekio.SeekableInput;
import java.io.IOException;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSInputStream;

/**
 * Decrypts data read from the given {@link FSDataInputStream} using the given {@link SeekableCipher}.
 */
public final class FsCipherInputStream extends FSInputStream {

    private final DefaultSeekableInputStream delegate;

    public FsCipherInputStream(FSDataInputStream delegate, SeekableCipher cipher) {
        this.delegate = new DefaultSeekableInputStream(
                new DecryptingInputStream(new FsSeekableInput(delegate), cipher));
    }

    @Override
    public void seek(long pos) throws IOException {
        delegate.seek(pos);
    }

    @Override
    public long getPos() throws IOException {
        return delegate.getPos();
    }

    @Override
    public boolean seekToNewSource(long targetPos) throws IOException {
        return false;
    }

    @Override
    public int read() throws IOException {
        return delegate.read();
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        return delegate.read(buffer, offset, length);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    /**
     * Wrapper that converts an {@link FSDataInputStream} into a {@link SeekableInput}.
     */
    private static final class FsSeekableInput implements SeekableInput {

        private FSDataInputStream input;

        private FsSeekableInput(FSDataInputStream input) {
            this.input = input;
        }

        @Override
        public void seek(long offset) throws IOException {
            input.seek(offset);
        }

        @Override
        public long getPos() throws IOException {
            return input.getPos();
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            return input.read(bytes, offset, length);
        }

        @Override
        public void close() throws IOException {
            input.close();
        }
    }

}
