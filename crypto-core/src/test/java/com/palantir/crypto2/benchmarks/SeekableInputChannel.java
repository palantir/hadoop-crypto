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

package com.palantir.crypto2.benchmarks;

import com.palantir.seekio.SeekableInput;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;

public final class SeekableInputChannel implements SeekableInput {

    private SeekableByteChannel channel;

    public SeekableInputChannel(SeekableByteChannel channel) {
        this.channel = channel;
    }

    @Override
    public void seek(long offset) throws IOException {
        channel.position(offset);
    }

    @Override
    public long getPos() throws IOException {
        return channel.position();
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
        return channel.read(ByteBuffer.wrap(bytes, offset, length));
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
