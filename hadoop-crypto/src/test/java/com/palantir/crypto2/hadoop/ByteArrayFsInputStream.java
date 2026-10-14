/*
 * (c) Copyright 2026 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.crypto2.hadoop;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import org.apache.hadoop.fs.FSInputStream;

public final class ByteArrayFsInputStream extends FSInputStream {

    private final ByteArrayInputStream in;
    private final int length;

    public ByteArrayFsInputStream(byte[] bytes) {
        in = new ByteArrayInputStream(bytes);
        length = bytes.length;
    }

    @Override
    public void seek(long position) throws EOFException {
        if (position < 0 || position > length) {
            throw new EOFException();
        }
        in.reset();
        if (in.skip(position) != position) {
            throw new EOFException();
        }
    }

    @Override
    public long getPos() {
        return (long) length - in.available();
    }

    @Override
    public boolean seekToNewSource(long _targetPos) {
        return false;
    }

    @Override
    public int read() {
        return in.read();
    }

    @Override
    public int read(byte[] buf, int off, int len) {
        return in.read(buf, off, len);
    }
}
