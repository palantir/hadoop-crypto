/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.io;

import com.palantir.seekio.SeekableInput;
import java.io.IOException;
import java.io.InputStream;

public final class DefaultSeekableInputStream extends InputStream implements SeekableInput {

    private final byte[] oneByte = new byte[1];
    private final SeekableInput input;

    public DefaultSeekableInputStream(SeekableInput input) {
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
    public int read() throws IOException {
        int numRead = input.read(oneByte, 0, 1);
        if (numRead == 1) {
            return oneByte[0] & 0xFF;
        } else {
            return numRead;
        }
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
