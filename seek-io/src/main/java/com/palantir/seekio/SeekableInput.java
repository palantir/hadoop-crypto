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

package com.palantir.seekio;

import java.io.Closeable;
import java.io.IOException;

/**
 * A marker interface for seekable inputs.
 * <p>
 * {@link #seek(long)} and {@link #getPos()} are assumed to be both cheap and fast.
 */
public interface SeekableInput extends Closeable {

    /**
     * Seeks to the given offset in the stream.
     */
    void seek(long offset) throws IOException;

    /**
     * Gets the current byte offset in the stream.
     */
    long getPos() throws IOException;

    /**
     * @see java.io.InputStream#read(byte[], int, int)
     */
    int read(byte[] bytes, int offset, int length) throws IOException;

}
