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

package com.palantir.crypto2.cipher;

import com.google.common.base.Preconditions;
import java.math.BigInteger;
import javax.crypto.spec.IvParameterSpec;

public final class CounterMode {

    public static final int BLOCK_SIZE = 16;
    public static final int IV_SIZE = 16;

    private CounterMode() {}

    /**
     * Returns the block that contains the byte at the given position.
     */
    public static long blockOffset(long position) {
        return position / BLOCK_SIZE;
    }

    /**
     * Returns the number of bytes that
     * @param position
     * @return
     */
    public static int bytesToSkip(long position) {
        return Math.toIntExact(position % BLOCK_SIZE);
    }

    public static IvParameterSpec computeIv(byte[] initIv, long blockOffset) {
        Preconditions.checkArgument(blockOffset >= 0, "Cannot seek to negative position: %s", blockOffset);

        // Compute the block that the byte 'pos' is located in
        BigInteger block = BigInteger.valueOf(blockOffset);

        // Compute the iv for the block to start decrypting. initIv needs to be treated as an unsigned int
        BigInteger ivBuffer = new BigInteger(1, initIv).add(block);
        byte[] ivBytes = ivBuffer.toByteArray();

        // Ensure the iv is exactly BLOCK_SIZE bytes in length
        final IvParameterSpec newIv;
        if (ivBytes.length >= IV_SIZE) {
            newIv = new IvParameterSpec(ivBytes, ivBytes.length - IV_SIZE, IV_SIZE);
        } else {
            final byte[] tmpIv = new byte[IV_SIZE];
            System.arraycopy(ivBytes, 0, tmpIv, IV_SIZE - ivBytes.length, ivBytes.length);
            newIv = new IvParameterSpec(tmpIv);
        }

        return newIv;
    }

}
