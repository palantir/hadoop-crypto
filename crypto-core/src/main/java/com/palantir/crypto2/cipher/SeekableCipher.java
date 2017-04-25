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

package com.palantir.crypto2.cipher;

import com.palantir.crypto2.keys.KeyMaterial;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.CryptoInputStream;
import org.apache.commons.crypto.stream.CryptoOutputStream;

/**
 * Provides information used to construct a {@link CryptoCipher}, along with the ability to update that
 * information when seeking to a different location in a {@link CryptoInputStream} or {@link CryptoOutputStream}.
 * // TODO(jellis): add note about using SeekableCipher streams instead of this directly
 */
public interface SeekableCipher {

    /**
     * The returned {@link CryptoCipher} is initialized such that future operations will encrypt/decrypt correctly for
     * the given byte offset {@code pos} into the plaintext data. Certain ciphers have special requirements and
     * restrictions on how and to where they are able to be seeked.
     */
    void updateIvForNewPosition(long pos);

    /**
     * Returns the {@link KeyMaterial} being used by this {@link SeekableCipher} for cryptographic operations.
     */
    KeyMaterial getKeyMaterial();

    /**
     * Returns the underlying {@link CryptoCipher}'s block size.
     */
    int getBlockSize();

    /**
     * Returns the algorithm used by the underlying {@link CryptoCipher} for encryption and decryption.
     */
    String getAlgorithm();

    /**
     * Returns the initialization vector for the block that the underlying {@link CryptoCipher} will encrypt or decrypt
     * next.
     */
    IvParameterSpec getCurrIv();

}
