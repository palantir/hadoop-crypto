/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.cipher;

import com.palantir.crypto2.keys.KeyMaterial;
import javax.crypto.Cipher;

/**
 * Provides access to a {@link Cipher} with the ability to {@link #seek} the Cipher.
 * // TODO(jellis): add note about using SeekableCipher streams instead of this directly
 */
public interface SeekableCipher {

    /**
     * Initialize the underlying {@link Cipher} to either {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}.
     */
    Cipher initCipher(int opmode);

    /**
     * The returned {@link Cipher} is initialized such that future operations will encrypt/decrypt correctly for the
     * given byte offset {@code pos} into the plaintext data. Certain Ciphers have special requirements and restrictions
     * on how and where they are able to be seeked to.
     */
    Cipher seek(long pos);

    /**
     * Returns the {@link KeyMaterial} being used by this {@link SeekableCipher} for cryptographic operations.
     */
    KeyMaterial getKeyMaterial();

    /**
     * Returns the underlying {@link Cipher}'s block size.
     */
    int getBlockSize();

}
