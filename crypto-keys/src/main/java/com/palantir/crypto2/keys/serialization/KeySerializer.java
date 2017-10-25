/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys.serialization;

import com.palantir.crypto2.keys.KeyMaterial;
import java.security.PrivateKey;
import java.security.PublicKey;

interface KeySerializer {

    /**
     * Serializes the given {@link KeyMaterial} and wraps the {@link javax.crypto.SecretKey} using the provided {@link
     * PublicKey}. The produced {@code byte[]} can be unwrapped and deserialized using {@link #unwrap}.
     */
    byte[] wrap(KeyMaterial keyMaterial, PublicKey key);

    /**
     * Deserializes and unwraps a {@link KeyMaterial} from the provided {@code byte[]}. The input {@code byte[]} is only
     * guaranteed to be valid if produced by the corresponding {@link #wrap} method.
     */
    KeyMaterial unwrap(byte[] wrappedKeyMaterial, PrivateKey key);

    /**
     * Returns the unique version of the serializer.
     */
    int getVersion();

}
