/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys;

import javax.crypto.SecretKey;
import org.immutables.value.Value;

// This class is not Jackson serializable due to SecretKey
@Value.Immutable
@Value.Style(visibility = Value.Style.ImplementationVisibility.PACKAGE, jdkOnly = true)
public abstract class KeyMaterial {

    @Value.Parameter
    public abstract SecretKey getSecretKey();

    /**
     * Initialization vector.
     */
    @Value.Parameter
    public abstract byte[] getIv();

    public static KeyMaterial of(SecretKey secretKey, byte[] iv) {
        return ImmutableKeyMaterial.of(secretKey, iv);
    }

}
