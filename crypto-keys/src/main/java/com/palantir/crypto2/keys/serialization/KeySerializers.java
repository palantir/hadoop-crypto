/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys.serialization;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

final class KeySerializers {

    private static final Map<Integer, ? extends KeySerializer> SERIALIZERS = ImmutableMap.of(
            KeySerializerV1.VERSION, KeySerializerV1.INSTANCE,
            KeySerializerV2.VERSION, KeySerializerV2.INSTANCE);

    private KeySerializers() {}

    static Cipher getCipher(int cipherMode, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(key.getAlgorithm());
            cipher.init(cipherMode, key);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw Throwables.propagate(e);
        }
    }

    static Map<Integer, ? extends KeySerializer> getSerializers() {
        return SERIALIZERS;
    }

}
