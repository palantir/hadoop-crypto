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

package com.palantir.hadoop.serializer;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public final class KeySerializers {

    private static final Map<Integer, KeySerializer> SERIALIZERS = ImmutableMap.of(
            KeySerializerV1.VERSION, new KeySerializerV1(),
            KeySerializerV2.VERSION, new KeySerializerV2());

    private KeySerializers() {}

    public static Cipher getCipher(int cipherMode, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(key.getAlgorithm());
            cipher.init(cipherMode, key);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw Throwables.propagate(e);
        }
    }

    public static Map<Integer, KeySerializer> getSerializers() {
        return SERIALIZERS;
    }

}
