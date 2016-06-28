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

package com.palantir.hadoop;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.base.Throwables;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.immutables.value.Value;

/**
 * A Jackson-serializable wrapper for {@link PublicKey}s.
 */
@Value.Immutable
@Value.Style(visibility = Value.Style.ImplementationVisibility.PACKAGE, jdkOnly = true)
@JsonSerialize(as = ImmutableSerializablePublicKey.class)
@JsonDeserialize(as = ImmutableSerializablePublicKey.class)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class SerializablePublicKey {

    @Value.Parameter
    public abstract String getAlgorithm();

    @Value.Parameter
    public abstract byte[] getEncodedKey();

    public static SerializablePublicKey of(String algorithm, byte[] encodedKey) {
        return ImmutableSerializablePublicKey.of(algorithm, encodedKey);
    }

    public static SerializablePublicKey of(PublicKey key) {
        return SerializablePublicKey.of(key.getAlgorithm(), key.getEncoded());
    }

    public final PublicKey deserialize() {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(getEncodedKey());
            KeyFactory keyFactory = KeyFactory.getInstance(getAlgorithm());
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw Throwables.propagate(e);
        }
    }

}
