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

import com.google.common.base.Preconditions;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.serialization.KeyMaterials;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.crypto.cipher.CryptoCipher;

/**
 * An extention of the 'AES/CBC/PKCS5Padding' {@link CryptoCipher} implementation which allows seeking of the cipher in
 * constant time. This is the same Cipher used by the original implementation of the hadoop-s3e-adapter.
 */
public final class AesCbcCipher implements SeekableCipher {

    public static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;
    private static final int BLOCK_SIZE = 16;
    private static final int IV_SIZE = 16;

    private final KeyMaterial keyMaterial;
    private final SecretKey key;
    private final byte[] initIv;
    private IvParameterSpec currIvParameterSpec;

    public AesCbcCipher(KeyMaterial keyMaterial) {
        this.initIv = keyMaterial.getIv();
        this.currIvParameterSpec = new IvParameterSpec(initIv);
        this.key = keyMaterial.getSecretKey();
        this.keyMaterial = keyMaterial;
    }

    /**
     * Seeking the AES/CBC {@link CryptoCipher} requires initializing its IV with the previous block of encrypted data,
     * and therefore cannot be done by the cipher alone. Therefore we do not update currIvParameterSpec here.
     */
    @Override
    public void updateIvForNewPosition(long pos) {
        Preconditions.checkArgument(pos >= 0, "Cannot seek to negative position: %s", pos);
        Preconditions.checkArgument(pos % BLOCK_SIZE == 0,
                "Can only seek AES/CBC cipher to block offset positions every %s bytes", BLOCK_SIZE);
    }

    @Override
    public KeyMaterial getKeyMaterial() {
        return keyMaterial;
    }

    @Override
    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    public IvParameterSpec getCurrIv() {
        return currIvParameterSpec;
    }

    public static KeyMaterial generateKeyMaterial() {
        return KeyMaterials.generateKeyMaterial(KEY_ALGORITHM, KEY_SIZE, IV_SIZE);
    }

}
