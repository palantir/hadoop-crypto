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
import com.google.common.base.Throwables;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.serialization.KeyMaterials;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * An extention of the 'AES/CTR/NoPadding' {@link Cipher} implementation which allows seeking of the cipher in constant
 * time.
 */
public final class AesCtrCipher implements SeekableCipher {

    public static final String ALGORITHM = "AES/CTR/NoPadding";
    static final String PROVIDER = "SunJCE";
    static final String KEY_ALGORITHM = "AES";
    static final int KEY_SIZE = 256;

    private final KeyMaterial keyMaterial;
    private final SecretKey key;
    private final byte[] initIv;
    private int currentOpmode;

    public AesCtrCipher(KeyMaterial keyMaterial) {
        this.key = keyMaterial.getSecretKey();
        this.initIv = keyMaterial.getIv();
        this.keyMaterial = keyMaterial;
    }

    @Override
    public Cipher initCipher(int opmode) {
        this.currentOpmode = opmode;
        try {
            Cipher cipher = getInstance();
            cipher.init(opmode, key, new IvParameterSpec(initIv));
            return cipher;
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw Throwables.propagate(e);
        }
    }

    @Override
    public Cipher seek(long pos) {
        Preconditions.checkState(currentOpmode == Cipher.DECRYPT_MODE || currentOpmode == Cipher.ENCRYPT_MODE,
                "Cipher not initialized");
        Preconditions.checkArgument(pos >= 0, "Cannot seek to negative position: %s", pos);

        // Compute the block that the byte 'pos' is located in
        long block = pos / CounterMode.BLOCK_SIZE;
        IvParameterSpec newIv = CounterMode.computeIv(initIv, block);

        Cipher cipher = getInstance();

        // Init the cipher with the new iv
        try {
            cipher.init(currentOpmode, key, newIv);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw Throwables.propagate(e);
        }

        // Skip to the byte offset in the block where 'pos' is located
        int bytesToSkip = (int) (pos % CounterMode.BLOCK_SIZE);
        byte[] skip = new byte[bytesToSkip];
        cipher.update(skip, 0, bytesToSkip);

        return cipher;
    }

    @Override
    public KeyMaterial getKeyMaterial() {
        return keyMaterial;
    }

    @Override
    public int getBlockSize() {
        return CounterMode.BLOCK_SIZE;
    }

    public static KeyMaterial generateKeyMaterial() {
        return KeyMaterials.generateKeyMaterial(KEY_ALGORITHM, KEY_SIZE, CounterMode.IV_SIZE);
    }

    private Cipher getInstance() {
        try {
            return Cipher.getInstance(ALGORITHM, PROVIDER);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            throw Throwables.propagate(e);
        }
    }

}
