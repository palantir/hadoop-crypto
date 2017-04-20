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
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;

/**
 * An extention of the 'AES/CTR/NoPadding' {@link Cipher} implementation which allows seeking of the cipher in constant
 * time.
 */
public final class AesCtrCipher implements SeekableCipher {

    public static final String ALGORITHM = "AES/CTR/NoPadding";
    static final String KEY_ALGORITHM = "AES";
    static final int KEY_SIZE = 256;
    static final int BLOCK_SIZE = 16;
    static final int IV_SIZE = 16;
    private static byte[] out = new byte[BLOCK_SIZE];

    private final KeyMaterial keyMaterial;
    private final SecretKey key;
    private final byte[] initIv;
    private IvParameterSpec currIvParameterSpec;
    private int currentOpmode;

    public AesCtrCipher(KeyMaterial keyMaterial) {
        this.key = keyMaterial.getSecretKey();
        this.initIv = keyMaterial.getIv();
        this.currIvParameterSpec = new IvParameterSpec(initIv);
        this.keyMaterial = keyMaterial;
    }

    @Override
    public CryptoCipher initCipher(int opmode) {
        this.currentOpmode = opmode;
        try {
            CryptoCipher cipher = CryptoCipherFactory.getCryptoCipher(ALGORITHM);
            cipher.init(opmode, key, new IvParameterSpec(initIv));
            return cipher;
        } catch (GeneralSecurityException e) {
            throw Throwables.propagate(e);
        }
    }

    @Override
    public CryptoCipher seek(long pos) {
        Preconditions.checkState(currentOpmode == Cipher.DECRYPT_MODE || currentOpmode == Cipher.ENCRYPT_MODE,
                "Cipher not initialized");
        Preconditions.checkArgument(pos >= 0, "Cannot seek to negative position: %s", pos);

        // Compute the block that the byte 'pos' is located in
        BigInteger block = BigInteger.valueOf(pos / BLOCK_SIZE);

        // Compute the iv for the block to start decrypting. initIv needs to be treated as an unsigned int
        BigInteger ivBuffer = new BigInteger(1, initIv).add(block);
        byte[] ivBytes = ivBuffer.toByteArray();

        // Ensure the iv is exactly BLOCK_SIZE bytes in length
        if (ivBytes.length >= IV_SIZE) {
            currIvParameterSpec = new IvParameterSpec(ivBytes, ivBytes.length - IV_SIZE, IV_SIZE);
        } else {
            final byte[] tmpIv = new byte[IV_SIZE];
            System.arraycopy(ivBytes, 0, tmpIv, IV_SIZE - ivBytes.length, ivBytes.length);
            currIvParameterSpec = new IvParameterSpec(tmpIv);
        }

        // Init the cipher with the new iv
        try {
            CryptoCipher cipher = CryptoCipherFactory.getCryptoCipher(ALGORITHM);
            cipher.init(currentOpmode, key, currIvParameterSpec);

            // Skip to the byte offset in the block where 'pos' is located
            int bytesToSkip = (int) (pos % BLOCK_SIZE);
            byte[] skip = new byte[bytesToSkip];
            cipher.update(skip, 0 /* inputOffset */, bytesToSkip, out, 0 /* outputOffset */);
            return cipher;
        } catch (GeneralSecurityException e) {
            throw Throwables.propagate(e);
        }
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
