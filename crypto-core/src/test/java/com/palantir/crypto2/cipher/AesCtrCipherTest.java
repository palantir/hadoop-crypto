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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import com.google.common.collect.Maps;
import com.palantir.crypto2.keys.KeyMaterial;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.junit.Test;

public final class AesCtrCipherTest extends AbstractSeekableCipherTest {

    // The following values are test samples from http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    private static final String KEY = "2b7e151628aed2a6abf7158809cf4f3c";
    private static final String IV = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    private static final Map<String, String> nistSamplePlainToCipherText;

    static {
        nistSamplePlainToCipherText = Maps.newLinkedHashMap();
        nistSamplePlainToCipherText.put("6bc1bee22e409f96e93d7e117393172a", "874d6191b620e3261bef6864990db6ce");
        nistSamplePlainToCipherText.put("ae2d8a571e03ac9c9eb76fac45af8e51", "9806f66b7970fdff8617187bb9fffdff");
        nistSamplePlainToCipherText.put("30c81c46a35ce411e5fbc1191a0a52ef", "5ae4df3edbd5d35e5b4f09020db03eab");
        nistSamplePlainToCipherText.put("f69f2445df4f9b17ad2b417be66c3710", "1e031dda2fbe03d1792170a0f3009cee");
    }

    private void initCipherUsingSeekableCipher(int mode, CryptoCipher cipher, SeekableCipher seekableCipher)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(mode, seekableCipher.getKeyMaterial().getSecretKey(), seekableCipher.getCurrIv());
    }

    @Override
    KeyMaterial generateKeyMaterial() {
        return AesCtrCipher.generateKeyMaterial();
    }

    @Override
    SeekableCipher getCipher(KeyMaterial initKeyMaterial) {
        return new AesCtrCipher(initKeyMaterial);
    }

    @Override
    String getAlgorithm() {
        return AesCtrCipher.ALGORITHM;
    }

    @Test
    public void testNistEncrypt() throws GeneralSecurityException {
        int idx = 0;
        for (Map.Entry<String, String> entry : nistSamplePlainToCipherText.entrySet()) {
            testNistExample(Cipher.ENCRYPT_MODE, idx, entry.getKey(), entry.getValue());
            idx++;
        }
    }

    @Test
    public void testNistDecrypt() throws GeneralSecurityException {
        int idx = 0;
        for (Map.Entry<String, String> entry : nistSamplePlainToCipherText.entrySet()) {
            testNistExample(Cipher.DECRYPT_MODE, idx, entry.getValue(), entry.getKey());
            idx++;
        }
    }

    public void testNistExample(int opmode, int blockNumber, String input, String output) throws
            GeneralSecurityException {
        byte[] key = DatatypeConverter.parseHexBinary(KEY);
        byte[] iv = DatatypeConverter.parseHexBinary(IV);
        byte[] inputBytes = DatatypeConverter.parseHexBinary(input);
        byte[] outputBytes = DatatypeConverter.parseHexBinary(output);

        KeyMaterial keyMaterial = KeyMaterial.of(new SecretKeySpec(key, AesCtrCipher.KEY_ALGORITHM), iv);
        SeekableCipher seekableCipher = getCipher(keyMaterial);
        seekableCipher.updateIvForNewPosition(blockNumber * (long) AesCtrCipher.BLOCK_SIZE);
        CryptoCipher cipher = CryptoCipherFactory.getCryptoCipher(getAlgorithm());
        initCipherUsingSeekableCipher(opmode, cipher, seekableCipher);

        byte[] finalBytes = new byte[outputBytes.length];
        cipher.update(inputBytes, 0, inputBytes.length, finalBytes, 0);
        assertThat(outputBytes, is(finalBytes));
    }

    @Test
    public void testEncryptDecrypt_ivIncrementedAsUnsignedInt() throws GeneralSecurityException {

        KeyMaterial keyMaterial = generateKeyMaterial();
        byte[] iv = keyMaterial.getIv();
        Arrays.fill(iv, (byte) 0xFF);
        KeyMaterial maxIvKeyMaterial = KeyMaterial.of(keyMaterial.getSecretKey(), iv);

        SeekableCipher seekableCipher = getCipher(maxIvKeyMaterial);
        // Encrypt without seeking so iv is not modified in seek method
        CryptoCipher encryptCipher = CryptoCipherFactory.getCryptoCipher(getAlgorithm());
        initCipherUsingSeekableCipher(Cipher.ENCRYPT_MODE, encryptCipher, seekableCipher);

        // Seek and decrypt so iv is modified by seek method
        seekableCipher.updateIvForNewPosition(0);
        CryptoCipher decryptCipher = CryptoCipherFactory.getCryptoCipher(getAlgorithm());
        initCipherUsingSeekableCipher(Cipher.DECRYPT_MODE, decryptCipher, seekableCipher);

        testEncryptDecrypt(encryptCipher, decryptCipher);
    }


    @Test
    public void testIvOverflow() {
        KeyMaterial baseKeyMaterial = generateKeyMaterial();
        byte[] iv = new byte[baseKeyMaterial.getIv().length];

        // Set iv to maximum possible value
        Arrays.fill(iv, (byte) 0xFF);
        KeyMaterial keyMaterial = KeyMaterial.of(baseKeyMaterial.getSecretKey(), iv);

        SeekableCipher cipher = getCipher(keyMaterial);
        cipher.updateIvForNewPosition(100);
    }

    @Test
    public void testIvUnderflow() {
        KeyMaterial baseKeyMaterial = generateKeyMaterial();
        byte[] iv = new byte[baseKeyMaterial.getIv().length];

        // Set iv to minimum possible value
        Arrays.fill(iv, (byte) 0x00);
        KeyMaterial keyMaterial = KeyMaterial.of(baseKeyMaterial.getSecretKey(), iv);

        SeekableCipher cipher = getCipher(keyMaterial);
        cipher.updateIvForNewPosition(100);
    }

}
