package com.palantir.crypto2.cipher;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class CipherCorruptionChecker {
    private static final int LOOPS = 1000;

    private CipherCorruptionChecker() {}

    public static boolean isCorruptionPresent() {
        try {
            SecureRandom random = new SecureRandom();

            byte[] keyBytes = new byte[32];
            random.nextBytes(keyBytes);
            Key key = new SecretKeySpec(keyBytes, "AES");

            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);

            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding", "SunJCE");
            Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding", "SunJCE");

            for (int j = 0; j < 10000; j++) {
                byte[][] unencryptedData = new byte[LOOPS][];
                byte[][] encryptedData = new byte[LOOPS][];

                encrypt.init(Cipher.ENCRYPT_MODE, key, iv);
                for (int i = 0; i < LOOPS; i++) {
                    int size = (i % 15) + 1;
                    byte[] unencrypted = new byte[size];
                    random.nextBytes(unencrypted);
                    unencryptedData[i] = unencrypted;

                    byte[] encrypted = encrypt.update(unencrypted);
                    encryptedData[i] = encrypted;
                }

                decrypt.init(Cipher.DECRYPT_MODE, key, iv);
                for (int i = 0; i < LOOPS; i++) {
                    byte[] decrypted = decrypt.update(encryptedData[i]);
                    byte[] original = unencryptedData[i];

                    if (!Arrays.equals(original, decrypted)) {
                        return true;
                    }
                }
            }
            return false;
        } catch (NoSuchProviderException _e) {
            return false;
        } catch (InvalidAlgorithmParameterException
                | NoSuchPaddingException
                | NoSuchAlgorithmException
                | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}
