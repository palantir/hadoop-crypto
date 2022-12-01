package com.palantir.crypto2.cipher;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.IntStream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class CipherCorruptionChecker {
    private static final int LOOPS = 100000000;
    private static final int LEN = 15;

    private CipherCorruptionChecker() {}

    public static boolean isCorruptionPresent() {
        for (int i = 0; i < 100_000; i++) {
            isCorruptionPresent(1);
        }
        return IntStream.range(0, 64)
                .parallel()
                .mapToObj(_index -> isCorruptionPresent(LOOPS))
                .reduce(false, Boolean::logicalOr);
    }

    private static boolean isCorruptionPresent(int loops) {
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
            encrypt.init(Cipher.ENCRYPT_MODE, key, iv);
            decrypt.init(Cipher.DECRYPT_MODE, key, iv);

            byte[] original = new byte[LEN];
            byte[] encrypted = new byte[LEN];
            byte[] decrypted = new byte[LEN];

            for (int i = 0; i < loops; i++) {
                random.nextBytes(original);
                encrypt.doFinal(original, 0, LEN, encrypted);

                decrypt.update(encrypted, 0, 1, decrypted, 0);
                decrypt.update(encrypted, 1, 1, decrypted, 1);
                decrypt.doFinal(encrypted, 2, LEN - 2, decrypted, 2);
                if (!Arrays.equals(original, decrypted)) {
                    return true;
                }
            }
            return false;
        } catch (NoSuchProviderException _e) {
            return false;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
