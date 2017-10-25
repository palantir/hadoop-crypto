/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.io;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.io.ByteStreams;
import com.palantir.crypto2.cipher.AesCbcCipher;
import com.palantir.crypto2.cipher.AesCtrCipher;
import com.palantir.crypto2.cipher.ApacheCiphers;
import com.palantir.crypto2.cipher.SeekableCipher;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.InMemorySeekableDataInput;
import com.palantir.seekio.SeekableInput;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.Properties;
import java.util.Random;
import java.util.function.BiFunction;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import org.apache.commons.crypto.stream.CtrCryptoOutputStream;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public final class DecryptionTests {

    private static final String AES_CTR = AesCtrCipher.ALGORITHM;
    private static final String AES_CBC = AesCbcCipher.ALGORITHM;
    private static final int NUM_BYTES = 1024 * 1024;
    private static final Random random = new Random(0);
    private static byte[] data;

    private int blockSize;
    private SeekableInput cis;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @BeforeClass
    public static void beforeClass() throws IOException {
        data = new byte[NUM_BYTES];
        random.nextBytes(data);
    }

    @Parameterized.Parameters
    public static Collection<TestCase> ciphers() {
        return ImmutableList.of(
                new TestCase(AES_CTR, DecryptionTests::jceEncrypted, DecryptionTests::apacheDecrypted),
                new TestCase(AES_CTR, DecryptionTests::jceEncrypted, DecryptionTests::jceDecrypted),
                new TestCase(AES_CTR, DecryptionTests::apacheEncrypted, DecryptionTests::apacheDecrypted),
                new TestCase(AES_CTR, DecryptionTests::apacheEncrypted, DecryptionTests::jceDecrypted),
                new TestCase(AES_CBC, DecryptionTests::jceEncrypted, DecryptionTests::jceDecrypted));
    }

    public DecryptionTests(TestCase testCase) {
        try {
            SeekableCipher seekableCipher = SeekableCipherFactory.getCipher(testCase.alg);
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            OutputStream cos = testCase.encFactory.apply(seekableCipher, os);
            cos.write(data);
            cos.close();

            InMemorySeekableDataInput input = new InMemorySeekableDataInput(os.toByteArray());
            cis = testCase.decFactory.apply(seekableCipher, input);
            blockSize = seekableCipher.getBlockSize();
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
    }

    @Test
    public void testDecrypt() throws IOException {
        assertThat(cis.getPos()).isEqualTo(0);

        byte[] decrypted = new byte[NUM_BYTES];
        readFully(cis, decrypted);

        assertThat(cis.getPos()).isEqualTo(NUM_BYTES);
        assertThat(decrypted).isEqualTo(data);
    }

    @Test
    public void testSeek_firstBlock() throws IOException {
        testSeek(0);
    }

    @Test
    public void testSeek_firstBlockAndOffset() throws IOException {
        testSeek(1);
    }

    @Test
    public void testSeek_manyBlocks() throws IOException {
        int pos = blockSize * 10;
        testSeek(pos);
    }

    @Test
    public void testSeek_manyBlocksAndOffset() throws IOException {
        int pos = blockSize * 10 + 1;
        testSeek(pos);
    }

    @Test
    public void testSeek_onePastEndOfData() throws IOException {
        cis.seek(NUM_BYTES);
        assertThat(cis.read(new byte[1], 0, 1)).isEqualTo(-1);
    }

    @Test
    public void testSeek_manyBlocksAndNegativeOffset() throws IOException {
        int pos = blockSize * 10 - 1;
        testSeek(pos);
    }

    private void testSeek(int seekPos) throws IOException {
        cis.seek(seekPos);

        assertThat(cis.getPos()).isEqualTo(seekPos);

        byte[] decrypted = new byte[NUM_BYTES - seekPos];
        readFully(cis, decrypted);

        byte[] expected = Arrays.copyOfRange(data, seekPos, NUM_BYTES);

        assertThat(decrypted.length).isEqualTo(expected.length);
        assertThat(decrypted).isEqualTo(expected);
    }

    @Test
    public void testBulkRead() throws IOException {
        long startPos = cis.getPos();
        byte[] buffer = new byte[NUM_BYTES];
        int offset = 0;

        while (offset < buffer.length) {
            int read = cis.read(buffer, offset, buffer.length - offset);
            if (read == -1) {
                break;
            }
            offset += read;
        }

        assertThat(cis.getPos()).isEqualTo(startPos + buffer.length);
        assertThat(buffer).isEqualTo(data);
        assertThat(offset).isEqualTo(NUM_BYTES);
        cis.close();
    }

    private static void readFully(SeekableInput input, byte[] decrypted) throws IOException {
        ByteStreams.readFully(new DefaultSeekableInputStream(input), decrypted);
    }

    // Marker interface
    private interface EncryptedStreamFactory extends BiFunction<SeekableCipher, OutputStream, OutputStream> {}

    // Marker interface
    private interface DecryptedStreamFactory extends BiFunction<SeekableCipher, SeekableInput, SeekableInput> {}

    @SuppressWarnings("VisibilityModifier")
    private static final class TestCase {
        String alg;
        EncryptedStreamFactory encFactory;
        DecryptedStreamFactory decFactory;

        TestCase(String alg, EncryptedStreamFactory encFactory, DecryptedStreamFactory decFactory) {
            this.alg = alg;
            this.encFactory = encFactory;
            this.decFactory = decFactory;
        }
    }

    private static OutputStream apacheEncrypted(SeekableCipher cipher, OutputStream output) {
        if (cipher instanceof AesCtrCipher) {
            return uncheckedApacheEncrypted(cipher, output);
        } else {
            throw new IllegalArgumentException("Unsupported cipher type");
        }
    }

    private static OutputStream uncheckedApacheEncrypted(SeekableCipher cipher, OutputStream output) {
        try {
            Properties props = ApacheCiphers.forceOpenSsl(new Properties());
            KeyMaterial km = cipher.getKeyMaterial();
            return new CtrCryptoOutputStream(props, output, km.getSecretKey().getEncoded(), km.getIv());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static SeekableInput apacheDecrypted(SeekableCipher cipher, SeekableInput input) {
        if (cipher instanceof AesCtrCipher) {
            return uncheckedApacheDecrypted(cipher, input);
        } else {
            throw new IllegalArgumentException("Unsupported cipher type");
        }
    }

    private static SeekableInput uncheckedApacheDecrypted(SeekableCipher cipher, SeekableInput input) {
        try {
            return new ApacheCtrDecryptingSeekableInput(input, cipher.getKeyMaterial());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static OutputStream jceEncrypted(SeekableCipher cipher, OutputStream output) {
        return new CipherOutputStream(output, cipher.initCipher(Cipher.ENCRYPT_MODE));
    }

    private static SeekableInput jceDecrypted(SeekableCipher cipher, SeekableInput input) {
        return new DecryptingSeekableInput(input, cipher);
    }

}
