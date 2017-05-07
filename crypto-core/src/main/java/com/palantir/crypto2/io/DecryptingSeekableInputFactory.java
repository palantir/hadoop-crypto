/*
 * Copyright 2017 Palantir Technologies, Inc. All rights reserved.
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

package com.palantir.crypto2.io;

import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.seekio.SeekableInput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class DecryptingSeekableInputFactory {

    private static final Logger log = LoggerFactory.getLogger(DecryptingSeekableInputFactory.class);

    private DecryptingSeekableInputFactory() {}

    /**
     * Returns a {@link SeekableInput} that decrypts the given SeekableInput using the given {@link KeyMaterial} and
     * cipher {@code algorithm}. When OpenSSL is available an implementation that uses AES-NI will be returned.
     */
    public static SeekableInput decrypt(SeekableInput encryptedInput, KeyMaterial keyMaterial, String algorithm) {
        if (algorithm.equals(ApacheCtrDecryptingSeekableInput.ALGORITHM)) {
            try {
                return ApacheCtrDecryptingSeekableInput.create(encryptedInput, keyMaterial);
            } catch (Throwable e) {
                log.warn("Unable to initialize cipher with OpenSSL falling back to JCE implementation");
            }
        }

        return new DecryptingSeekableInput(encryptedInput, SeekableCipherFactory.getCipher(algorithm, keyMaterial));
    }

}
