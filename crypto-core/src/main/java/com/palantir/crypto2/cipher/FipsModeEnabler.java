/*
 * (c) Copyright 2019 Palantir Technologies Inc. All rights reserved.
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

import com.sun.jna.Native;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * If we are using a FIPS mode OpenSSL, enable FIPS mode automatically. OpenSSL is generally not FIPS certified, and
 * if it reports itself to be FIPS compliant that means that crypto will basically not work unless FIPS mode has been
 * enabled. So, it's always safe to call this.
 */
@SuppressWarnings({"checkstyle:MethodName", "checkstyle:ParameterName", "checkstyle:AbbreviationAsWordInName"})
public final class FipsModeEnabler {
    private static final int ENABLE_FIPS = 1;
    private static final int FIPS_WAS_NOT_ENABLED = 0;
    private static final Logger log = LoggerFactory.getLogger(FipsModeEnabler.class);

    private static final boolean FIPS_MODE_ENABLED;

    static {
        boolean enabled = false;
        try {
            Native.register("crypto");
            int fipsMode = FIPS_mode_set(ENABLE_FIPS);
            if (fipsMode == FIPS_WAS_NOT_ENABLED) {
                log.debug("FIPS mode not enabled, we're likely not using FIPS OpenSSL");
            } else {
                enabled = FIPS_mode() != 0;
                log.info("FIPS mode enabled");
            }
        } catch (Exception | UnsatisfiedLinkError e) {
            log.debug("Unable to enable FIPS mode, and got an exception, probably OpenSSL couldn't be loaded", e);
        }
        FIPS_MODE_ENABLED = enabled;
    }

    private FipsModeEnabler() {}

    public static boolean maybeEnableFipsMode() {
        return FIPS_MODE_ENABLED;
    }

    private static native int FIPS_mode_set(int r);
    private static native int FIPS_mode();
}
