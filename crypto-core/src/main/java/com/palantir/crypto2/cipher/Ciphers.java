/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.cipher;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import java.security.Security;
import java.util.List;

final class Ciphers {

    private static final ImmutableList<String> ACCEPTABLE_PROVIDERS = ImmutableList.of("SunJCE", "IBMJCE");

    private Ciphers() {}

    /**
     * Returns the first acceptable provider that is installed on the system.
     */
    static String getProvider() {
        return getProvider(ACCEPTABLE_PROVIDERS);
    }

    /**
     * Returns the first provider that is installed on the system.
     */
    @VisibleForTesting
    static String getProvider(List<String> providers) {
        for (String provider : providers) {
            if (Security.getProvider(provider) != null) {
                return provider;
            }
        }
        throw new IllegalStateException(
                String.format("None of the acceptable JCE providers are available: %s", providers));
    }

}
