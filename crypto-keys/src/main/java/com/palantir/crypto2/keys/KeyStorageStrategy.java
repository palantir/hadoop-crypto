/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys;

/**
 * The strategy used to store the per file {@link KeyMaterial} used for encryption operations.
 */
public interface KeyStorageStrategy {

    /**
     * Stores the {@link KeyMaterial} for a file with the given {@code fileKey}.
     */
    void put(String fileKey, KeyMaterial keyMaterial);

    /**
     * Retrieves the {@link KeyMaterial} for a file with the given {@code fileKey}.
     */
    KeyMaterial get(String fileKey);

    /**
     * Removes the {@link KeyMaterial} for a file with the given {@code fileKey}.
     */
    void remove(String fileKey);

}
