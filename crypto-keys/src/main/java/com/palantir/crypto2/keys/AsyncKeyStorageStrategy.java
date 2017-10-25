/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys;

import java.util.concurrent.CompletableFuture;

/**
 * The asynchronous equivalent of {@link KeyStorageStrategy}.
 */
public interface AsyncKeyStorageStrategy {

    /**
     * Async equivalent of {@link KeyStorageStrategy#put(String, KeyMaterial)}.
     */
    CompletableFuture<Void> put(String fileKey, KeyMaterial keyMaterial);

    /**
     * Async equivalent of {@link KeyStorageStrategy#get(String)}.
     */
    CompletableFuture<KeyMaterial> get(String fileKey);

    /**
     * Async equivalent of {@link KeyStorageStrategy#remove(String)}.
     */
    CompletableFuture<Void> remove(String fileKey);

}
