/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

public final class DefaultAsyncKeyStorageStrategy implements AsyncKeyStorageStrategy {

    private final KeyStorageStrategy keys;
    private final ExecutorService executor;

    public DefaultAsyncKeyStorageStrategy(KeyStorageStrategy keys, ExecutorService executor) {
        this.keys = keys;
        this.executor = executor;
    }

    @Override
    public CompletableFuture<Void> put(String fileKey, KeyMaterial keyMaterial) {
        return CompletableFuture.supplyAsync(() -> {
            keys.put(fileKey, keyMaterial);
            return null;
        }, executor);
    }

    @Override
    public CompletableFuture<KeyMaterial> get(String fileKey) {
        return CompletableFuture.supplyAsync(() -> keys.get(fileKey), executor);
    }

    @Override
    public CompletableFuture<Void> remove(String fileKey) {
        return CompletableFuture.supplyAsync(() -> {
            keys.remove(fileKey);
            return null;
        }, executor);
    }

}
