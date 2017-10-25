/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.hadoop;

import com.google.common.collect.Maps;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.KeyStorageStrategy;
import java.util.Map;

public final class InMemoryKeyStorageStrategy implements KeyStorageStrategy {

    private Map<String, KeyMaterial> store = Maps.newHashMap();

    public InMemoryKeyStorageStrategy() {}

    @Override
    public void put(String fileKey, KeyMaterial keyMaterial) {
        store.put(fileKey, keyMaterial);
    }

    @Override
    public KeyMaterial get(String fileKey) {
        return store.get(fileKey);
    }

    @Override
    public void remove(String fileKey) {
        store.remove(fileKey);
    }

}
