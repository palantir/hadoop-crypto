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

package com.palantir.crypto2.keys;

import com.google.common.base.Preconditions;
import com.google.common.base.Suppliers;
import com.google.common.collect.Collections2;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wrapper that allows ordered usage of multiple {@link KeyStorageStrategy}s. {@link #put} dispatches to every storage
 * strategy and succeeds iff all delegate puts succeed. {@link #get} attempts a get call on each storage strategy in
 * order, returning after the first successful call.
 */
public final class ChainedKeyStorageStrategy implements KeyStorageStrategy {

    private static final Logger logger = LoggerFactory.getLogger(ChainedKeyStorageStrategy.class);

    private final List<KeyStorageStrategy> strategies;

    public ChainedKeyStorageStrategy(List<KeyStorageStrategy> strategies) {
        Preconditions.checkArgument(strategies.size() > 0, "Must specify at least one storage strategy");
        this.strategies = strategies;
    }

    public ChainedKeyStorageStrategy(KeyStorageStrategy... strategies) {
        this(Arrays.asList(strategies));
    }

    @Override
    public void put(String fileKey, KeyMaterial keyMaterial) {
        for (KeyStorageStrategy strategy : strategies) {
            strategy.put(fileKey, keyMaterial);
        }
    }

    @Override
    public KeyMaterial get(String fileKey) {
        for (KeyStorageStrategy strategy : strategies) {
            try {
                return strategy.get(fileKey);
            } catch (Exception e) {
                logger.info("Failed to get key material using {}", strategy.getClass().getCanonicalName(), e);
            }
        }
        throw new InternalError(String.format(
                "Unable to get key material using any of the provided strategies: %s",
                Collections2.transform(strategies, s -> s.getClass().getCanonicalName())));
    }

    @Override
    public CompletableFuture<KeyMaterial> getAsync(String fileKey) {
        List<Supplier<CompletableFuture<KeyMaterial>>> futures = strategies.stream()
                .skip(1)
                .map(strategy -> (Supplier<CompletableFuture<KeyMaterial>>)
                        Suppliers.memoize(() -> strategy.getAsync("fileKey"))::get)
                .collect(Collectors.toList());

        CompletableFuture<KeyMaterial> accumulated = strategies.get(0).getAsync(fileKey);
        for (Supplier<CompletableFuture<KeyMaterial>> remainingStrategies : futures) {
            accumulated = accumulated
                    .handle((result, error) -> {
                        if (error != null) {
                            logger.info("Failed to get key material", error);
                        }
                        return result;
                    })
                    .thenCompose(result -> {
                        if (result != null) {
                            return CompletableFuture.completedFuture(result);
                        } else {
                            return remainingStrategies.get();
                        }
                    });
        }
        return accumulated;
    }

    @Override
    public void remove(String fileKey) {
        for (KeyStorageStrategy strategy : strategies) {
            strategy.remove(fileKey);
        }
    }

}
