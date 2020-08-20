/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
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
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
        this.strategies = ImmutableList.copyOf(strategies);
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
        List<Exception> suppressedExceptions = new ArrayList<>();
        for (KeyStorageStrategy strategy : strategies) {
            try {
                return strategy.get(fileKey);
            } catch (Exception e) {
                suppressedExceptions.add(e);
                logger.info(
                        "Failed to get key material using {}",
                        strategy.getClass().getCanonicalName(),
                        e);
            }
        }
        RuntimeException toThrow = new RuntimeException(String.format(
                "Unable to get key material for '%s' using any of the provided strategies: %s",
                fileKey, Collections2.transform(strategies, s -> s.getClass().getCanonicalName())));
        suppressedExceptions.forEach(toThrow::addSuppressed);
        throw toThrow;
    }

    @Override
    public void remove(String fileKey) {
        for (KeyStorageStrategy strategy : strategies) {
            strategy.remove(fileKey);
        }
    }
}
