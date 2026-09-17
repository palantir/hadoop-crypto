/*
 * (c) Copyright 2026 Palantir Technologies Inc. All rights reserved.
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import com.google.common.collect.ImmutableSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Tests the default {@link KeyStorageStrategy#remove(Set)} implementation, which every strategy that does not provide
 * a batched removal of its own inherits.
 */
public final class KeyStorageStrategyTest {

    private static final Set<String> FILE_KEYS = ImmutableSet.of("first", "second", "third");

    @Test
    public void testRemovesEveryFileKey() {
        RecordingKeyStorageStrategy strategy = new RecordingKeyStorageStrategy(ImmutableSet.of());

        strategy.remove(FILE_KEYS);

        assertThat(strategy.removed).containsExactlyInAnyOrderElementsOf(FILE_KEYS);
    }

    @Test
    public void testAttemptsEveryFileKeyWhenOneFails() {
        RecordingKeyStorageStrategy strategy = new RecordingKeyStorageStrategy(ImmutableSet.of("second"));

        assertThatExceptionOfType(RuntimeException.class)
                .isThrownBy(() -> strategy.remove(FILE_KEYS))
                .withMessageContaining("Failed to remove key material for one or more files")
                .satisfies(thrown -> assertThat(thrown.getSuppressed()).hasSize(1));

        // The failure of "second" must not prevent "third" from being attempted, otherwise an interrupted bulk
        // delete would leave key material behind for every file after the first failure.
        assertThat(strategy.removed).containsExactlyInAnyOrder("first", "third");
    }

    @Test
    public void testCollectsEverySuppressedFailure() {
        RecordingKeyStorageStrategy strategy = new RecordingKeyStorageStrategy(FILE_KEYS);

        assertThatExceptionOfType(RuntimeException.class)
                .isThrownBy(() -> strategy.remove(FILE_KEYS))
                .satisfies(thrown -> assertThat(thrown.getSuppressed()).hasSize(FILE_KEYS.size()));

        assertThat(strategy.removed).isEmpty();
    }

    @Test
    public void testEmptyBatchSucceeds() {
        RecordingKeyStorageStrategy strategy = new RecordingKeyStorageStrategy(FILE_KEYS);

        strategy.remove(ImmutableSet.of());

        assertThat(strategy.removed).isEmpty();
    }

    private static final class RecordingKeyStorageStrategy implements KeyStorageStrategy {

        private final List<String> removed = new ArrayList<>();
        private final Set<String> failingFileKeys;

        RecordingKeyStorageStrategy(Set<String> failingFileKeys) {
            this.failingFileKeys = failingFileKeys;
        }

        @Override
        public void put(String _fileKey, KeyMaterial _keyMaterial) {
            throw new UnsupportedOperationException();
        }

        @Override
        public KeyMaterial get(String _fileKey) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void remove(String fileKey) {
            if (failingFileKeys.contains(fileKey)) {
                throw new IllegalStateException("cannot remove " + fileKey);
            }
            removed.add(fileKey);
        }
    }
}
