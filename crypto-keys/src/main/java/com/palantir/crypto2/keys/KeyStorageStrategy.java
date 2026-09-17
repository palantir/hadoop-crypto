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

import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.exceptions.SafeRuntimeException;
import java.util.Set;

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

    /**
     * Removes the {@link KeyMaterial} for each of the given {@code fileKeys}. Used to clean up after bulk operations
     * such as {@code EncryptedFileSystem#delete(Path, boolean)} with {@code recursive} set to true.
     * <p>
     * Removal is attempted for every file key even if some of them fail. If any removal failed then a
     * {@link RuntimeException} is thrown once all of them have been attempted, with the individual failures attached
     * as suppressed exceptions.
     * <p>
     * Implementations backed by a remote store are encouraged to override this with a batched implementation, as the
     * default issues one {@link #remove(String)} per file key.
     */
    default void remove(Set<String> fileKeys) {
        RuntimeException failure = null;
        for (String fileKey : fileKeys) {
            try {
                remove(fileKey);
            } catch (RuntimeException e) {
                if (failure == null) {
                    failure = new SafeRuntimeException(
                            "Failed to remove key material for one or more files",
                            SafeArg.of("numFileKeys", fileKeys.size()));
                }
                failure.addSuppressed(e);
            }
        }
        if (failure != null) {
            throw failure;
        }
    }
}
