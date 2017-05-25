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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import org.junit.Before;
import org.junit.Test;

public final class DefaultAsyncKeyStorageStrategyTest {

    private static final ListeningExecutorService executor = MoreExecutors.newDirectExecutorService();
    private static final String KEY = "file";

    private KeyMaterial keyMaterial;
    private KeyStorageStrategy delegate;
    private DefaultAsyncKeyStorageStrategy keys;

    @Before
    public void before() {
        keyMaterial = mock(KeyMaterial.class);
        delegate = mock(KeyStorageStrategy.class);

        keys = new DefaultAsyncKeyStorageStrategy(delegate, executor);
    }

    @Test
    public void testPut() {
        keys.put(KEY, keyMaterial).join();

        verify(delegate).put(KEY, keyMaterial);
    }

    @Test
    public void testGet() {
        when(delegate.get(KEY)).thenReturn(keyMaterial);

        assertThat(keys.get(KEY).join(), is(keyMaterial));
    }

    @Test
    public void testRemove() {
        keys.remove(KEY).join();

        verify(delegate).remove(KEY);
    }

}
