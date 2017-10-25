/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import org.junit.Assert;
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
    public void testPut_exception() {
        doThrow(IllegalStateException.class).when(delegate).put(KEY, keyMaterial);

        keys.put(KEY, keyMaterial)
                .thenRun(Assert::fail)
                .exceptionally(this::verifyIllegalStateThrown)
                .join();
    }

    @Test
    public void testGet() {
        when(delegate.get(KEY)).thenReturn(keyMaterial);

        assertThat(keys.get(KEY).join()).isEqualTo(keyMaterial);
    }

    @Test
    public void testGet_exception() {
        doThrow(IllegalStateException.class).when(delegate).get(KEY);

        keys.get(KEY)
                .thenRun(Assert::fail)
                .exceptionally(this::verifyIllegalStateThrown)
                .join();
    }

    @Test
    public void testRemove() {
        keys.remove(KEY).join();

        verify(delegate).remove(KEY);
    }

    @Test
    public void testRemove_exception() {
        doThrow(IllegalStateException.class).when(delegate).remove(KEY);

        keys.remove(KEY)
                .thenRun(Assert::fail)
                .exceptionally(this::verifyIllegalStateThrown)
                .join();
    }

    private Void verifyIllegalStateThrown(Throwable throwable) {
        assertThat(throwable).hasCauseInstanceOf(IllegalStateException.class);
        return null;
    }

}
