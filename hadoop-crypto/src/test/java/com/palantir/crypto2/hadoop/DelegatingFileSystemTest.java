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

package com.palantir.crypto2.hadoop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.io.Files;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.BlockLocation;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FSInputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public final class DelegatingFileSystemTest {

    private static final Path remotePath = new Path("/test");
    private static final byte[] bytes = "data".getBytes(StandardCharsets.UTF_8);

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Mock
    private FileSystem delegate;

    private DelegatingFileSystem delegatingFs;

    @Before
    public void before() throws IOException {
        when(delegate.getConf()).thenReturn(new Configuration());
        when(delegate.getUri()).thenReturn(URI.create("foo://bar"));
        when(delegate.getFileStatus(remotePath)).thenReturn(new FileStatus(0, false, 0, 0, 0, remotePath));
        delegatingFs = new DelegatingFileSystem(delegate) {};
    }

    @Test
    public void testCopyFromLocal() throws IOException {
        testCopyFromLocal(src -> delegatingFs.copyFromLocalFile(src, remotePath));
        testCopyFromLocal(src -> delegatingFs.copyFromLocalFile(false, src, remotePath));
        testCopyFromLocal(src -> delegatingFs.copyFromLocalFile(false, true, src, remotePath));
        testCopyFromLocal(src -> delegatingFs.copyFromLocalFile(false, true, new Path[] {src}, remotePath));
    }

    private interface ThrowingConsumer<T> {
        void accept(T it) throws IOException;
    }

    private void testCopyFromLocal(ThrowingConsumer<Path> copyFromLocal) throws IOException {
        File localFile = folder.newFile();
        Path src = new Path(localFile.getAbsolutePath());
        Files.write(bytes, localFile);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        when(delegate.create(remotePath, FsPermission.valueOf("-rw-r--r--"), true, 4096, (short) 0, 0, null))
                .thenReturn(new FSDataOutputStream(output, null));

        copyFromLocal.accept(src);
        assertThat(output.toByteArray()).isEqualTo(bytes);
    }

    @Test
    public void testCopyToLocal() throws IOException {
        testCopyToLocal(dst -> delegatingFs.copyToLocalFile(remotePath, dst));
        testCopyToLocal(dst -> delegatingFs.copyToLocalFile(false, remotePath, dst));
        testCopyToLocal(dst -> delegatingFs.copyToLocalFile(false, remotePath, dst, false));
    }

    private void testCopyToLocal(ThrowingConsumer<Path> copyToLocal) throws IOException {
        File localFile = folder.newFile();
        Path dst = new Path(localFile.getAbsolutePath());

        when(delegate.open(remotePath, 4096)).thenReturn(new FSDataInputStream(new ByteArrayFsInputStream(bytes)));

        copyToLocal.accept(dst);
        assertThat(Files.toByteArray(localFile)).isEqualTo(bytes);
    }

    @Test
    public void testGetFileBlockLocations() throws IOException {
        Path path = new Path("test-path");
        BlockLocation location =
                new BlockLocation(new String[] {"some-host:50010"}, new String[] {"some-host"}, 0L, 0L);
        when(delegate.getFileBlockLocations(eq(path), anyLong(), anyLong())).thenReturn(new BlockLocation[] {location});

        assertThat(delegatingFs.getFileBlockLocations(path, 0L, 0L)).containsExactly(location);
        verify(delegate).getFileBlockLocations(path, 0L, 0L);
    }

    private static final class ByteArrayFsInputStream extends FSInputStream {

        private final ByteArrayInputStream in;

        ByteArrayFsInputStream(byte[] bytes) {
            in = new ByteArrayInputStream(bytes);
        }

        @Override
        public void seek(long _pos) throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public long getPos() throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean seekToNewSource(long _targetPos) throws IOException {
            return false;
        }

        @Override
        public int read() throws IOException {
            return in.read();
        }
    }
}
