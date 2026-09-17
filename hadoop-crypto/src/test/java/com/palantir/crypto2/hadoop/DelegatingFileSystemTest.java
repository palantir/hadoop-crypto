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
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.io.ByteStreams;
import com.google.common.io.Files;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.BlockLocation;
import org.apache.hadoop.fs.CreateFlag;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FSInputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Options.ChecksumOpt;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.PathHandle;
import org.apache.hadoop.fs.RawLocalFileSystem;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.util.Progressable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public final class DelegatingFileSystemTest {

    private static final Path remotePath = new Path("/test");
    private static final byte[] bytes = "data".getBytes(StandardCharsets.UTF_8);

    @TempDir
    public File folder;

    @Mock
    private FileSystem delegate;

    private DelegatingFileSystem delegatingFs;

    private interface ThrowingConsumer<T> {
        void accept(T it) throws IOException;
    }

    @BeforeEach
    public void before() throws IOException {
        when(delegate.getConf()).thenReturn(new Configuration());
        when(delegate.getUri()).thenReturn(URI.create("foo://bar"));
        delegatingFs = new DelegatingFileSystem(delegate) {};
    }

    @Test
    public void testCopyFromLocal() throws IOException {
        when(delegate.getFileStatus(remotePath)).thenReturn(new FileStatus(0, false, 0, 0, 0, remotePath));
        testCopyFromLocal(src -> delegatingFs.copyFromLocalFile(src, remotePath));
        testCopyFromLocal(src -> delegatingFs.copyFromLocalFile(false, src, remotePath));
        testCopyFromLocal(src -> delegatingFs.copyFromLocalFile(false, true, src, remotePath));
        testCopyFromLocal(src -> delegatingFs.copyFromLocalFile(false, true, new Path[] {src}, remotePath));
    }

    private void testCopyFromLocal(ThrowingConsumer<Path> copyFromLocal) throws IOException {
        File localFile = new File(folder, "test.bin");
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
        when(delegate.getFileStatus(remotePath)).thenReturn(new FileStatus(0, false, 0, 0, 0, remotePath));
        testCopyToLocal(dst -> delegatingFs.copyToLocalFile(remotePath, dst));
        testCopyToLocal(dst -> delegatingFs.copyToLocalFile(false, remotePath, dst));
        testCopyToLocal(dst -> delegatingFs.copyToLocalFile(false, remotePath, dst, false));
    }

    private void testCopyToLocal(ThrowingConsumer<Path> copyToLocal) throws IOException {
        File localFile = new File(folder, "test.bin");
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

    @Test // https://github.com/palantir/hadoop-crypto/issues/105
    public void testCreateFileBuilderRoutesThroughCreate() throws IOException {
        RecordingFileSystem recordingFs = recordingFs();

        try (FSDataOutputStream os =
                recordingFs.createFile(localPath("created.bin")).build()) {
            os.write(bytes);
        }

        assertThat(recordingFs.calls).containsExactly("create");
    }

    @Test // https://github.com/palantir/hadoop-crypto/issues/105
    public void testCreateNonRecursiveRoutesThroughCreate() throws IOException {
        RecordingFileSystem recordingFs = recordingFs();

        try (FSDataOutputStream os = createNonRecursive(recordingFs, localPath("non-recursive.bin"))) {
            os.write(bytes);
        }

        assertThat(recordingFs.calls).containsExactly("create");
    }

    @Test // https://github.com/palantir/hadoop-crypto/issues/105
    public void testCreateNonRecursiveFailsWhenParentDoesNotExist() throws IOException {
        RecordingFileSystem recordingFs = recordingFs();

        assertThatExceptionOfType(FileNotFoundException.class)
                .isThrownBy(() -> createNonRecursive(recordingFs, localPath("missing-parent/child.bin")));
        assertThat(recordingFs.calls).isEmpty();
    }

    @Test // https://github.com/palantir/hadoop-crypto/issues/105
    public void testPrimitiveCreateRoutesThroughCreate() throws IOException {
        RecordingFileSystem recordingFs = recordingFs();

        try (FSDataOutputStream os = recordingFs.primitiveCreate(
                localPath("primitive.bin"),
                FsPermission.getFileDefault(),
                EnumSet.of(CreateFlag.CREATE),
                4096,
                (short) 1,
                4096,
                null,
                null)) {
            os.write(bytes);
        }

        assertThat(recordingFs.calls).containsExactly("create");
    }

    @Test // https://github.com/palantir/hadoop-crypto/issues/105
    public void testAppendFileBuilderRoutesThroughAppend() throws IOException {
        RecordingFileSystem recordingFs = recordingFs();
        Path file = localPath("appended.bin");
        try (FSDataOutputStream os = recordingFs.createFile(file).build()) {
            os.write(bytes);
        }
        recordingFs.calls.clear();

        try (FSDataOutputStream os = recordingFs.appendFile(file).build()) {
            os.write(bytes);
        }

        assertThat(recordingFs.calls).containsExactly("append");
    }

    @Test // https://github.com/palantir/hadoop-crypto/issues/105
    public void testOpenFileBuilderRoutesThroughOpen() throws Exception {
        RecordingFileSystem recordingFs = recordingFs();
        Path file = localPath("opened.bin");
        try (FSDataOutputStream os = recordingFs.createFile(file).build()) {
            os.write(bytes);
        }
        recordingFs.calls.clear();

        try (FSDataInputStream is = recordingFs.openFile(file).build().get()) {
            assertThat(ByteStreams.toByteArray(is)).isEqualTo(bytes);
        }

        assertThat(recordingFs.calls).containsExactly("open");
    }

    @Test // https://github.com/palantir/hadoop-crypto/issues/105
    public void testPathHandlesAreUnsupported() throws IOException {
        RecordingFileSystem recordingFs = recordingFs();
        Path file = localPath("handle.bin");
        try (FSDataOutputStream os = recordingFs.createFile(file).build()) {
            os.write(bytes);
        }
        FileStatus status = recordingFs.getFileStatus(file);

        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> recordingFs.getPathHandle(status));
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> recordingFs.open(mock(PathHandle.class), 4096));
    }

    private static FSDataOutputStream createNonRecursive(FileSystem fileSystem, Path path) throws IOException {
        return fileSystem.createNonRecursive(
                path, FsPermission.getFileDefault(), EnumSet.of(CreateFlag.CREATE), 4096, (short) 1, 4096, null);
    }

    private Path localPath(String name) {
        return new Path(new File(folder, name).getAbsolutePath());
    }

    private RecordingFileSystem recordingFs() throws IOException {
        RawLocalFileSystem local = new RawLocalFileSystem();
        local.initialize(URI.create("file://" + folder.getAbsolutePath()), new Configuration());
        return new RecordingFileSystem(local);
    }

    /**
     * Records which of the {@link DelegatingFileSystem} extension points each entry point funnels into. A subclass
     * that only overrides these methods must see every create/open/append call, otherwise the raw delegate stream
     * escapes undecorated.
     */
    private static final class RecordingFileSystem extends DelegatingFileSystem {

        private final List<String> calls = new ArrayList<>();
        private final FileSystem delegate;

        RecordingFileSystem(FileSystem delegate) {
            super(delegate);
            this.delegate = delegate;
        }

        @Override
        public FSDataInputStream open(Path path, int bufferSize) throws IOException {
            calls.add("open");
            return delegate.open(path, bufferSize);
        }

        @Override
        public FSDataOutputStream create(
                Path path,
                FsPermission permission,
                boolean overwrite,
                int bufferSize,
                short replication,
                long blockSize,
                Progressable progress)
                throws IOException {
            calls.add("create");
            return delegate.create(path, permission, overwrite, bufferSize, replication, blockSize, progress);
        }

        @Override
        public FSDataOutputStream create(
                Path path,
                FsPermission permission,
                EnumSet<CreateFlag> flags,
                int bufferSize,
                short replication,
                long blockSize,
                Progressable progress,
                ChecksumOpt checksumOpt)
                throws IOException {
            calls.add("create");
            return delegate.create(path, permission, flags, bufferSize, replication, blockSize, progress, checksumOpt);
        }

        @Override
        public FSDataOutputStream append(Path path, int bufferSize, Progressable progress) throws IOException {
            calls.add("append");
            return delegate.append(path, bufferSize, progress);
        }
    }

    private static final class ByteArrayFsInputStream extends FSInputStream {

        private final ByteArrayInputStream in;

        ByteArrayFsInputStream(byte[] bytes) {
            in = new ByteArrayInputStream(bytes);
        }

        @Override
        public void seek(long _pos) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long getPos() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean seekToNewSource(long _targetPos) {
            return false;
        }

        @Override
        public int read() {
            return in.read();
        }

        @Override
        public int read(byte[] buf, int off, int len) {
            return in.read(buf, off, len);
        }
    }
}
