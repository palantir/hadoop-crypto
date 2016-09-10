/*
 * Copyright 2016 Palantir Technologies, Inc. All rights reserved.
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

package com.palantir.hadoop;

import com.google.common.base.Function;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.util.Progressable;

/**
 * A decorator {@link FileSystem} that delegates calls and converts paths to/from the delegate FileSystem.
 * {@link Path}s passed into methods are converted using {@code toDelegatePathFunc} before being forwarded.
 * {@link Path}s returned from the delegate are converted using {@code toReturnPathFunc} before being returned.
 */
public final class PathConvertingFileSystem extends FileSystem {

    private final FileSystem delegate;
    private final Function<Path, Path> toDelegatePathFunc;
    private final Function<Path, Path> toReturnPathFunc;

    public PathConvertingFileSystem(FileSystem delegate,
            Function<Path, Path> toDelegatePathFunc,
            Function<Path, Path> toReturnPathFunc) {
        this.delegate = delegate;
        this.toDelegatePathFunc = toDelegatePathFunc;
        this.toReturnPathFunc = toReturnPathFunc;
        super.setConf(delegate.getConf());
    }

    // convenience
    private Path toDelegatePath(Path path) {
        return toDelegatePathFunc.apply(path);
    }

    // convenience
    private Path toReturnPath(Path path) {
        return toReturnPathFunc.apply(path);
    }

    @Override
    public URI getUri() {
        return delegate.getUri();
    }

    @Override
    public FSDataInputStream open(Path f, int bufferSize) throws IOException {
        return delegate.open(toDelegatePath(f), bufferSize);
    }

    @Override
    public FSDataOutputStream create(Path f, FsPermission permission, boolean overwrite, int bufferSize,
            short replication, long blockSize, Progressable progress) throws IOException {
        return delegate.create(toDelegatePath(f), permission, overwrite, bufferSize, replication, blockSize,
                progress);
    }

    @Override
    public FSDataOutputStream append(Path f, int bufferSize, Progressable progress) throws IOException {
        return delegate.append(toDelegatePath(f), bufferSize, progress);
    }

    @Override
    public boolean rename(Path src, Path dst) throws IOException {
        return delegate.rename(toDelegatePath(src), toDelegatePath(dst));
    }

    @Override
    public boolean delete(Path f, boolean recursive) throws IOException {
        return delegate.delete(toDelegatePath(f), recursive);
    }

    @Override
    public FileStatus[] listStatus(Path f) throws FileNotFoundException, IOException {
        FileStatus[] fileStatuses = delegate.listStatus(toDelegatePath(f));
        for (int i = 0; i < fileStatuses.length; i++) {
            fileStatuses[i] = toReturnFileStatus(fileStatuses[i]);
        }
        return fileStatuses;
    }

    @Override
    public FileStatus getFileStatus(Path f) throws IOException {
        return toReturnFileStatus(delegate.getFileStatus(toDelegatePath(f)));
    }

    private FileStatus toReturnFileStatus(FileStatus status) throws IOException {
        // same as FileStatus copy constructor
        return new FileStatus(
                status.getLen(),
                status.isDirectory(),
                status.getReplication(),
                status.getBlockSize(),
                status.getModificationTime(),
                status.getAccessTime(),
                status.getPermission(),
                status.getOwner(),
                status.getGroup(),
                (status.isSymlink() ? status.getSymlink() : null), // getSymlink throws if file is not a symlink
                toReturnPath(status.getPath()));
    }

    @Override
    public void setWorkingDirectory(Path new_dir) {
        delegate.setWorkingDirectory(toDelegatePath(new_dir));
    }

    @Override
    public Path getWorkingDirectory() {
        return toReturnPath(delegate.getWorkingDirectory());
    }

    @Override
    public boolean mkdirs(Path f, FsPermission permission) throws IOException {
        return delegate.mkdirs(toDelegatePath(f), permission);
    }

}
