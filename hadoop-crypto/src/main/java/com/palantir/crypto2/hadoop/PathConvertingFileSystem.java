/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.hadoop;

import java.io.IOException;
import java.net.URI;
import java.util.function.Function;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.util.Progressable;

/**
 * A decorator {@link FileSystem} that delegates calls and converts paths to/from the delegate FileSystem.
 * {@link Path}s passed into methods are converted using {@link #toFunc} before being forwarded.
 * {@link Path}s returned from the delegate are converted using {@link #fromFunc} before being returned.
 */
public final class PathConvertingFileSystem extends DelegatingFileSystem {

    private final FileSystem delegate;
    private final Function<Path, Path> toFunc;
    private final Function<Path, Path> fromFunc;
    private Function<URI, URI> fromUriFunc;

    public PathConvertingFileSystem(FileSystem delegate,
            Function<Path, Path> toFunc,
            Function<Path, Path> fromFunc,
            Function<URI, URI> fromUriFunc) {
        super(delegate);
        this.delegate = delegate;
        this.toFunc = toFunc;
        this.fromFunc = fromFunc;
        this.fromUriFunc = fromUriFunc;
    }

    @Override
    public URI getUri() {
        return fromUriFunc.apply(delegate.getUri());
    }

    @Override
    public FSDataInputStream open(Path path, int bufferSize) throws IOException {
        return delegate.open(to(path), bufferSize);
    }

    @Override
    public FSDataOutputStream create(Path path, FsPermission permission, boolean overwrite, int bufferSize,
            short replication, long blockSize, Progressable progress) throws IOException {
        return delegate.create(to(path), permission, overwrite, bufferSize, replication, blockSize,
                progress);
    }

    @Override
    public FSDataOutputStream append(Path path, int bufferSize, Progressable progress) throws IOException {
        return delegate.append(to(path), bufferSize, progress);
    }

    @Override
    public boolean rename(Path src, Path dst) throws IOException {
        return delegate.rename(to(src), to(dst));
    }

    @Override
    public boolean delete(Path path, boolean recursive) throws IOException {
        return delegate.delete(to(path), recursive);
    }

    @Override
    public Path makeQualified(Path path) {
        return from(delegate.makeQualified(to(path)));
    }

    @Override
    public FileStatus[] listStatus(Path path) throws IOException {
        FileStatus[] fileStatuses = delegate.listStatus(to(path));
        for (int i = 0; i < fileStatuses.length; i++) {
            fileStatuses[i] = toReturnFileStatus(fileStatuses[i]);
        }
        return fileStatuses;
    }

    @Override
    public FileStatus getFileStatus(Path path) throws IOException {
        return toReturnFileStatus(delegate.getFileStatus(to(path)));
    }

    @Override
    public void setWorkingDirectory(Path path) {
        delegate.setWorkingDirectory(to(path));
    }

    @Override
    public Path getWorkingDirectory() {
        return from(delegate.getWorkingDirectory());
    }

    @Override
    public boolean mkdirs(Path path, FsPermission permission) throws IOException {
        return delegate.mkdirs(to(path), permission);
    }

    private Path to(Path path) {
        return toFunc.apply(path);
    }

    private Path from(Path path) {
        return fromFunc.apply(path);
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
                status.isSymlink() ? status.getSymlink() : null, // getSymlink throws if file is not a symlink
                from(status.getPath()));
    }

}
