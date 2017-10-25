/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.crypto2.hadoop;

import java.io.IOException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.BlockLocation;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.FileUtil;
import org.apache.hadoop.fs.FilterFileSystem;
import org.apache.hadoop.fs.Path;

/**
 * Equivalent to {@link FilterFileSystem} but invokes {@link #create} and {@link #open} on this class when calling
 * {@link #copyFromLocalFile} and {@link #copyToLocalFile}.
 * <p>
 * Additionally delegates (@link getFileBlockLocations(Path, long, long)} to the underlying filesystem.
 * <p>
 * Solves: https://issues.apache.org/jira/browse/HADOOP-13870
 */
public abstract class DelegatingFileSystem extends FilterFileSystem {

    public DelegatingFileSystem(FileSystem delegate) {
        super(delegate);
        try {
            super.initialize(delegate.getUri(), delegate.getConf());
        } catch (IOException e) {
            throw new RuntimeException("Failed to initialize the delegating filesystem", e);
        }
    }

    @Override
    public void copyFromLocalFile(Path src, Path dst) throws IOException {
        copyFromLocalFile(false, src, dst);
    }

    @Override
    public void copyFromLocalFile(boolean delSrc, Path src, Path dst)
            throws IOException {
        copyFromLocalFile(delSrc, true, src, dst);
    }

    @Override
    public void copyFromLocalFile(boolean delSrc, boolean overwrite, Path[] srcs, Path dst) throws IOException {
        Configuration conf = getConf();
        FileUtil.copy(getLocal(conf), srcs, this, dst, delSrc, overwrite, conf);
    }

    @Override
    public void copyFromLocalFile(boolean delSrc, boolean overwrite, Path src, Path dst) throws IOException {
        Configuration conf = getConf();
        FileUtil.copy(getLocal(conf), src, this, dst, delSrc, overwrite, conf);
    }

    @Override
    public void copyToLocalFile(Path src, Path dst) throws IOException {
        copyToLocalFile(false, src, dst);
    }

    @Override
    public void copyToLocalFile(boolean delSrc, Path src, Path dst) throws IOException {
        copyToLocalFile(delSrc, src, dst, false);
    }

    @Override
    public void copyToLocalFile(boolean delSrc, Path src, Path dst, boolean useRawLocalFileSystem) throws IOException {
        Configuration conf = getConf();
        FileSystem local = useRawLocalFileSystem
                ? getLocal(conf).getRaw()
                : getLocal(conf);
        FileUtil.copy(this, src, local, dst, delSrc, conf);
    }

    @Override
    public BlockLocation[] getFileBlockLocations(Path path, long start, long len) throws IOException {
        return fs.getFileBlockLocations(path, start, len);
    }
}
