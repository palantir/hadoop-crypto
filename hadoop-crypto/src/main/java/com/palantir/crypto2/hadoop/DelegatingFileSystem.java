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

import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.exceptions.SafeUncheckedIoException;
import com.palantir.logsafe.exceptions.SafeUnsupportedOperationException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.concurrent.CompletableFuture;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.BlockLocation;
import org.apache.hadoop.fs.CreateFlag;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FSDataOutputStreamBuilder;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.FileUtil;
import org.apache.hadoop.fs.FilterFileSystem;
import org.apache.hadoop.fs.FutureDataInputStreamBuilder;
import org.apache.hadoop.fs.Options.ChecksumOpt;
import org.apache.hadoop.fs.Options.HandleOpt;
import org.apache.hadoop.fs.ParentNotDirectoryException;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.PathHandle;
import org.apache.hadoop.fs.impl.AbstractFSBuilderImpl;
import org.apache.hadoop.fs.impl.OpenFileParameters;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.util.LambdaUtils;
import org.apache.hadoop.util.Progressable;

/**
 * Equivalent to {@link FilterFileSystem} but guarantees that every way of creating or opening a file funnels through
 * the {@link #create}, {@link #open} and {@link #append} methods of <em>this</em> class rather than being forwarded
 * straight to the wrapped {@link FileSystem}.
 * <p>
 * {@link FilterFileSystem} forwards a number of read and write entry points directly to the delegate. A subclass that
 * only overrides {@link #create}/{@link #open} therefore still leaks the raw delegate streams through those other
 * entry points, which for {@link EncryptedFileSystem} means writing plaintext or reading ciphertext. This class
 * re-routes each of them:
 * <ul>
 *     <li>{@link #createFile}, {@link #appendFile}, {@link #openFile(Path)} and {@link #openFile(PathHandle)} return
 *     builders bound to this FileSystem, so {@code build()} lands on the overridden {@link #create}/{@link #append}/
 *     {@link #open} methods. {@link #openFileWithOptions} is re-routed for the same reason, as it is what the builder
 *     returned by {@code openFile} ultimately calls.</li>
 *     <li>{@link #createNonRecursive} and {@link #primitiveCreate} are implemented in terms of {@link #create}.</li>
 *     <li>{@link #open(PathHandle, int)} and {@link #createPathHandle} are unsupported by default: a
 *     {@link PathHandle} is an opaque delegate specific reference that a decorating FileSystem cannot translate, so
 *     forwarding it would silently bypass the decoration.</li>
 * </ul>
 * Additionally, {@link #copyFromLocalFile} and {@link #copyToLocalFile} are re-routed for the same reason, and
 * {@link #getFileBlockLocations(Path, long, long)} is delegated to the underlying filesystem.
 * <p>
 * Solves: <a href="https://issues.apache.org/jira/browse/HADOOP-13870">HADOOP-13870</a>
 */
public abstract class DelegatingFileSystem extends FilterFileSystem {

    protected DelegatingFileSystem(FileSystem delegate) {
        super(delegate);
        try {
            super.initialize(delegate.getUri(), delegate.getConf());
        } catch (IOException e) {
            throw new SafeUncheckedIoException("Failed to initialize the delegating filesystem", e);
        }
    }

    @Override
    public final void copyFromLocalFile(Path src, Path dst) throws IOException {
        copyFromLocalFile(false, src, dst);
    }

    @Override
    public final void copyFromLocalFile(boolean delSrc, Path src, Path dst) throws IOException {
        copyFromLocalFile(delSrc, true, src, dst);
    }

    @Override
    public final void copyFromLocalFile(boolean delSrc, boolean overwrite, Path[] srcs, Path dst) throws IOException {
        Configuration conf = getConf();
        FileUtil.copy(getLocal(conf), srcs, this, dst, delSrc, overwrite, conf);
    }

    @Override
    public final void copyFromLocalFile(boolean delSrc, boolean overwrite, Path src, Path dst) throws IOException {
        Configuration conf = getConf();
        FileUtil.copy(getLocal(conf), src, this, dst, delSrc, overwrite, conf);
    }

    @Override
    public final void copyToLocalFile(Path src, Path dst) throws IOException {
        copyToLocalFile(false, src, dst);
    }

    @Override
    public final void copyToLocalFile(boolean delSrc, Path src, Path dst) throws IOException {
        copyToLocalFile(delSrc, src, dst, false);
    }

    @Override
    public final void copyToLocalFile(boolean delSrc, Path src, Path dst, boolean useRawLocalFileSystem)
            throws IOException {
        Configuration conf = getConf();
        FileSystem local = useRawLocalFileSystem ? getLocal(conf).getRaw() : getLocal(conf);
        FileUtil.copy(this, src, local, dst, delSrc, conf);
    }

    @Override
    public final BlockLocation[] getFileBlockLocations(Path path, long start, long len) throws IOException {
        return fs.getFileBlockLocations(path, start, len);
    }

    /**
     * Returns a builder bound to this FileSystem so that {@code build()} calls {@link #create} or
     * {@link #createNonRecursive} on this class. {@link FilterFileSystem} returns the delegate's builder, which
     * bypasses those overrides.
     */
    @Override
    public final FSDataOutputStreamBuilder<?, ?> createFile(Path path) {
        return createDataOutputStreamBuilder(this, path).create().overwrite(true);
    }

    /**
     * Returns a builder bound to this FileSystem so that {@code build()} calls {@link #append} on this class.
     * {@link FilterFileSystem} returns the delegate's builder, which bypasses that override.
     */
    @Override
    public final FSDataOutputStreamBuilder<?, ?> appendFile(Path path) {
        return createDataOutputStreamBuilder(this, path).append();
    }

    /**
     * Returns a builder bound to this FileSystem so that {@code build()} calls {@link #openFileWithOptions} and in
     * turn {@link #open} on this class. {@link FilterFileSystem} returns the delegate's builder, which bypasses those
     * overrides.
     */
    @Override
    public final FutureDataInputStreamBuilder openFile(Path path) throws IOException {
        return createDataInputStreamBuilder(this, path);
    }

    /**
     * Returns a builder bound to this FileSystem. Note that {@link #open(PathHandle, int)} is unsupported by default,
     * so building the returned stream fails unless a subclass can meaningfully support path handles.
     */
    @Override
    public final FutureDataInputStreamBuilder openFile(PathHandle pathHandle) throws IOException {
        return createDataInputStreamBuilder(this, pathHandle);
    }

    @Override
    protected final CompletableFuture<FSDataInputStream> openFileWithOptions(Path path, OpenFileParameters parameters) {
        AbstractFSBuilderImpl.rejectUnknownMandatoryKeys(
                parameters.getMandatoryKeys(), Collections.emptySet(), "for " + path);
        return LambdaUtils.eval(new CompletableFuture<>(), () -> open(path, parameters.getBufferSize()));
    }

    @Override
    protected final CompletableFuture<FSDataInputStream> openFileWithOptions(
            PathHandle pathHandle, OpenFileParameters parameters) {
        AbstractFSBuilderImpl.rejectUnknownMandatoryKeys(parameters.getMandatoryKeys(), Collections.emptySet(), "");
        return LambdaUtils.eval(new CompletableFuture<>(), () -> open(pathHandle, parameters.getBufferSize()));
    }

    /**
     * Implemented in terms of {@link #create} so that the stream is decorated by this class rather than produced by
     * the delegate. The "non recursive" contract is upheld by checking the parent directory up front; unlike a native
     * implementation this check is not atomic with the create.
     */
    @Override
    public final FSDataOutputStream createNonRecursive(
            Path path,
            FsPermission permission,
            EnumSet<CreateFlag> flags,
            int bufferSize,
            short replication,
            long blockSize,
            Progressable progress)
            throws IOException {
        Path parent = path.getParent();
        if (parent != null) {
            FileStatus parentStatus;
            try {
                parentStatus = getFileStatus(parent);
            } catch (FileNotFoundException e) {
                FileNotFoundException missingParent =
                        new FileNotFoundException("Parent directory does not exist: " + parent);
                missingParent.initCause(e);
                throw missingParent;
            }
            if (!parentStatus.isDirectory()) {
                throw new ParentNotDirectoryException("Parent path is not a directory: " + parent);
            }
        }

        return create(path, permission, flags, bufferSize, replication, blockSize, progress, null);
    }

    /**
     * Implemented in terms of {@link #create} and {@link #append} so that the stream is decorated by this class rather
     * than produced by the delegate. Mirrors {@link FileSystem#primitiveCreate}.
     */
    @Override
    protected final FSDataOutputStream primitiveCreate(
            Path path,
            FsPermission absolutePermission,
            EnumSet<CreateFlag> flag,
            int bufferSize,
            short replication,
            long blockSize,
            Progressable progress,
            ChecksumOpt _checksumOpt)
            throws IOException {
        boolean pathExists = exists(path);
        CreateFlag.validate(path, pathExists, flag);

        if (pathExists && flag.contains(CreateFlag.APPEND)) {
            return append(path, bufferSize, progress);
        }

        return create(
                path,
                absolutePermission,
                flag.contains(CreateFlag.OVERWRITE),
                bufferSize,
                replication,
                blockSize,
                progress);
    }

    /**
     * Unsupported by default. A {@link PathHandle} is an opaque reference to a file in the delegate FileSystem which a
     * decorating FileSystem has no way of translating, so forwarding it to the delegate would return an undecorated
     * stream.
     */
    @Override
    public FSDataInputStream open(PathHandle _fd, int _bufferSize) throws IOException {
        throw new SafeUnsupportedOperationException(
                "Opening a PathHandle is not supported",
                SafeArg.of("fileSystem", getClass().getSimpleName()));
    }

    /**
     * Unsupported by default, because the resulting {@link PathHandle} could not be opened through
     * {@link #open(PathHandle, int)}.
     */
    @Override
    protected PathHandle createPathHandle(FileStatus _stat, HandleOpt... _opts) {
        throw new SafeUnsupportedOperationException(
                "Creating a PathHandle is not supported",
                SafeArg.of("fileSystem", getClass().getSimpleName()));
    }
}
