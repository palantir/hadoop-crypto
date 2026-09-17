# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## What this is

Seekable client-side encryption for Java, plus a Hadoop `FileSystem` implementation built on top of
it. Data is encrypted with a per-file symmetric key; that key is itself wrapped and stored via a
pluggable `KeyStorageStrategy`. The "seekable" part is the point: readers can seek within an
encrypted stream without decrypting from byte zero.

Published to Maven Central under `com.palantir.hadoop-crypto2`.

## Modules

| Module | Contents |
| --- | --- |
| `crypto-core` | Ciphers (`AesCtrCipher`, `AesCbcCipher`, `SeekableCipherFactory`) and the seekable stream plumbing in `com.palantir.crypto2.io`. No Hadoop dependency. |
| `crypto-keys` | `KeyMaterial`, `KeyStorageStrategy`, and the versioned key (de)serializers in `com.palantir.crypto2.keys.serialization`. |
| `hadoop-crypto` | The Hadoop `FileSystem` implementations. Depends on the other two. Also produces a shaded jar. |

## Build and test

The build provisions its own JDKs through `com.palantir.gradle.jdks` — you do **not** need a system
JDK on the `PATH`. `./gradlew` sources `gradle/gradle-jdks-setup.sh`, which downloads the JDKs
declared under `gradle/jdks/` into `~/.gradle/gradle-jdks`. The first invocation takes a few minutes.

```bash
./gradlew build                  # compile, test, javadoc, checkstyle, error-prone
./gradlew :hadoop-crypto:test    # one module's tests
./gradlew test --tests '*EncryptedFileSystemTest*'
./gradlew format                 # apply palantir-java-format; run before committing
```

Java versions are pinned in the root `build.gradle`: compiled with 25, targeting 17, tests run on
21. CI (`.circleci/config.yml`) runs `./gradlew build` and then **fails if any git-tracked file was
modified during the build**. So if `format` or a lockfile task rewrites something, commit it.

## Dependencies

Managed by `com.palantir.consistent-versions`. Declare dependencies in `build.gradle` *without*
versions; set the version in `versions.props`. After changing either, regenerate the lockfile:

```bash
./gradlew --write-locks
```

`versions.lock` is checked in and CI verifies it is current. `./gradlew check` also runs
`checkUnusedDependencies` and `checkImplicitDependencies`, so an unused or undeclared dependency
fails the build.

## Hadoop FileSystem architecture

```
StandaloneEncryptedFileSystem   (efs://, e<scheme>:// — configured via Configuration)
  └── EncryptedFileSystem       (encrypt/decrypt streams, manage key material)
        └── PathConvertingFileSystem  (rewrite URI schemes)
              └── the real backing FileSystem (hdfs, s3a, file, …)
```

- `EncryptedFileSystem` wraps a delegate, encrypting on `create` and decrypting on `open`. It
  generates a fresh `KeyMaterial` per file and stores it through a `KeyStorageStrategy`.
- `FileKeyStorageStrategy` stores each file's wrapped key next to the data as `<file>.keymaterial`.
  `StandaloneEncryptedFileSystem.listStatus` filters those entries out.
- `PathConvertingFileSystem` only rewrites paths; it does not touch stream contents.

### The decoration invariant

`DelegatingFileSystem` is the base class for every decorating FileSystem here, and it exists because
Hadoop's `FilterFileSystem` is unsafe to subclass for this purpose: `FilterFileSystem` forwards many
entry points (`createFile`, `appendFile`, `openFile`, `openFileWithOptions`, `createNonRecursive`,
`primitiveCreate`, `copyFromLocalFile`, `copyToLocalFile`, …) *straight to the wrapped delegate*.
A subclass that overrides only `create`/`open` therefore still leaks undecorated delegate streams
through all of those — for `EncryptedFileSystem` that means silently writing plaintext or reading
ciphertext.

`DelegatingFileSystem` re-routes every one of those back through `this`, so there are exactly three
extension points a subclass needs to implement:

- `create(...)`
- `open(Path, int)`
- `append(Path, int, Progressable)`

**When adding a subclass, override only those.** The re-routing methods in `DelegatingFileSystem`
are `final` on purpose — do not un-final them to "fix" a caller.

**When bumping the Hadoop version, re-check `FilterFileSystem` for newly added methods that forward
to the delegate.** A new forwarding method is a new hole in the encryption, and it will not fail any
existing test. `DelegatingFileSystemTest` exercises each routed entry point with a recording
subclass; extend it alongside any such change.

`PathHandle`-based reads (`open(PathHandle, int)`, `createPathHandle`) are unsupported by default: a
path handle is an opaque, delegate-specific reference that a decorator cannot translate back into a
path, and `EncryptedFileSystem` needs the path to look up key material.

## Conventions

- Formatting is palantir-java-format (4 spaces, 120 columns). `./gradlew format` is authoritative.
- Baseline error-prone runs as part of compilation and **errors** on violations. The most common one
  you will hit: an intentionally unused parameter must be renamed with a leading underscore
  (`_path`, `_bufferSize`), as in `EncryptedFileSystem.append`.
- Throw log-safe exceptions from `com.palantir.logsafe.exceptions`
  (`SafeIllegalStateException`, `SafeUnsupportedOperationException`, …) and attach context with
  `SafeArg` / `UnsafeArg` rather than interpolating into the message. Paths and file keys are
  `UnsafeArg`. Hadoop-contract exceptions (`FileNotFoundException`, `ParentNotDirectoryException`)
  are the exception — throw the type callers expect.
- Tests are JUnit 5 + AssertJ + Mockito. Prefer a real `RawLocalFileSystem` over a `@TempDir` for
  FileSystem behaviour; reserve mocks for failure injection. Loggable exceptions are asserted with
  `assertThatLoggableExceptionThrownBy(...)` from `com.palantir.logsafe.testing`.

## Security notes

Neither supported AES mode is authenticated. Ciphertext integrity is explicitly out of scope and
must be handled by the caller (e.g. encrypt-then-MAC) — see the disclaimer in `README.md`. Do not
add code that implies ciphertext is tamper-evident.

Changes that could cause plaintext to be written, or ciphertext to be returned to a caller expecting
plaintext, are the highest-severity class of bug in this repository. Cover them with a test that
asserts on the bytes actually on the delegate FileSystem, not just on a round-trip.
