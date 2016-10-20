[![CircleCI Build Status](https://circleci.com/gh/palantir/hadoop-crypto/tree/develop.svg?style=shield)](https://circleci.com/gh/palantir/hadoop-crypto)
[![Download](https://api.bintray.com/packages/palantir/releases/hadoop-crypto/images/download.svg)](https://bintray.com/palantir/releases/hadoop-crypto/_latestVersion)

Hadoop Crypto
=============
*Hadoop Crypto* is a library for per-file client-side encryption in Hadoop
FileSystems such as HDFS or S3. It provides wrappers for the Hadoop FileSystem
API that transparently encrypt and decrypt the underlying streams. The
encryption algorithm uses [Key
Encapsulation](https://en.wikipedia.org/wiki/Key_encapsulation): each file is
encrypted with a unique symmetric key, which is itself secured with a
public/private key pair and stored alongside the file.

Architecture
------------
The `EncryptedFileSystem` wraps any `FileSystem` implementation and encrypts the
streams returned by open and close. These streams are encrypted/decrypted by a
unique per-file symmetric key which is then passed to the `KeyStorageStrategy`
which stores the key for future access. The provided storage strategy
implementation encrypts the symmetric key using a public/private key pair and
then stores the encrypted key on the `FileSystem` with the encrypted file.

Standalone Example
------------------

The hadoop-crypto-all.jar can be added to the classpath of any client and used
to wrap any concrete backing FileSystem. The scheme of the EncryptedFileSystem
is `e[FS-scheme]` where `[FS-scheme]` is any FileSystem that can be instantiated
statically using `FileSystem#get` (eg: efile). The FileSystem implementation,
public key, and private key must be configured in the core-site.xml as well.

### Hadoop Cli

Add hadoop-crypto-all.jar to the classpath of the cli (ex: share/hadoop/common).

##### core-site.xml
```xml
<configuration>
    <property>
        <name>fs.efile.impl</name> <!-- others: fs.es3a.impl or fs.ehdfs.impl -->
        <value>com.palantir.hadoop.ConfigurableEncryptedFileSystem</value>
    </property>

    <property>
        <name>fs.efs.key.public</name>
        <value>REDACTED</value>
    </property>

    <property>
        <name>fs.efs.key.private</name>
        <value>REDACTED</value>
    </property>
</configuration>
```

##### Commands
``` bash
./bin/hadoop dfs -put file.txt /tmp/file.txt
./bin/hadoop dfs -ls /tmp
./bin/hadoop dfs -cat /tmp/file.txt
```

Programatic Example
-------------------

Source for examples can be found [here](hadoop-crypto/src/test/java/com/palantir/hadoop/example/ExampleUsage.java)

### Initialization

```java
KeyPair pair = KeyPairs.generateKeyPair(); // Long lived KeyPair that must be saved
FileSystem fs = FileSystem.get(new URI("file:///"), new Configuration());
KeyStorageStrategy keyStore = new FileKeyStorageStrategy(fs, pair);
FileSystem efs = new EncryptedFileSystem(fs, keyStore);
```

### Writing data using EFS

``` java
// Init data and local path to write to
byte[] data = "test".getBytes(StandardCharsets.UTF_8);
byte[] readData = new byte[data.length];
Path path = new Path(folder.newFile().getAbsolutePath());

// Write data out to the encrypted stream
OutputStream eos = efs.create(path);
eos.write(data);
eos.close();

// Reading through the decrypted stream produces the original bytes
InputStream ein = efs.open(path);
IOUtils.readFully(ein, readData);
assertThat(data, is(readData));

// Reading through the raw stream produces the encrypted bytes
InputStream in = fs.open(path);
IOUtils.readFully(in, readData);
assertThat(data, is(not(readData)));

// Wrapped symmetric key is stored next to the encrypted file
assertTrue(fs.exists(new Path(path + FileKeyStorageStrategy.EXTENSION)));
```

Hadoop Configuration Properties
-------------------------------


| Key                   | Value                                           | Default
|-----------------------|-------------------------------------------------|--------
|`fs.cipher`            | The cipher used to wrap the underlying streams. | `AES/CTR/NoPadding`
|`fs.e[FS-scheme].impl` | Must be set to `com.palantir.hadoop.ConfigurableEncryptedFileSystem`
|`fs.efs.key.public`    | Base64 encoded X509 public key
|`fs.efs.key.private`   | Base64 encoded PKCS8 private key
|`fs.efs.key.algorithm` | Public/private key pair algorithm               | `RSA`

License
-------
This repository is made available under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).
