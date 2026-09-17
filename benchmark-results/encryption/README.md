# AES-CTR benchmark report

## Purpose

This report compares SunJCE and OpenSSL performance on two CPUs:

- AMD EPYC 7R13
- Intel Xeon Platinum 8375C

The report uses the matched JDK 21 and JDK 25 benchmark runs. It does not use the older Intel Xeon E5-2686 results.

## Summary

SunJCE encryption is much faster on the Intel CPU. The Intel result is 1.98 to 2.61 times the AMD result.

SunJCE decryption has similar performance on the two CPUs. Most differences are small or have overlapping JMH error intervals.

The AMD OpenSSL result is usually faster than the Intel OpenSSL result. However, the OpenSSL software differs between the hosts. Do not use this result as a CPU-only comparison.

On the Intel CPU, SunJCE is faster than OpenSSL for all tested operations. SunJCE is 12% to 24% faster for decryption. It is 2.65 to 2.98 times faster for encryption.

On the AMD CPU, the provider difference is smaller. OpenSSL can be faster for decryption. SunJCE is faster for 100 MiB encryption.

## Recommendation

Use SunJCE for AES-CTR encryption on the Intel Xeon Platinum 8375C. The result is large and consistent on both JDKs.

Measure the complete application before you change its provider. This benchmark does not retain encrypted output. Application I/O and memory use can change the result.

Do not make a CPU choice from the OpenSSL host comparison. The hosts used different Commons Crypto and OpenSSL versions.

## Terms and units

SunJCE is the Java cryptography implementation in the JDK.

The OpenSSL path uses Apache Commons Crypto and its JNI interface. JNI is the Java Native Interface.

Throughput is the amount of data processed in one second. A higher value is better.

This report uses MiB/s. One MiB is 1,048,576 bytes.

A positive delta means that the named comparison result is faster. A negative delta means that it is slower.

The provider delta is `(OpenSSL / SunJCE - 1) * 100`. The CPU delta is `(Intel / AMD - 1) * 100`.

## Test method

The benchmark has these settings:

- Algorithm: AES/CTR/NoPadding
- Key size: 256 bits
- Initialization vector size: 16 bytes
- Payload sizes: 1 MiB, 10 MiB, and 100 MiB
- I/O block size: 16 KiB
- JMH version: 1.37
- Mode: throughput
- Threads: one
- Forks: one
- Warm-up: three iterations of three seconds
- Measurement: four iterations of four seconds
- Heap limit: 1 GiB
- Profiler: JMH garbage collection profiler

The encryption benchmark writes to a JMH `Blackhole`. It does not create an output byte array. This design reduces memory allocation in the measured operation.

The decryption benchmark reads prepared ciphertext. It creates plaintext output during the measured operation. It checks the plaintext before measurement.

The runs execute serially. Each result uses one benchmark thread. The number of CPU cores does not directly multiply the result.

## Test environments

| Item | AMD host | Intel host |
| --- | --- | --- |
| CPU | AMD EPYC 7R13 | Intel Xeon Platinum 8375C at 2.90 GHz |
| Virtual machine | KVM, 16 cores and 32 hardware threads | KVM, 4 virtual CPUs |
| CPU features | AES, AVX2, VAES | AES, AVX2, AVX-512, VAES, VPCLMULQDQ |
| Operating system | Linux 6.8.0-1063-aws | Linux 4.18.0-553.40.1.el8_10 |
| JDK 21 | Amazon Corretto 21.0.12.1 | Amazon Corretto 21.0.12.1 |
| JDK 25 | Amazon Corretto 25.0.4.1 | Amazon Corretto 25.0.4.1 |
| Commons Crypto | 1.2.1-SNAPSHOT | 1.2.0 |
| OpenSSL | 3.0.2 | 1.1.1k FIPS |

The JDK versions match. Therefore, the SunJCE CPU comparison has fewer software differences.

The Commons Crypto and OpenSSL versions do not match. The Intel OpenSSL build also uses FIPS mode. These differences limit the OpenSSL CPU comparison.

## Throughput results

The tables give throughput in MiB/s. Higher values are better.

### AMD EPYC 7R13

| JDK | Operation | Provider | 1 MiB | 10 MiB | 100 MiB |
| --- | --- | --- | ---: | ---: | ---: |
| 21 | Decrypt | SunJCE | 2,759 | 2,764 | 2,793 |
| 21 | Decrypt | OpenSSL | 3,281 | 2,785 | 2,561 |
| 21 | Encrypt | SunJCE | 5,238 | 5,396 | 5,350 |
| 21 | Encrypt | OpenSSL | 5,199 | 5,419 | 4,599 |
| 25 | Decrypt | SunJCE | 3,113 | 2,587 | 2,292 |
| 25 | Decrypt | OpenSSL | 3,135 | 2,627 | 2,584 |
| 25 | Encrypt | SunJCE | 5,263 | 5,413 | 5,353 |
| 25 | Encrypt | OpenSSL | 5,176 | 5,108 | 4,458 |

### Intel Xeon Platinum 8375C

| JDK | Operation | Provider | 1 MiB | 10 MiB | 100 MiB |
| --- | --- | --- | ---: | ---: | ---: |
| 21 | Decrypt | SunJCE | 3,340 | 2,793 | 2,680 |
| 21 | Decrypt | OpenSSL | 2,696 | 2,444 | 2,238 |
| 21 | Encrypt | SunJCE | 13,604 | 14,106 | 10,612 |
| 21 | Encrypt | OpenSSL | 4,904 | 4,901 | 4,001 |
| 25 | Decrypt | SunJCE | 3,327 | 2,759 | 2,755 |
| 25 | Decrypt | OpenSSL | 2,763 | 2,456 | 2,223 |
| 25 | Encrypt | SunJCE | 13,594 | 14,124 | 10,782 |
| 25 | Encrypt | OpenSSL | 4,901 | 4,734 | 4,049 |

## Provider comparison

The next table gives the OpenSSL delta from SunJCE on the same host. A positive value means that OpenSSL is faster.

| CPU | JDK | Operation | 1 MiB | 10 MiB | 100 MiB |
| --- | --- | --- | ---: | ---: | ---: |
| AMD EPYC 7R13 | 21 | Decrypt | +18.9% | +0.8% | -8.3% |
| AMD EPYC 7R13 | 21 | Encrypt | -0.8% | +0.4% | -14.0% |
| AMD EPYC 7R13 | 25 | Decrypt | +0.7% | +1.6% | +12.7% |
| AMD EPYC 7R13 | 25 | Encrypt | -1.7% | -5.6% | -16.7% |
| Intel Xeon 8375C | 21 | Decrypt | -19.3% | -12.5% | -16.5% |
| Intel Xeon 8375C | 21 | Encrypt | -64.0% | -65.3% | -62.3% |
| Intel Xeon 8375C | 25 | Decrypt | -16.9% | -11.0% | -19.3% |
| Intel Xeon 8375C | 25 | Encrypt | -63.9% | -66.5% | -62.4% |

### Provider findings

OpenSSL does not give a stable advantage on the AMD CPU. Its largest advantage is 18.9% for 1 MiB decryption on JDK 21.

SunJCE has a clear advantage for 100 MiB encryption on the AMD CPU. The advantage is 14.0% on JDK 21 and 16.7% on JDK 25.

SunJCE is faster in every Intel comparison. The encryption difference is much larger than the decryption difference.

## CPU comparison

The next table gives the Intel delta from AMD for the same provider. A positive value means that Intel is faster.

| JDK | Operation | Provider | 1 MiB | 10 MiB | 100 MiB |
| --- | --- | --- | ---: | ---: | ---: |
| 21 | Decrypt | SunJCE | +21.0% | +1.1% | -4.1% |
| 21 | Decrypt | OpenSSL | -17.8% | -12.2% | -12.6% |
| 21 | Encrypt | SunJCE | +159.7% | +161.4% | +98.4% |
| 21 | Encrypt | OpenSSL | -5.7% | -9.6% | -13.0% |
| 25 | Decrypt | SunJCE | +6.9% | +6.7% | +20.2% |
| 25 | Decrypt | OpenSSL | -11.8% | -6.5% | -14.0% |
| 25 | Encrypt | SunJCE | +158.3% | +160.9% | +101.4% |
| 25 | Encrypt | OpenSSL | -5.3% | -7.3% | -9.2% |

### CPU findings

The Intel SunJCE encryption result is approximately 2.6 times the AMD result at 1 MiB and 10 MiB. It is approximately two times the AMD result at 100 MiB.

The Intel CPU supports AVX-512, VAES, and VPCLMULQDQ. The AMD CPU supports VAES but does not support AVX-512.

The SunJCE encryption result is consistent with wider vector processing on the Intel CPU. The benchmark does not identify the specific JDK intrinsic that causes the difference.

SunJCE decryption does not have the same CPU difference. Decryption allocates approximately one payload for each operation. This memory work can limit the measured cipher difference.

The AMD OpenSSL result is 5% to 18% faster than the Intel OpenSSL result. This comparison includes the software differences in the environment table.

## JDK comparison

The Intel results change by less than 3.5% between JDK 21 and JDK 25. This applies to every provider, operation, and payload size.

SunJCE encryption on AMD changes by less than 0.5%. The other AMD results have more variation.

The stable Intel encryption result supports the main finding. The JDK version does not cause the large Intel advantage.

## Memory allocation

The encryption benchmark has low allocation because it uses a `Blackhole` output stream.

SunJCE encryption allocates approximately 19 KiB for each operation on both CPUs. The value does not increase with the payload size.

OpenSSL encryption allocates approximately 10 KiB for each operation on AMD. It allocates approximately 16 KiB to 18 KiB on Intel.

Decryption allocates approximately one payload for each operation. For example, a 100 MiB decryption operation allocates approximately 100 MiB.

The allocation difference is important. The encryption result gives a better measure of cipher and stream-wrapper throughput. The decryption result includes more memory-allocation work.

## Statistical limits

JMH used one fork and four measurement iterations. Both hosts are virtual machines. CPU scheduling can change a result.

JMH calculates 99.9% confidence intervals. Some intervals are wide. These examples have large relative error values:

- AMD, JDK 25, OpenSSL 10 MiB encryption: 29.1%
- AMD, JDK 21, OpenSSL 1 MiB encryption: 20.5%
- AMD, JDK 25, SunJCE 100 MiB decryption: 18.5%
- Intel, JDK 25, OpenSSL 10 MiB encryption: 18.3%
- Intel, JDK 21, OpenSSL 1 MiB decryption: 16.9%
- Intel, JDK 21, SunJCE 100 MiB encryption: 11.8%

When error intervals overlap, do not treat a small difference as conclusive. The SunJCE encryption CPU difference is much larger than these intervals.

The benchmark measures one thread. It does not measure total throughput from all CPU cores.

The benchmark does not write encrypted data to storage. It does not measure file-system or network performance.

## Source data

### AMD EPYC 7R13

- [AMD method, environment, and original analysis](epyc-7R13/README.md)
- [JDK 21 text result](epyc-7R13/jdk21-blackhole-chunked.txt)
- [JDK 21 JSON result](epyc-7R13/jdk21-blackhole-chunked.json)
- [JDK 25 text result](epyc-7R13/jdk25-blackhole-chunked.txt)
- [JDK 25 JSON result](epyc-7R13/jdk25-blackhole-chunked.json)

The AMD directory also contains the original output-retaining matrices. Those matrices include JDK 17. This report does not compare those matrices with Intel because the Intel directory has no matching runs.

### Intel Xeon Platinum 8375C

- [Intel environment metadata](xeon-8375C-20260917T191355Z/xeon-8375C-metadata.txt)
- [JDK 21 text result](xeon-8375C-20260917T191355Z/xeon-8375C-jdk21-blackhole-chunked.txt)
- [JDK 21 JSON result](xeon-8375C-20260917T191355Z/xeon-8375C-jdk21-blackhole-chunked.json)
- [JDK 25 text result](xeon-8375C-20260917T191355Z/xeon-8375C-jdk25-blackhole-chunked.txt)
- [JDK 25 JSON result](xeon-8375C-20260917T191355Z/xeon-8375C-jdk25-blackhole-chunked.json)
