# AMD EPYC 7R13 AES-CTR benchmark

## Purpose

This report compares SunJCE and OpenSSL on an AMD EPYC 7R13 CPU.

The benchmark uses the AES/CTR/NoPadding algorithm. It measures encryption and decryption throughput.

See the [CPU comparison report](../README.md) for the Intel Xeon Platinum 8375C comparison.

## Summary

SunJCE and OpenSSL have similar encryption throughput for 1 MiB and 10 MiB payloads. SunJCE is 14% to 17% faster for 100 MiB payloads.

The provider difference is smaller for decryption. OpenSSL is faster in some tests. SunJCE is faster in other tests.

The I/O method has a large effect on decryption. Reads in 16 KiB blocks are usually faster than one full-buffer read.

The preferred encryption test writes to a JMH `Blackhole`. It does not save encrypted output. This design removes most output allocation from the measured operation.

The original tests save encrypted output in a `ByteArrayOutputStream`. These tests include array growth and copying costs. They represent a different workload.

## Terms and units

SunJCE is the Java cryptography implementation in the JDK.

The OpenSSL path uses Apache Commons Crypto and its JNI interface. JNI is the Java Native Interface.

Throughput is the amount of data processed in one second. A higher value is better.

This report uses MiB/s. One MiB is 1,048,576 bytes.

The tables also give milliseconds for each operation. A lower value is better.

The OpenSSL delta is `(OpenSSL / SunJCE - 1) * 100`. A positive value means that OpenSSL is faster.

## Blackhole encryption results

These tests use 16 KiB writes. They do not save encrypted output.

| JDK | Payload | SunJCE MiB/s | SunJCE ms/op | OpenSSL MiB/s | OpenSSL ms/op | OpenSSL delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 21 | 1 MiB | 5,238 | 0.19 | 5,199 | 0.19 | -0.8% |
| 21 | 10 MiB | 5,396 | 1.85 | 5,419 | 1.85 | +0.4% |
| 21 | 100 MiB | 5,350 | 18.69 | 4,599 | 21.75 | -14.0% |
| 25 | 1 MiB | 5,263 | 0.19 | 5,176 | 0.19 | -1.7% |
| 25 | 10 MiB | 5,413 | 1.85 | 5,108 | 1.96 | -5.6% |
| 25 | 100 MiB | 5,353 | 18.68 | 4,458 | 22.43 | -16.7% |

SunJCE changes by less than 0.5% between JDK 21 and JDK 25.

The JDK 25 OpenSSL 10 MiB result has a 29.1% relative JMH error. The 5.6% difference is not conclusive.

The 100 MiB results have smaller relative errors. They show a clear SunJCE advantage.

## Decryption results

These tests use 16 KiB reads. They create plaintext output during the measured operation.

| JDK | Payload | SunJCE MiB/s | OpenSSL MiB/s | OpenSSL delta |
| --- | ---: | ---: | ---: | ---: |
| 21 | 1 MiB | 2,759 | 3,281 | +18.9% |
| 21 | 10 MiB | 2,764 | 2,785 | +0.8% |
| 21 | 100 MiB | 2,793 | 2,561 | -8.3% |
| 25 | 1 MiB | 3,113 | 3,135 | +0.7% |
| 25 | 10 MiB | 2,587 | 2,627 | +1.6% |
| 25 | 100 MiB | 2,292 | 2,584 | +12.7% |

Several decryption error intervals overlap. Treat the small differences only as indications.

Decryption allocates approximately one payload for each operation. This memory work can limit the measured provider difference.

## Allocation in the Blackhole tests

SunJCE encryption allocates approximately 19 KiB to 20 KiB for each operation.

OpenSSL encryption allocates approximately 9.5 KiB to 10 KiB for each operation.

The encryption allocation does not increase with the payload size.

The Blackhole reduces encryption allocation by more than 99.4% from the original tests. It also removes most garbage collection from large-payload measurements.

The change improves JDK 21 result stability. It does not remove virtual-machine scheduling noise.

## Original 10 MiB results

The original encryption tests save output in memory. The decryption tests are unchanged.

| Provider and operation | I/O method | JDK 17 MiB/s | JDK 21 MiB/s | JDK 25 MiB/s |
| --- | --- | ---: | ---: | ---: |
| SunJCE decrypt | Full buffer | 1,897 | 1,828 | 1,845 |
| SunJCE decrypt | 16 KiB blocks | 2,771 | 2,651 | 2,582 |
| OpenSSL decrypt | Full buffer | 1,920 | 1,917 | 1,924 |
| OpenSSL decrypt | 16 KiB blocks | 2,694 | 2,737 | 2,719 |
| SunJCE encrypt | Full buffer | 2,024 | 1,921 | 1,926 |
| SunJCE encrypt | 16 KiB blocks | 1,593 | 1,449 | 1,527 |
| OpenSSL encrypt | Full buffer | 1,444 | 1,355 | 1,409 |
| OpenSSL encrypt | 16 KiB blocks | 1,438 | 1,367 | 1,410 |

Reads in 16 KiB blocks improve decryption throughput. The improvement is larger than most provider differences.

The original encryption results include the cost to grow and copy output arrays. Do not interpret these results as cipher-only performance.

## Provider deltas in the original tests

A positive value means that OpenSSL is faster. The JDK 17 and JDK 21 values for 1 MiB full-buffer encryption use the stable confirmation results.

| JDK | Operation | I/O method | 1 MiB | 10 MiB | 100 MiB |
| --- | --- | --- | ---: | ---: | ---: |
| 17 | Decrypt | Full buffer | +12% | +1% | +3% |
| 17 | Decrypt | 16 KiB blocks | +17% | -3% | -7% |
| 17 | Encrypt | Full buffer | 0% | -29% | -20% |
| 17 | Encrypt | 16 KiB blocks | -4% | -10% | -6% |
| 21 | Decrypt | Full buffer | +12% | +5% | 0% |
| 21 | Decrypt | 16 KiB blocks | +20% | +3% | -9% |
| 21 | Encrypt | Full buffer | -8% | -29% | -22% |
| 21 | Encrypt | 16 KiB blocks | -3% | -6% | -8% |
| 25 | Decrypt | Full buffer | +3% | +4% | +2% |
| 25 | Decrypt | 16 KiB blocks | +4% | +5% | +6% |
| 25 | Encrypt | Full buffer | -2% | -27% | -12% |
| 25 | Encrypt | 16 KiB blocks | -5% | -8% | -8% |

## Allocation in the original tests

Full-buffer decryption allocates approximately two times the payload. Decryption in 16 KiB blocks allocates approximately one payload.

SunJCE full-buffer encryption allocates approximately three times the payload.

The other original encryption tests allocate approximately three times the payload at 1 MiB. They allocate 4.2 times the payload at 10 MiB. They allocate 3.56 times the payload at 100 MiB.

`ByteArrayOutputStream` growth and output copying cause most of this allocation.

## JIT confirmation

JIT means just-in-time compilation. The JDK compiles frequently used Java code to optimized machine code.

The original 1 MiB SunJCE encryption tests changed speed during measurement on JDK 17 and JDK 21. Early iterations processed approximately 265 MiB/s. Later iterations processed approximately 1,900 MiB/s to 2,100 MiB/s.

The speed change made the first combined results unreliable. A second test used a 50-second warm-up and five 3-second measurements.

| JDK | SunJCE MiB/s | Relative error | OpenSSL MiB/s | OpenSSL delta |
| --- | ---: | ---: | ---: | ---: |
| 17 | 1,957 | 1.2% | 1,962 | 0% |
| 21 | 2,101 | 2.7% | 1,935 | -8% |

Use these stable values for 1 MiB full-buffer encryption.

## Test method

The benchmark has these settings:

- Algorithm: AES/CTR/NoPadding
- Key size: 256 bits
- Initialization vector size: 16 bytes
- Payload sizes: 1 MiB, 10 MiB, and 100 MiB
- I/O methods: one full-buffer operation or 16 KiB blocks
- JMH version: 1.37
- Mode: throughput
- Threads: one
- Forks: one for the main runs
- Warm-up: three iterations of three seconds
- Measurement: four iterations of four seconds
- Heap limit: 1 GiB
- Profiler: JMH garbage collection profiler

Both providers use the same prepared ciphertext for decryption. The setup code checks the plaintext before measurement.

The benchmark selects SunJCE directly. It configures Apache Commons Crypto to use its OpenSSL implementation.

The runner executes each test serially.

## Test environment

| Item | Value |
| --- | --- |
| Host | KVM virtual machine |
| CPU | AMD EPYC 7R13 |
| CPU resources | 16 cores and 32 hardware threads |
| CPU features | AES, AVX2, VAES |
| Operating system | Linux 6.8.0-1063-aws, x86-64 |
| JDK 17 | Amazon Corretto 17.0.20.1 |
| JDK 21 | Amazon Corretto 21.0.12.1 |
| JDK 25 | Amazon Corretto 25.0.4.1 |
| Commons Crypto | 1.2.1-SNAPSHOT, build 1.2.1-20250207.114551-117 |
| OpenSSL | 3.0.2 |
| OpenSSL library | `/lib/x86_64-linux-gnu/libcrypto.so` |

The Commons Crypto JAR has this SHA-256 value:

`5485503220bf2551289137b4b32b2746ce873fa14a7a0651f7bceeae99bd7460`

## Limits

The host is a virtual machine. CPU scheduling can change a result.

The main runs use one JMH fork. A single run cannot show all host variation.

Some results have wide 99.9% JMH confidence intervals. Do not treat small differences as conclusive when the intervals overlap.

The benchmark uses one thread. It does not measure total throughput from all CPU cores.

The Blackhole test does not retain encrypted output. The original test includes output allocation and copying.

## Raw results

### Original result sets

- [JDK 17 text](jdk17.txt) and [JDK 17 JSON](jdk17.json)
- [JDK 21 text](jdk21.txt) and [JDK 21 JSON](jdk21.json)
- [JDK 25 text](jdk25.txt) and [JDK 25 JSON](jdk25.json)

### JIT confirmation

- [JDK 17 two-fork text](jdk17-confirmation.txt) and [JDK 17 two-fork JSON](jdk17-confirmation.json)
- [JDK 21 two-fork text](jdk21-confirmation.txt) and [JDK 21 two-fork JSON](jdk21-confirmation.json)
- [JDK 17 long-warm-up text](jdk17-steady-state.txt) and [JDK 17 long-warm-up JSON](jdk17-steady-state.json)
- [JDK 21 long-warm-up text](jdk21-steady-state.txt) and [JDK 21 long-warm-up JSON](jdk21-steady-state.json)

### Blackhole result sets

- [JDK 21 text](jdk21-blackhole-chunked.txt) and [JDK 21 JSON](jdk21-blackhole-chunked.json)
- [JDK 25 text](jdk25-blackhole-chunked.txt) and [JDK 25 JSON](jdk25-blackhole-chunked.json)
