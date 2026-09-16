# AES-CTR provider benchmark

## Executive summary

The Blackhole-backed 16 KiB chunked follow-up removes output materialization from timed encryption. SunJCE sustains about 5.24–5.41 GiB/s on both JDK 21 and JDK 25. OpenSSL is approximately tied at 1–10 MiB, then falls behind SunJCE by 14–17% at 100 MiB. SunJCE encryption differs by less than 0.5% between JDK 21 and JDK 25.

Decryption is much closer. OpenSSL ranges from 9% slower to 6% faster at 10–100 MiB, while it is 3–20% faster at 1 MiB. The I/O strategy has a larger effect than the provider for decryption: 16 KiB chunked reads allocate about one payload per operation and are generally faster than whole-buffer reads, which allocate about two payloads.

Replacing `ByteArrayOutputStream` with `BlackholeOutputStream` reduces normalized encryption allocation from 3–356 MiB/op to about 9–20 KiB/op. This removes more than 99.4% of measured allocation and eliminates GC from most large-payload encryption iterations. It substantially improves JDK 21 large-payload score stability, although virtual-host noise remains visible in several JDK 25/OpenSSL cells.

The original matrices remain useful as end-to-end stream results including output allocation and copying. The Blackhole follow-up better isolates cipher and stream-wrapper throughput, but does not represent an application that retains encrypted output.

## Blackhole-backed 16 KiB chunked results

Each entry is `MiB/s (milliseconds/operation)`. OpenSSL delta is relative to SunJCE; positive values mean OpenSSL is faster.

| Runtime | Payload | SunJCE | OpenSSL | OpenSSL delta |
| --- | ---: | ---: | ---: | ---: |
| JDK 21 | 1 MiB | 5,238 (0.19) | 5,199 (0.19) | −0.8% |
| JDK 21 | 10 MiB | 5,396 (1.85) | 5,419 (1.85) | +0.4% |
| JDK 21 | 100 MiB | 5,350 (18.69) | 4,599 (21.75) | −14.0% |
| JDK 25 | 1 MiB | 5,263 (0.19) | 5,176 (0.19) | −1.7% |
| JDK 25 | 10 MiB | 5,413 (1.85) | 5,108 (1.96) | −5.6% |
| JDK 25 | 100 MiB | 5,353 (18.68) | 4,458 (22.43) | −16.7% |

SunJCE allocates about 19 KiB/op and OpenSSL about 9.5 KiB/op, nearly independent of payload size. The JDK 25 OpenSSL 10 MiB score has a wide 99.9% error interval, so its 5.6% deficit is directional rather than conclusive.

Decryption is an unchanged control group. Matched old/new scores generally move by a few percent, consistent with run-to-run host variation, and normalized allocation is unchanged. The larger JDK 25 100 MiB decryption movement also has overlapping wide error intervals.

For JDK 21, removing output materialization reduces relative JMH score error at 10/100 MiB from 29%/65% to 0.9%/4.3% for SunJCE and from 26%/79% to 2.8%/5.5% for OpenSSL. JDK 25 is mixed: most large cells improve, but the OpenSSL 10 MiB run remains noisy. The change removes GC-driven noise, not virtualization or CPU-scheduling noise.

## Original output-materializing 10 MiB results

Each entry is `MiB/s (milliseconds/operation)`. Higher throughput and lower latency are better.

| Provider / operation | I/O | JDK 17 | JDK 21 | JDK 25 |
| --- | --- | ---: | ---: | ---: |
| SunJCE decrypt | whole buffer | 1,897 (5.27) | 1,828 (5.47) | 1,845 (5.42) |
| SunJCE decrypt | 16 KiB chunks | 2,771 (3.61) | 2,651 (3.77) | 2,582 (3.87) |
| OpenSSL decrypt | whole buffer | 1,920 (5.21) | 1,917 (5.22) | 1,924 (5.20) |
| OpenSSL decrypt | 16 KiB chunks | 2,694 (3.71) | 2,737 (3.65) | 2,719 (3.68) |
| SunJCE encrypt | whole buffer | 2,024 (4.94) | 1,921 (5.21) | 1,926 (5.19) |
| SunJCE encrypt | 16 KiB chunks | 1,593 (6.28) | 1,449 (6.90) | 1,527 (6.55) |
| OpenSSL encrypt | whole buffer | 1,444 (6.92) | 1,355 (7.38) | 1,409 (7.10) |
| OpenSSL encrypt | 16 KiB chunks | 1,438 (6.95) | 1,367 (7.31) | 1,410 (7.09) |

## OpenSSL relative to SunJCE

Positive values mean OpenSSL is faster. The JDK 17 and JDK 21 1 MiB whole-buffer encryption values use the long-warmup steady-state measurements described below.

| Runtime | Operation | I/O | 1 MiB | 10 MiB | 100 MiB |
| --- | --- | --- | ---: | ---: | ---: |
| JDK 17 | decrypt | whole buffer | +12% | +1% | +3% |
| JDK 17 | decrypt | 16 KiB chunks | +17% | −3% | −7% |
| JDK 17 | encrypt | whole buffer | ~0% | −29% | −20% |
| JDK 17 | encrypt | 16 KiB chunks | −4% | −10% | −6% |
| JDK 21 | decrypt | whole buffer | +12% | +5% | ~0% |
| JDK 21 | decrypt | 16 KiB chunks | +20% | +3% | −9% |
| JDK 21 | encrypt | whole buffer | −8% | −29% | −22% |
| JDK 21 | encrypt | 16 KiB chunks | −3% | −6% | −8% |
| JDK 25 | decrypt | whole buffer | +3% | +4% | +2% |
| JDK 25 | decrypt | 16 KiB chunks | +4% | +5% | +6% |
| JDK 25 | encrypt | whole buffer | −2% | −27% | −12% |
| JDK 25 | encrypt | 16 KiB chunks | −5% | −8% | −8% |

## Original allocation behavior

- Decryption allocates approximately 2.0× the payload with whole-buffer reads and 1.0× with chunked reads for both providers.
- SunJCE whole-buffer encryption allocates approximately 3.0× the payload.
- Chunked SunJCE encryption and both OpenSSL encryption strategies allocate approximately 3.0× at 1 MiB, 4.2× at 10 MiB, and 3.56× at 100 MiB. `ByteArrayOutputStream` growth and final copying dominate this pattern.
- Consequently, these measurements should not be interpreted as cipher-only performance. A benchmark using preallocated buffers or `ByteBuffer` would isolate provider throughput and reduce GC sensitivity.

## JIT confirmation

The primary JDK 17 and JDK 21 1 MiB whole-buffer SunJCE encryption cells crossed a tiered-compilation threshold during measurement. Initial iterations were about 265 MiB/s and later iterations were about 1.9–2.1 GiB/s, producing unusably wide aggregate confidence intervals.

Long-warmup confirmation runs (50 seconds warmup followed by five 3-second measurements) produced stable steady-state results:

| Runtime | SunJCE MiB/s | Error | OpenSSL primary-matrix MiB/s | OpenSSL delta |
| --- | ---: | ---: | ---: | ---: |
| JDK 17 | 1,957 | ±1.2% | 1,962 | ~0% |
| JDK 21 | 2,101 | ±2.7% | 1,935 | −8% |

The primary matrix is retained unchanged. The confirmation and steady-state raw files document the transition and the corrected interpretation.

## Method

- Algorithm: AES/CTR/NoPadding with a 256-bit key and 16-byte IV.
- Providers: `SunJCE` selected explicitly; Commons Crypto forced to its OpenSSL JNI provider.
- Decryption providers consume the same precomputed ciphertext and validate plaintext during trial setup.
- Payloads: 1 MiB, 10 MiB, and 100 MiB.
- I/O: one whole-buffer operation or repeated 16 KiB operations.
- Main matrix: JMH 1.37, throughput mode, one thread, one fork, three 3-second warmup iterations, four 4-second measurement iterations.
- Profiling: JMH GC profiler, including allocation rate, normalized bytes/op, collection count, and collection time.
- Heap: 1 GiB.
- Runs were executed serially.
- Blackhole follow-up: JDK 21 and JDK 25 only, 16 KiB chunked I/O only, otherwise the same main-matrix protocol. Encryption writes output to a JMH `Blackhole`; decryption remains unchanged as a control.

## Environment

- Host: KVM virtual machine, AMD EPYC 7R13, 16 cores / 32 hardware threads, AES/AVX2/VAES available.
- OS: Linux 6.8.0-1063-aws x86_64.
- JDKs: Amazon Corretto 17.0.20.1, 21.0.12.1, and 25.0.4.1.
- Commons Crypto: `1.2.1-SNAPSHOT`, resolved snapshot build `1.2.1-20250207.114551-117`.
- Commons Crypto jar SHA-256: `5485503220bf2551289137b4b32b2746ce873fa14a7a0651f7bceeae99bd7460`.
- JNI library: `/lib/x86_64-linux-gnu/libcrypto.so`.
- Loaded OpenSSL: 3.0.2, built August 18, 2026.

The host is virtualized and the primary matrix has only one fork. Single-digit differences should be treated as directional unless confidence intervals are clearly disjoint. Several large-buffer encryption cells have wider intervals because each operation allocates hundreds of MiB.

## Raw results

Canonical 24-cell runtime matrices:

- [JDK 17 text](jdk17.txt) / [JDK 17 JSON](jdk17.json)
- [JDK 21 text](jdk21.txt) / [JDK 21 JSON](jdk21.json)
- [JDK 25 text](jdk25.txt) / [JDK 25 JSON](jdk25.json)

JDK 17/21 1 MiB whole-buffer encryption investigation:

- [JDK 17 two-fork confirmation text](jdk17-confirmation.txt) / [JSON](jdk17-confirmation.json)
- [JDK 21 two-fork confirmation text](jdk21-confirmation.txt) / [JSON](jdk21-confirmation.json)
- [JDK 17 long-warmup steady-state text](jdk17-steady-state.txt) / [JSON](jdk17-steady-state.json)
- [JDK 21 long-warmup steady-state text](jdk21-steady-state.txt) / [JSON](jdk21-steady-state.json)

Blackhole-backed 16 KiB chunked follow-up:

- [JDK 21 text](jdk21-blackhole-chunked.txt) / [JSON](jdk21-blackhole-chunked.json)
- [JDK 25 text](jdk25-blackhole-chunked.txt) / [JSON](jdk25-blackhole-chunked.json)
