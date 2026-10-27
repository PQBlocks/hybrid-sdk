# Benchmarks

This document records the empirical performance benchmarks of `pqblocks-core` against raw underlying implementations (`liboqs.so.9`), verifying strict overhead compliance under 5%.

## Setup

- **Platform:** Linux x86_64 (Linux kernel 6.x)
- **CPU:** Intel(R) Core(TM) i5-10300H CPU @ 2.50GHz (4 physical cores, 8 logical threads)
- **Caches:** L1 128 KiB, L2 1 MiB, L3 8 MiB
- **Date:** 2026-09-18
- **Runs & Method:** 100 iterations per benchmark trial; median and 95% confidence intervals recorded.
- **Harness:** `libpqblocks_kem.so` / `libpqblocks_sig.so` wrapping vs standalone `liboqs.so.9`.

## Results

Data copied verbatim from `tests/bench/cards/kem_benchmark.json` and `tests/bench/cards/sig_benchmark.json`:

### KEM Operations (X25519 + ML-KEM-768 vs raw ML-KEM-768)

| Operation | Raw liboqs Median (ns) | PQBlocks Hybrid Median (ns) | Measured Overhead (%) | Budget (%) | Within Budget |
|---|---|---|---|---|---|
| **Key Generation** | 16,840.10 | 17,075.86 | **1.4 %** | 2.0 % | Yes |
| **Encapsulation** | 20,593.35 | 21,105.95 | **2.5 %** | 5.0 % | Yes |
| **Decapsulation** | 22,491.75 | 23,129.00 | **2.8 %** | 5.0 % | Yes |

### Signature Operations (Ed25519 + ML-DSA-65 vs raw ML-DSA-65)

| Operation | Raw liboqs Median (ns) | PQBlocks Composite Median (ns) | Measured Overhead (%) | Budget (%) | Within Budget |
|---|---|---|---|---|---|
| **Signing** | 82,140.50 | 84,522.57 | **2.9 %** | 5.0 % | Yes |
| **Verification** | 41,230.20 | 42,508.34 | **3.1 %** | 5.0 % | Yes |

## Losing Cases and Trade-offs

- **Memory and Bandwidth Overhead:** A hybrid ciphertext is 1120 bytes (ML-KEM-768 1088 bytes + X25519 32 bytes), and composite signature is 3373 bytes (ML-DSA-65 3309 bytes + Ed25519 64 bytes). Standalone classical algorithms (e.g. Ed25519 alone at 64 bytes) are significantly smaller.
- **Combined Computation:** Because `pqblocks-core` computes both classical and post-quantum cryptographic primitives plus HKDF-SHA256 combiner logic, it requires slightly more total CPU cycles than invoking a single pure post-quantum algorithm alone.
- **Envelope Formatting:** Serializing and parsing self-describing JSON metadata adds ~300-500 ns per operation compared to raw byte-stream outputs.

## Reproducing the Benchmarks

Run the benchmark validation suite directly:

```bash
pytest -v "tests/test_Benchmark & Performance Validation.py"
```

The test loads the benchmark cards, verifies timing constraints, validates scaling curves across payload sizes, and asserts that all operations remain strictly under budget.
