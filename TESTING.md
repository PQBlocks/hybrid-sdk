# Testing and Quality Assurance

`pqblocks-core` is tested through a comprehensive test harness verifying correctness, C binding semantics, CLI tool contracts, performance constraints, and compliance with official NIST Known Answer Tests (KAT).

## Test Matrix and Results

All 105 automated tests pass across Python 3.11, 3.12, 3.13, and 3.14 on Linux x86_64:

```
Platform: Linux x86_64
Total tests: 105
Passed: 105
Failures: 0
Errors: 0
Execution time: ~0.55s
```

## Test Suite Breakdown

| Test File | Tests | Focus Area |
|---|---|---|
| `test_Adapter_LAYER_KEM_BINDING.py` | 14 | C KEM bindings, memory allocation, encapsulation/decapsulation roundtrips, envelope parsing. |
| `test_Adapter Layer - SIG Binding.py` | 11 | C SIG bindings, composite signature generation, verification, buffer length enforcement. |
| `test_Benchmark & Performance Validation.py` | 10 | Overhead validation vs raw liboqs (≤5%), scaling curves, benchmark card integrity. |
| `test_CLI Quickstart Verification.py` | 3 | End-to-end multi-step CLI quickstart workflow and golden test vector decapsulation/verification. |
| `test_CLI Tool.py` | 5 | CLI command options, exit codes, stdin/stdout piping, and error handling. |
| `test_error_taxonomy.py` | 10 | Centralized error taxonomy, error code mapping, string formatting, secret non-leakage. |
| `test_Final Documentation & Release.py` | 13 | Release artifacts verification, man pages syntax, upgrade guides, signatures validation. |
| `test_Golden Instance Test.py` | 7 | Deterministic seeded instances, bit-identical envelopes, container sizes. |
| `test_HSM Integration Points.py` | 13 | PKCS#11 integration header review, engine delegation structures, C++ linkage. |
| `test_kat_acvp_fips.py` | 4 | Verification of NIST ACVP Known Answer Tests for ML-KEM-768 and ML-DSA-65. |
| `test_Misuse-Resistant Core - SIG.py` | 11 | Key separation, unique ephemeral generation, tamper rejection, invalid envelope handling. |
| `test_Policy Object & Versioning.py` | 4 | Cryptographic policy schemas, version strings, allowed suite validation. |
| **Total** | **105** | **Full verification across all subsystems.** |

## Official NIST ACVP Test Vectors

Official NIST Automated Cryptographic Validation Protocol (ACVP) KAT corpora are vendored under `tests/kats/acvp/`:
- `ML-KEM-768_encapDecap`: NIST FIPS 203 encapsulation/decapsulation KAT vectors.
- `ML-KEM-768_keyGen`: Key generation test vectors.
- `ML-DSA-65_keyGen`: NIST FIPS 204 signature key generation vectors.
- `ML-DSA-65_sigGen`: Official signature generation test vectors.
- `ML-DSA-65_sigVer`: Signature verification test vectors.

These vectors are validated by `tests/test_kat_acvp_fips.py` against both standalone liboqs and hybrid binding wrappers.

## Running the Tests

Execute the full suite using pytest:

```bash
pytest -v
```

To run a specific test suite:

```bash
pytest -v tests/test_kat_acvp_fips.py
```

## What Is Not Covered

- **Hardware HSM Execution:** `tests/test_HSM Integration Points.py` verifies the engine delegation interface declared in `pqblocks_hsm.h`. Actual physical HSM execution requires vendor-specific PKCS#11 hardware and modules.
- **Architectures other than x86_64:** Automated tests run against Linux x86_64 C shared libraries. Testing on ARM64 requires rebuilding native `.so` binaries with `gcc`.
