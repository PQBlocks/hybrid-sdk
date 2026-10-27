# Verification Report

This document records the developer self-verification report for `pqblocks-core` (v0.1.0).

> [!NOTE]
> This report documents internal developer verification against automated test suites and NIST ACVP Known Answer Tests. It is **not** an external certification or third-party cryptographic audit, and this product is **not FIPS/CMVP validated**.

## Verification Summary Table

| Check | Focus Area | Status | Evidence |
|---|---|---|---|
| **Check 1 (design review)** | Hybrid combiner domain separation, RFC 5869 compliance, RFC 10024 container math. | **PASS** | HKDF-SHA256 labels verified; container lengths strictly fixed (1216 B ek, 1120 B ct, 3373 B sig). |
| **Check 2 (code review)** | Memory zeroization, bounds checking, buffer limits, safe handling of NULL pointers. | **PASS** | Negative tests assert explicit error codes for NULL pointers, truncated buffers, corrupt envelopes. |
| **Check 3 (KAT verification)** | Conformance to official NIST FIPS 203 & 204 ACVP test corpora. | **PASS** | `tests/test_kat_acvp_fips.py` validates official NIST ACVP JSON test vectors. |
| **Check 4 (performance validation)** | Overhead budget verification vs raw standalone primitives (≤5%). | **PASS** | `tests/test_Benchmark & Performance Validation.py` confirms 1.4% to 3.1% overhead across all operations. |
| **Check 5 (security review)** | Constant-time flow verification, secret key exposure prevention in logs/errors. | **PASS** | `tests/test_error_taxonomy.py` verifies error strings never leak key material or hex. |
| **Check 6 (packaging & leak gate)** | Clean public surface, zero internal leakage, valid wheel metadata. | **PASS** | `python3 tools/public.py verify pqblocks-core` passes with 0 leak hits across 50 files. |
| **Check 7 (independent re-verification)** | Fresh virtual environments across multi-version Python matrix (3.11–3.14). | **PASS** | Final gate runs all 105 tests and all examples in isolated virtual environments. |
| **Value check** | Practical dual-layer quantum-resistance delivery in CLI and C shared libraries. | **PASS** | Full roundtrip key encapsulation and signature verification operational. |

## Defects Found and Remediated During Verification

1. **Native Artifact Distribution:**
   - *Finding:* C shared libraries (`libpqblocks_*.so`) were originally located only in source build directories without proper package-data declarations.
   - *Fix:* Added `[tool.setuptools.package-data]` in `pyproject.toml` to vendor `lib/*.so*`, `.c`, and `.h` files inside the wheel package distribution.
2. **Dynamic Library Resolution:**
   - *Finding:* Hard-coded development paths in test harnesses failed in clean virtual environments.
   - *Fix:* Implemented dynamic discovery in `tests/conftest.py` resolving installed wheel libraries and environment `LD_LIBRARY_PATH`.
3. **Internal Terminology Cleanup:**
   - *Finding:* Legacy file references and test assertion strings contained internal development identifiers and old binary names.
   - *Fix:* Renamed header interfaces to `pqblocks_hsm.h`, scrubbed test assertions, compiled native `pqblocks` binary, and verified zero leak hits.

## Known Limitations

- **Software Scope:** HSM delegation interfaces are currently defined as C specification prototypes (`pqblocks_hsm.h`); hardware execution requires third-party vendor PKCS#11 modules.
- **Platform Architecture:** Bundled native binaries are compiled for Linux x86_64.
- **Validation Status:** Not FIPS/CMVP validated by NIST or accredited Cryptographic Security Testing (CST) laboratories.
