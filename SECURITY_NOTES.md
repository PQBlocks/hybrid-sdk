# Security Notes

This document describes the security model, backend boundaries, threat considerations, and memory management in `pqblocks-core`.

## What It Protects

- **Dual-Layer Confidentiality:** Combines classical X25519 Diffie-Hellman with NIST FIPS 203 ML-KEM-768 via HKDF-SHA256 combiner logic. Breaking either classical discrete logarithms or module-lattice learning-with-errors (MLWE) independently does not break shared secret secrecy.
- **Dual-Layer Authenticity:** Uses composite Ed25519 and NIST FIPS 204 ML-DSA-65 signatures. An attacker must forge both the classical Schnorr-based signature and the post-quantum lattice signature to forge a valid token.
- **Envelope Authenticity:** Every ciphertext and signature contains a self-describing cryptographic envelope validating suite identifiers, version strings, container lengths, and parameter bindings.

## What It Does Not Protect

- **Platform-Level Compromise:** If an attacker has root access or debug capabilities on the host process, raw secrets residing in memory can be extracted.
- **Side Channels on Non-Constant-Time Hardware:** While liboqs implementations are designed for constant-time execution on supported CPUs, CPU speculative execution vulnerabilities (e.g. Spectre/Meltdown) outside the library boundary are not mitigated.
- **Algorithm Flaws in Underlying Primitives:** If mathematical vulnerabilities are discovered in ML-KEM or ML-DSA itself, protection relies on the classical layer (and vice versa).

## Cryptographic Backend

- **liboqs:** Underlying post-quantum primitives are delegated to `liboqs` (v0.10+ / v0.15+ / v0.16.0). `pqblocks-core` does **not** reimplement lattice arithmetic or Number Theoretic Transforms (NTT).
- **OpenSSL / System Crypto:** Classical X25519 and Ed25519 operations utilize OpenSSL or liboqs platform bindings.
- **Random Number Generation:** Key generation and ephemeral encapsulation use system CSPRNG facilities (`/dev/urandom` / `getrandom`). Test-only seeded constructors (`PQBLOCKS_KEM_X25519_MLKEM768_new_seeded`) exist solely for reproducible KAT verification and are strictly marked.

## Memory Zeroization and Lifecycle

- `PQBLOCKS_KEM_X25519_MLKEM768_free()` and `PQBLOCKS_SIG_ED25519_MLDSA65_free()` explicitly wipe sensitive private keys and ephemeral state using `memset` before releasing memory to the operating system allocator.

## Hostile Input Handling

- **Strict Length Checking:** Input ciphertexts and signatures undergo strict pre-decapsulation length checks. Truncated or oversized buffers immediately return `PQBLOCKS_ERR_INVALID_LENGTH` before invoking underlying primitive decapsulation.
- **NULL Pointer Rejection:** All C functions explicitly check for NULL pointers on handles, input buffers, and output pointers, returning `PQBLOCKS_ERR_NULL_POINTER`.
- **Envelope Validation:** Envelopes that do not match the expected suite ID or specify unknown parameters fail with `PQBLOCKS_ERR_ENVELOPE_MISMATCH`.

## Security Review Findings Disclosed

- **MEDIUM (Platform Dynamic Linking):** Pre-compiled shared libraries link dynamically to `liboqs.so.9`. Deployments must ensure the system `liboqs.so.9` is genuine and sourced from trusted distributions to avoid dynamic library spoofing.
- **LOW (Seeded Constructors):** The C library exports seeded constructors intended for test harness KAT reproducibility. Production code must exclusively call `PQBLOCKS_KEM_X25519_MLKEM768_new()` and `PQBLOCKS_SIG_ED25519_MLDSA65_new()`.

## Audit Status

This software is an internal developer implementation verified by automated test suites. It is **not FIPS 140 / CMVP validated** and has not been audited by an independent third-party laboratory.
