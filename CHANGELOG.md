# Changelog

All notable changes to `pqblocks-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-25

### Added
- Hybrid key encapsulation combining NIST FIPS 203 ML-KEM-768 with RFC 7748 X25519.
- Composite digital signatures combining NIST FIPS 204 ML-DSA-65 with RFC 8032 Ed25519 per draft-ietf-lamps-pq-composite-sigs.
- C shared libraries (`libpqblocks_kem.so`, `libpqblocks_sig.so`, `libpqblocks_policy.so`, `libpqblocks_errors.so`) with strict ≤5% overhead.
- Compiled `pqblocks` command-line utility for key generation, encapsulation, decapsulation, signing, and verification.
- Self-describing JSON cryptographic envelope format.
- Cryptographic policy engine for runtime algorithm suite governance.
- Formal error taxonomy with error string translation.
- Comprehensive test harness covering NIST ACVP Known Answer Tests, golden instances, and error handling.
