# Release Notes for pqblocks-core v1.0.0

## New Features in v1.0.0
- Initial release of pqblocks-core hybrid post-quantum/classical cryptographic SDK
- Hybrid KEM: X25519 + ML-KEM-768 with RFC 10024 compliant concatenation
- Hybrid SIG: Ed25519 + ML-DSA-65 with draft-ietf-lamps-pq-composite-sigs-19 construction
- Misuse-resistant API with mandatory HKDF-SHA256 and key confirmation
- Versioned policy object for algorithm agility in CI/CD pipelines
- Self-describing JSON envelope binding algorithm parameters to each operation
- CLI tool for key generation, encapsulation, decapsulation, signing, and verification
- Comprehensive error taxonomy with full error code preservation
- Benchmark validation showing ≤5% overhead vs raw liboqs
- HSM integration points defined for future PKCS#11 implementation

## Supported Platforms
- Linux x86_64
- macOS x86_64 and arm64
- Windows x86_64

## Dependencies
- liboqs v0.10.0
- OpenSSL 3.5+ (with oqs-provider fallback)
- C compiler with C11 support

## Known Limitations
- Initial release supports only X25519MLKEM768/Ed25519MLDSA65 hybrid suites
- SUF-CMA security not provided for signature component (reduction to EUF-CMA only)
- HSM integration defined but not implemented in this release

## Getting Started
See the UPGRADE.md file for installation instructions and the QUICKSTART guide in the documentation.