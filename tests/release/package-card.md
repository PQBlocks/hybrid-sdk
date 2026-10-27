# pqblocks-core Hybrid Post-Quantum Cryptography SDK

pqblocks-core is a hybrid post-quantum/classical cryptographic SDK providing misuse-resistant API, versioned policy object, and self-describing envelope for TLS 1.3 hybrid group `X25519MLKEM768`.

## Technology Description
- Hybrid post-quantum/classical cryptography
- X25519 + ML-KEM-768 key encapsulation mechanism
- Ed25519 + ML-DSA-65 digital signatures
- Mandatory HKDF-SHA256 key derivation
- Key confirmation via HMAC-SHA256
- Self-describing JSON envelope output
- Misuse-resistant API design