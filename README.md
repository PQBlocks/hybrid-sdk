# pqblocks-core

Post-quantum hybrid cryptography core SDK with C shared libraries and policy enforcement.
Use it for native, high-performance hybrid key encapsulation (ML-KEM-768 + X25519) and composite signatures (ML-DSA-65 + Ed25519) with C-speed bindings and policy governance.
Standards implemented: NIST FIPS 203 (ML-KEM), NIST FIPS 204 (ML-DSA), RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 5869 (HKDF), and draft-ietf-lamps-pq-composite-sigs.

```bash
pip install pqblocks-core
```

```python
import ctypes, os
import pqblocks_core

# Locate the native hybrid KEM library
lib_path = os.path.join(os.path.dirname(pqblocks_core.__file__), "lib", "libpqblocks_kem.so")
lib = ctypes.CDLL(lib_path)
lib.PQBLOCKS_KEM_X25519_MLKEM768_new.restype = ctypes.c_void_p

# Initialize hybrid KEM handle (ML-KEM-768 + X25519)
kem = lib.PQBLOCKS_KEM_X25519_MLKEM768_new()
assert kem is not None
print("PQBlocks hybrid core initialized successfully.")
```

Or execute via the bundled `pqblocks` command-line utility:
```bash
pqblocks kem keygen --out kem.json
pqblocks kem encaps --in kem.json --out encaps.json
pqblocks kem decaps --in encaps.json --out shared.key
```

## Why PQBlocks

- **Dual-Layer Defense:** Combines NIST post-quantum standards with established classical algorithms. Compromising either classical ECDH or ML-KEM alone does not break confidentiality or authenticity.
- **Strict Overhead Budgets:** C shared libraries achieve under 5% overhead compared to raw standalone primitives, verified by continuous benchmarking ([BENCHMARKS.md](BENCHMARKS.md)).
- **Misuse-Resistant Envelopes:** All outputs are formatted in self-describing cryptographic envelopes specifying suite ID, algorithm parameters, and container lengths.
- **Strict Verification:** Verified against official NIST ACVP known answer tests with 105 automated test cases ([TESTING.md](TESTING.md)).
- **Licence:** Apache-2.0.

## Usage

### Command-Line Interface (CLI)

The package bundles a compiled native `pqblocks` executable supporting six core commands:

1. **KEM Key Generation:**
   ```bash
   pqblocks kem keygen --out kem.json
   ```
2. **KEM Encapsulation:**
   ```bash
   pqblocks kem encaps --in kem.json --out encaps.json
   ```
3. **KEM Decapsulation:**
   ```bash
   pqblocks kem decaps --in encaps.json --out shared.key
   ```
4. **Signature Key Generation:**
   ```bash
   pqblocks sig keygen --out sig.json
   ```
5. **Message Signing:**
   ```bash
   pqblocks sig sign --in sig.json --msg document.txt --out sig.bin
   ```
6. **Signature Verification:**
   ```bash
   pqblocks sig verify --in sig.json --msg document.txt --sig sig.bin
   ```

### Python / C Native Integration

For high-throughput applications, Python applications can interface directly with the bundled C libraries (`libpqblocks_kem.so`, `libpqblocks_sig.so`, `libpqblocks_policy.so`, `libpqblocks_errors.so`) located in `pqblocks_core/lib/`. Runnable examples are provided in `examples/01_hybrid_kem_exchange.py` and `examples/02_hybrid_signature.py`.

## API Reference

### C Interface (`pqblocks_core/lib/`)

- `void *PQBLOCKS_KEM_X25519_MLKEM768_new(void)`: Allocates and initializes a hybrid KEM instance.
- `void PQBLOCKS_KEM_X25519_MLKEM768_free(void *kem)`: Safely zeroes and deallocates a KEM instance.
- `int PQBLOCKS_KEM_X25519_MLKEM768_encaps(const void *kem, uint8_t *ct, size_t *ct_len, uint8_t *ss, size_t *ss_len, char **env_json)`: Encapsulates a 32-byte shared secret into an 1120-byte ciphertext.
- `int PQBLOCKS_KEM_X25519_MLKEM768_decaps(const void *kem, const uint8_t *ct, size_t ct_len, const char *env_json, uint8_t *ss, size_t *ss_len)`: Decapsulates a shared secret from ciphertext and validating envelope.
- `void *PQBLOCKS_SIG_ED25519_MLDSA65_new(void)`: Allocates and initializes a composite signature instance.
- `void PQBLOCKS_SIG_ED25519_MLDSA65_free(void *sig)`: Safely zeroes and deallocates a signature instance.
- `int PQBLOCKS_SIG_ED25519_MLDSA65_sign(const void *sig, const uint8_t *msg, size_t msg_len, uint8_t *out_sig, size_t *sig_len, char **env_json)`: Generates a 3373-byte composite signature.
- `int PQBLOCKS_SIG_ED25519_MLDSA65_verify(const void *sig, const uint8_t *msg, size_t msg_len, const uint8_t *in_sig, size_t sig_len, const char *env_json)`: Verifies signature validity.
- `const char *PQBLOCKS_strerror(int err)`: Returns human-readable error descriptions.

## Limitations

- **Platform Support:** Pre-compiled native libraries are built for Linux x86_64. Other platforms require compiling C sources against liboqs.
- **External Dependency:** Dynamic linking requires `liboqs.so.9` present on the system search path or in `~/.local/lib`.
- **Not FIPS/CMVP Validated:** While tested against official NIST ACVP KAT corpora, this package has not undergone formal CMVP/FIPS 140 certification.

## Security Notes

See [SECURITY_NOTES.md](SECURITY_NOTES.md) for details on zeroization, side-channel posture, memory safety, and hostile input handling.

## Verification

Full verification artifacts, test matrices, and reproducibility evidence:
- [BENCHMARKS.md](BENCHMARKS.md) — Exact performance metrics and overhead validation.
- [TESTING.md](TESTING.md) — Test suites, coverage metrics, and ACVP KAT vectors.
- [EVIDENCE.md](EVIDENCE.md) — Standards citations and method-to-code mapping.
- [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) — Self-verification report and defect registry.

## Part of PQBlocks

`pqblocks-core` is the foundational cryptographic engine of the PQBlocks post-quantum ecosystem:
- `pqblocks-jose`: Hybrid PQC JSON Web Encryption and Signatures.
- `pqblocks-wire`: Cryptographic wire format and envelope compatibility.
- `pqblocks-scan`: Quantum-readiness and cryptographic discovery scanner.
- `pqblocks-lint`: Static AST analysis for migration linting.
- `pqblocks-agility`: Cryptographic Bill of Materials (CBOM) and agility assessment.
