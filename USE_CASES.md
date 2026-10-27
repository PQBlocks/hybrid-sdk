# Use Cases and Deployment Patterns

`pqblocks-core` provides high-performance, dual-layer post-quantum cryptography for infrastructure engineering, microservices, and automated command-line workflows.

## Scenario 1: Post-Quantum Microservice Key Exchange

**Context:** Two services require a quantum-resistant shared secret for symmetrical AES-GCM channel encryption while retaining classical security fallback.

```python
import ctypes
import os
import pqblocks_core

# 1. Load native KEM library
lib_path = os.path.join(os.path.dirname(pqblocks_core.__file__), "lib", "libpqblocks_kem.so")
lib = ctypes.CDLL(lib_path)
lib.PQBLOCKS_KEM_X25519_MLKEM768_new.restype = ctypes.c_void_p
lib.PQBLOCKS_KEM_X25519_MLKEM768_free.restype = None

# Initialize recipient handle
recipient = lib.PQBLOCKS_KEM_X25519_MLKEM768_new()

# Encapsulate shared secret
ct_buf = (ctypes.c_uint8 * 2048)()
ct_len = ctypes.c_size_t(2048)
ss_sender = (ctypes.c_uint8 * 32)()
ss_len = ctypes.c_size_t(32)
env_ptr = ctypes.c_char_p()

lib.PQBLOCKS_KEM_X25519_MLKEM768_encaps(
    recipient, ct_buf, ctypes.byref(ct_len),
    ss_sender, ctypes.byref(ss_len), ctypes.byref(env_ptr)
)

# Decapsulate on recipient side
ss_recipient = (ctypes.c_uint8 * 32)()
rec_len = ctypes.c_size_t(32)

lib.PQBLOCKS_KEM_X25519_MLKEM768_decaps(
    recipient, ct_buf, ct_len.value, env_ptr.value,
    ss_recipient, ctypes.byref(rec_len)
)

assert bytes(ss_sender) == bytes(ss_recipient)
print("Derived 256-bit quantum-safe symmetric key successfully.")
lib.PQBLOCKS_KEM_X25519_MLKEM768_free(recipient)
```

## Scenario 2: Tamper-Evident Composite Document Signing

**Context:** Sign software distribution manifests or compliance records using dual Ed25519 + ML-DSA-65 signatures per draft-ietf-lamps-pq-composite-sigs.

```python
import ctypes
import os
import pqblocks_core

lib_path = os.path.join(os.path.dirname(pqblocks_core.__file__), "lib", "libpqblocks_sig.so")
lib = ctypes.CDLL(lib_path)
lib.PQBLOCKS_SIG_ED25519_MLDSA65_new.restype = ctypes.c_void_p
lib.PQBLOCKS_SIG_ED25519_MLDSA65_free.restype = None

signer = lib.PQBLOCKS_SIG_ED25519_MLDSA65_new()
payload = b"Manifest: artifact-v1.0.tar.gz sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

msg_buf = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
sig_buf = (ctypes.c_uint8 * 4096)()
sig_len = ctypes.c_size_t(4096)
env_ptr = ctypes.c_char_p()

# Sign
lib.PQBLOCKS_SIG_ED25519_MLDSA65_sign(
    signer, msg_buf, len(payload),
    sig_buf, ctypes.byref(sig_len), ctypes.byref(env_ptr)
)

# Verify
rc = lib.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
    signer, msg_buf, len(payload),
    sig_buf, sig_len.value, env_ptr.value
)
assert rc == 0
print(f"Verified composite signature ({sig_len.value} bytes) successfully.")
lib.PQBLOCKS_SIG_ED25519_MLDSA65_free(signer)
```

## Scenario 3: Automated CLI Pipeline

**Context:** Shell script generating key pairs and authenticating files inside CI/CD runners without writing Python code:

```bash
# Generate key pair
pqblocks sig keygen --out signing-key.json

# Sign release tarball
pqblocks sig sign --in signing-key.json --msg release.tar.gz --out release.sig

# Verify release tarball
pqblocks sig verify --in signing-key.json --msg release.tar.gz --sig release.sig
```

## When to Use Something Else

- **When you need high-level JSON Web Tokens (JWE/JWS):** Use `pqblocks-jose` instead, which provides full standard-compliant JWT/JWE/JWS abstractions.
- **When you only need token serialization without cryptography:** Use `pqblocks-jwe` for simple five-part token formatting.
- **When you require Python-pure implementations:** `pqblocks-core` relies on compiled C shared libraries and `liboqs.so.9`. If native compilation is prohibited, use pure-Python cryptographic libraries.
