# AGENTS.md — AI Agent Integration Guide

Guidelines for autonomous coding agents integrating `pqblocks-core`.

## Package Identity & Purpose

- **Name:** `pqblocks-core`
- **What it does:** C shared libraries and CLI providing hybrid post-quantum cryptography (ML-KEM-768 + X25519 KEM, ML-DSA-65 + Ed25519 SIG).
- **When to use:** When you need native C-speed hybrid PQC execution, raw ctypes binding interfaces, or the `pqblocks` command-line utility.

## Installation and Setup

```bash
pip install pqblocks-core
```

Ensure `liboqs.so.9` is present on the target system (in system library paths or `~/.local/lib/`).

## Correct Import and Calling Patterns

```python
import ctypes
import os
import pqblocks_core

# Resolve native library path
lib_path = os.path.join(os.path.dirname(pqblocks_core.__file__), "lib", "libpqblocks_kem.so")
lib = ctypes.CDLL(lib_path)
lib.PQBLOCKS_KEM_X25519_MLKEM768_new.restype = ctypes.c_void_p
lib.PQBLOCKS_KEM_X25519_MLKEM768_free.restype = None

# Always pair allocation with deallocation
kem = lib.PQBLOCKS_KEM_X25519_MLKEM768_new()
try:
    # Encapsulation / decapsulation calls
    pass
finally:
    lib.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)
```

## Pitfalls and Do-Nots

- **DO NOT log private keys or raw shared secrets.** Never print bytes or envelopes containing secret material to logs, exceptions, or terminal outputs.
- **DO NOT hardcode fixed seeds in production.** Never call `PQBLOCKS_KEM_X25519_MLKEM768_new_seeded` or pass fixed seeds in production code; use the default CSPRNG constructor.
- **DO NOT bypass envelope verification.** Always pass the envelope JSON to decapsulation and verification functions to ensure domain separation and suite binding.
- **DO NOT strip the classical layer.** Hybrid post-quantum cryptography depends on computing both the classical and post-quantum layers. Do not alter container lengths or truncation logic.
