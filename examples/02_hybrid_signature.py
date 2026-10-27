#!/usr/bin/env python3
"""Example 2: Hybrid Post-Quantum Digital Signature (ML-DSA-65 + Ed25519).

Demonstrates key generation, signing, and verification using
the PQBlocks hybrid core C shared library.
"""
import ctypes
import os
import sys

def find_lib(name):
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "src", name),
        os.path.join(os.path.dirname(__file__), "..", "src", "pqblocks_core", "lib", name),
        os.path.expanduser(f"~/.local/lib/{name}"),
    ]
    try:
        import pqblocks_core
        pkg_lib = os.path.join(os.path.dirname(pqblocks_core.__file__), "lib", name)
        candidates.insert(0, pkg_lib)
    except ImportError:
        pass
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None

def main():
    lib_path = find_lib("libpqblocks_sig.so")
    if not lib_path:
        print("Error: SIG library not found", file=sys.stderr)
        return 1

    lib = ctypes.CDLL(lib_path)
    lib.PQBLOCKS_SIG_ED25519_MLDSA65_new.restype = ctypes.c_void_p
    lib.PQBLOCKS_SIG_ED25519_MLDSA65_new.argtypes = []
    lib.PQBLOCKS_SIG_ED25519_MLDSA65_free.restype = None
    lib.PQBLOCKS_SIG_ED25519_MLDSA65_free.argtypes = [ctypes.c_void_p]

    lib.PQBLOCKS_SIG_ED25519_MLDSA65_sign.restype = ctypes.c_int
    lib.PQBLOCKS_SIG_ED25519_MLDSA65_sign.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_char_p),
    ]

    lib.PQBLOCKS_SIG_ED25519_MLDSA65_verify.restype = ctypes.c_int
    lib.PQBLOCKS_SIG_ED25519_MLDSA65_verify.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.c_char_p,
    ]

    signer = lib.PQBLOCKS_SIG_ED25519_MLDSA65_new()
    assert signer, "Failed to initialize signer handle"

    message = b"Quantum-resistant document integrity verification payload."
    msg_buf = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)

    sig_buf = (ctypes.c_uint8 * 4096)()
    sig_len = ctypes.c_size_t(4096)
    envelope_ptr = ctypes.c_char_p()

    rc = lib.PQBLOCKS_SIG_ED25519_MLDSA65_sign(
        signer, msg_buf, len(message),
        sig_buf, ctypes.byref(sig_len),
        ctypes.byref(envelope_ptr)
    )
    assert rc == 0, f"Signing failed with code {rc}"
    print(f"Generated composite hybrid signature ({sig_len.value} bytes)")

    # Verify signature on genuine message
    rc = lib.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
        signer, msg_buf, len(message),
        sig_buf, sig_len.value,
        envelope_ptr.value
    )
    assert rc == 0, f"Verification failed with code {rc}"
    print("SUCCESS: Composite signature verified on authentic message.")

    # Verify signature fails on tampered message
    bad_msg = b"Tampered document payload."
    bad_buf = (ctypes.c_uint8 * len(bad_msg)).from_buffer_copy(bad_msg)
    rc_bad = lib.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
        signer, bad_buf, len(bad_msg),
        sig_buf, sig_len.value,
        envelope_ptr.value
    )
    assert rc_bad != 0, "Tampered message unexpectedly verified!"
    print("SUCCESS: Tampered message rejected as expected.")

    lib.PQBLOCKS_SIG_ED25519_MLDSA65_free(signer)
    return 0

if __name__ == "__main__":
    sys.exit(main())
