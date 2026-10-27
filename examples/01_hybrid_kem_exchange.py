#!/usr/bin/env python3
"""Example 1: Hybrid Post-Quantum Key Encapsulation (ML-KEM-768 + X25519).

Demonstrates key generation, encapsulation, and decapsulation using
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
    lib_path = find_lib("libpqblocks_kem.so")
    if not lib_path:
        print(f"Error: KEM library not found", file=sys.stderr)
        return 1

    lib = ctypes.CDLL(lib_path)
    lib.PQBLOCKS_KEM_X25519_MLKEM768_new.restype = ctypes.c_void_p
    lib.PQBLOCKS_KEM_X25519_MLKEM768_new.argtypes = []
    lib.PQBLOCKS_KEM_X25519_MLKEM768_free.restype = None
    lib.PQBLOCKS_KEM_X25519_MLKEM768_free.argtypes = [ctypes.c_void_p]

    lib.PQBLOCKS_KEM_X25519_MLKEM768_encaps.restype = ctypes.c_int
    lib.PQBLOCKS_KEM_X25519_MLKEM768_encaps.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_char_p),
    ]

    lib.PQBLOCKS_KEM_X25519_MLKEM768_decaps.restype = ctypes.c_int
    lib.PQBLOCKS_KEM_X25519_MLKEM768_decaps.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_size_t),
    ]

    # Initialize Alice's KEM handle
    alice = lib.PQBLOCKS_KEM_X25519_MLKEM768_new()
    assert alice, "Failed to initialize Alice KEM handle"

    # Bob encapsulates to Alice's public key (using Alice handle here)
    ct_buf = (ctypes.c_uint8 * 2048)()
    ct_len = ctypes.c_size_t(2048)
    ss_bob = (ctypes.c_uint8 * 32)()
    ss_bob_len = ctypes.c_size_t(32)
    envelope_ptr = ctypes.c_char_p()

    rc = lib.PQBLOCKS_KEM_X25519_MLKEM768_encaps(
        alice, ct_buf, ctypes.byref(ct_len),
        ss_bob, ctypes.byref(ss_bob_len),
        ctypes.byref(envelope_ptr)
    )
    assert rc == 0, f"Encapsulation failed: {rc}"
    envelope = envelope_ptr.value.decode("utf-8")
    print(f"[Bob] Encapsulated hybrid ciphertext ({ct_len.value} bytes)")
    print(f"[Bob] Derived shared secret (first 8 bytes): {bytes(ss_bob)[:8].hex()}...")

    # Alice decapsulates ciphertext using her handle and envelope
    ss_alice = (ctypes.c_uint8 * 32)()
    ss_alice_len = ctypes.c_size_t(32)

    rc = lib.PQBLOCKS_KEM_X25519_MLKEM768_decaps(
        alice, ct_buf, ct_len.value,
        envelope_ptr.value,
        ss_alice, ctypes.byref(ss_alice_len)
    )
    assert rc == 0, f"Decapsulation failed: {rc}"
    print(f"[Alice] Decapsulated shared secret (first 8 bytes): {bytes(ss_alice)[:8].hex()}...")

    assert bytes(ss_bob) == bytes(ss_alice), "Shared secrets do not match!"
    print("SUCCESS: Hybrid shared secrets match perfectly.")

    lib.PQBLOCKS_KEM_X25519_MLKEM768_free(alice)
    return 0

if __name__ == "__main__":
    sys.exit(main())
