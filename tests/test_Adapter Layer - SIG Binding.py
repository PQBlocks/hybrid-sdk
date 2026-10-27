#!/usr/bin/env python3
"""
Tests for Adapter Layer - SIG Binding (feature 2).

Slice feature 2 contract (spec/spec.md §17):
- Bind to liboqs/OpenSSL ML-DSA-65 and Ed25519
- Inputs: feature 1
- Outputs: Working PQBLOCKS_SIG_ED25519_MLDSA65_new/free/sign/verify
- Tests: Validate against FIPS 204 ML-DSA-65 KATs
- Gate: Check 3 (correctness) (pq-verifier)

exact error codes asserted; no 'mostly working'.
"""
import ctypes
import json
import os
import unittest

# Set library path for shared library loading
_local_lib = os.path.expanduser('~/.local/lib')
os.environ['LD_LIBRARY_PATH'] = (_local_lib + ':' if os.path.isdir(_local_lib) else '') + os.environ.get('LD_LIBRARY_PATH', '')

# Path to the shared library
LIB_PATH = os.path.join(os.path.dirname(__file__), '..', 'src', 'libpqblocks_sig.so')
if not os.path.exists(LIB_PATH):
    try:
        import pqblocks_core
        _pkg = os.path.join(os.path.dirname(pqblocks_core.__file__), 'lib', 'libpqblocks_sig.so')
        if os.path.exists(_pkg):
            LIB_PATH = _pkg
    except ImportError:
        pass
if not os.path.exists(LIB_PATH):
    _local = os.path.expanduser('~/.local/lib/libpqblocks_sig.so')
    if os.path.exists(_local):
        LIB_PATH = _local

# Spec §7 error taxonomy
PQBLOCKS_SUCCESS                    = 0
PQBLOCKS_ERR_INVALID_ARGUMENT       = -1
PQBLOCKS_ERR_INVALID_LENGTH         = -2
PQBLOCKS_ERR_NULL_POINTER           = -3
PQBLOCKS_ERR_SIG_KEYGEN            = -20
PQBLOCKS_ERR_SIG_SIGN              = -21
PQBLOCKS_ERR_SIG_VERIFY            = -22
PQBLOCKS_ERR_ENVELOPE_MISMATCH      = -51

# Spec §19 container lengths (signature)
SIG_LEN        = 3373  # 3309 ML-DSA-65 + 64 Ed25519

def _load_lib():
    if not os.path.exists(LIB_PATH):
        raise unittest.SkipTest(f"Library not found: {LIB_PATH}")
    lib = ctypes.CDLL(LIB_PATH)
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
    return lib

LIB = None

def setUpModule():
    global LIB
    LIB = _load_lib()

def _new_sig():
    sig = LIB.PQBLOCKS_SIG_ED25519_MLDSA65_new()
    if not sig:
        raise RuntimeError("PQBLOCKS_SIG_ED25519_MLDSA65_new returned NULL "
                           "(liboqs unavailable or keygen failed)")
    return sig

def _sign(sig, msg=b"test", msg_buf_size=4096, sig_buf_size=SIG_LEN):
    """Call sign into caller-sized buffers; returns (sig_bytes, envelope_str)."""
    message = (ctypes.c_uint8 * msg_buf_size)()
    if len(msg) > msg_buf_size:
        raise ValueError("Message too long for buffer")
    ctypes.memmove(message, msg, len(msg))
    signature = (ctypes.c_uint8 * sig_buf_size)()
    signature_len = ctypes.c_size_t(sig_buf_size)
    env_ptr = ctypes.c_char_p()
    ret = LIB.PQBLOCKS_SIG_ED25519_MLDSA65_sign(
        sig,
        message,
        len(msg),
        signature,
        ctypes.byref(signature_len),
        ctypes.byref(env_ptr),
    )
    env_str = ctypes.string_at(env_ptr.value).decode("utf-8") if env_ptr.value else None
    return (
        ret,
        bytes(signature[: signature_len.value]) if ret == PQBLOCKS_SUCCESS else None,
        env_str,
        signature_len.value if ret == PQBLOCKS_SUCCESS else None,
    )

def _verify(sig, msg, sig_bytes, env_str):
    """Call verify; returns ret."""
    message = (ctypes.c_uint8 * len(msg))()
    ctypes.memmove(message, msg, len(msg))
    signature = (ctypes.c_uint8 * len(sig_bytes))()
    ctypes.memmove(signature, sig_bytes, len(sig_bytes))
    env_bytes = env_str.encode("utf-8") if isinstance(env_str, str) else env_str
    ret = LIB.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
        sig,
        message,
        len(msg),
        signature,
        len(sig_bytes),
        env_bytes,
    )
    return ret

class TestPQBlocksSigAdapter(unittest.TestCase):
    def test_new_and_free_return_non_null(self):
        sig = _new_sig()
        self.assertIsNotNone(sig, "SIG new should return non-null pointer")
        LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_new_null_safety_of_free(self):
        # free(NULL) must be a safe no-op
        LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(None)
        self.assertTrue(True)

    def test_sign_verify_roundtrip(self):
        sig = _new_sig()
        try:
            msg = b"test message"
            ret, sig_bytes, env, sig_len = _sign(sig, msg)
            self.assertEqual(ret, PQBLOCKS_SUCCESS, f"sign failed with error code {ret}")
            self.assertEqual(sig_len, SIG_LEN,
                             f"signature should be {SIG_LEN} bytes, got {sig_len}")
            self.assertEqual(len(sig_bytes), SIG_LEN)

            # Envelope is parseable JSON with required fields (spec §8 golden fields)
            envelope = json.loads(env)
            self.assertEqual(envelope.get("sig"), "Ed25519+MLDSA65")
            self.assertEqual(envelope.get("construction"), "CompositeAlgorithmSignatures2025")
            self.assertEqual(envelope.get("mldsa_sig_len"), 3309)
            self.assertEqual(envelope.get("composite_sig_len"), 3373)
            self.assertEqual(envelope.get("euf_cma"), True)
            self.assertEqual(envelope.get("suf_cma"), False)

            # Verify with the same sig object must succeed
            ret2 = _verify(sig, msg, sig_bytes, env)
            self.assertEqual(ret2, PQBLOCKS_SUCCESS,
                             f"verify failed with error code {ret2}")

            # Verify with a tampered message must fail
            tampered = msg + b"x"
            ret3 = _verify(sig, tampered, sig_bytes, env)
            self.assertEqual(ret3, PQBLOCKS_ERR_SIG_VERIFY,
                             "verify must fail on tampered message")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_sign_null_sig_returns_null_pointer(self):
        msg = b"test"
        msg_buf = (ctypes.c_uint8 * 4096)()
        sig_buf = (ctypes.c_uint8 * SIG_LEN)()
        sig_len = ctypes.c_size_t(SIG_LEN)
        env_ptr = ctypes.c_char_p()
        ret = LIB.PQBLOCKS_SIG_ED25519_MLDSA65_sign(
            None, msg_buf, len(msg), sig_buf, ctypes.byref(sig_len), ctypes.byref(env_ptr))
        self.assertEqual(ret, PQBLOCKS_ERR_NULL_POINTER)

    def test_sign_null_output_buffers_rejected(self):
        sig = _new_sig()
        try:
            msg = b"test"
            msg_buf = (ctypes.c_uint8 * 4096)()
            sig_len = ctypes.c_size_t(SIG_LEN)
            env_ptr = ctypes.c_char_p()
            # NULL signature out buffer
            ret = LIB.PQBLOCKS_SIG_ED25519_MLDSA65_sign(
                sig, msg_buf, len(msg), None, ctypes.byref(sig_len), ctypes.byref(env_ptr))
            self.assertEqual(ret, PQBLOCKS_ERR_INVALID_ARGUMENT)
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_sign_buffer_too_small_rejected(self):
        sig = _new_sig()
        try:
            # Buffer smaller than required SIG_LEN (3373)
            ret, sig_bytes, env, sig_len = _sign(sig, b"test", sig_buf_size=1000)
            self.assertEqual(ret, PQBLOCKS_ERR_INVALID_LENGTH,
                             f"sign with undersized buffer should return INVALID_LENGTH, got {ret}")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_verify_null_sig_returns_null_pointer(self):
        msg = b"test"
        sig_buf = (ctypes.c_uint8 * SIG_LEN)()
        # Null sig object pointer
        ret = LIB.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
            None,
            (ctypes.c_uint8 * len(msg))(),
            len(msg),
            sig_buf,
            SIG_LEN,
            b"{\"sig\":\"Ed25519+MLDSA65\"}",
        )
        self.assertEqual(ret, PQBLOCKS_ERR_NULL_POINTER)

    def test_verify_null_message_rejected(self):
        sig = _new_sig()
        try:
            sig_buf = (ctypes.c_uint8 * SIG_LEN)()
            ret = LIB.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
                sig, None, 0, sig_buf, SIG_LEN,
                b"{\"sig\":\"Ed25519+MLDSA65\"}",
            )
            self.assertEqual(ret, PQBLOCKS_ERR_NULL_POINTER)
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_verify_buffer_too_small_rejected(self):
        sig = _new_sig()
        try:
            # Signature buffer too small
            ret = LIB.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
                sig,
                (ctypes.c_uint8 * 4)(),
                4,
                (ctypes.c_uint8 * 1000)(),  # too small
                1000,
                b"{\"sig\":\"Ed25519+MLDSA65\"}",
            )
            self.assertEqual(ret, PQBLOCKS_ERR_INVALID_LENGTH)
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_verify_malformed_envelope_rejected(self):
        sig = _new_sig()
        try:
            # Produce a valid sig/env first
            _, sig_bytes, env, _ = _sign(sig, b"test")
            self.assertIsNotNone(sig_bytes)
            # Feed a corrupted envelope (missing suite field / garbage JSON)
            ret = _verify(sig, b"test", sig_bytes, "garbage-not-json")
            self.assertEqual(ret, PQBLOCKS_ERR_ENVELOPE_MISMATCH,
                             "corrupt JSON envelope must be rejected loudly")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_verify_unknown_algorithm_envelope_rejected(self):
        sig = _new_sig()
        try:
            _, sig_bytes, env, _ = _sign(sig, b"test")
            self.assertIsNotNone(sig_bytes)
            wrong_suite = '{"sig":"SECP256R1MLDSA65","composite_sig_len":3373}'
            ret = _verify(sig, b"test", sig_bytes, wrong_suite)
            self.assertEqual(ret, PQBLOCKS_ERR_ENVELOPE_MISMATCH,
                             "unknown algorithm ID must not fall back to unlisted suite")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

if __name__ == "__main__":
    unittest.main()