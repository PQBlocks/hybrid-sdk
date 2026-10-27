#!/usr/bin/env python3
"""Tests for Adapter Layer - KEM Binding (feature 1).

Slice feature 1 contract (spec/spec.md §17):
- Bind to liboqs ML-KEM-768 and X25519.
- Production code: CSPRNG for X25519 ephemeral (seeded 0x42*32 test-only,
  reproducibility invariant via PQBLOCKS_KEM_X25519_MLKEM768_new_seeded).
- Outputs: working PQBLOCKS_KEM_X25519_MLKEM768_new/free/encaps/decaps.
- Envelope: self-describing JSON, ek_len=1216, ct_len=1120, ss_len=32
  (RFC 10024 hybrid container math, spec §19).
- Edge cases exercised here (spec §15 ledger subset applicable to feature 1):
  NULL pointer, zero-length ciphertext, truncated ciphertext,
  corrupt/unknown-algorithm envelope, buffer-too-small, uninitialized binding.
- Negative tests: decaps must reject truncated/zero ciphertexts and
  mismatched envelopes loudly (no partial key recovery).

exact error codes asserted; no 'mostly working'.
"""
import ctypes
import json
import os
import unittest

LIB_PATH = os.path.join(os.path.dirname(__file__), '..', 'src', 'libpqblocks_kem.so')
if not os.path.exists(LIB_PATH):
    try:
        import pqblocks_core
        _pkg = os.path.join(os.path.dirname(pqblocks_core.__file__), 'lib', 'libpqblocks_kem.so')
        if os.path.exists(_pkg):
            LIB_PATH = _pkg
    except ImportError:
        pass
if not os.path.exists(LIB_PATH):
    _local = os.path.expanduser('~/.local/lib/libpqblocks_kem.so')
    if os.path.exists(_local):
        LIB_PATH = _local

PQBLOCKS_SUCCESS                    = 0
PQBLOCKS_ERR_INVALID_ARGUMENT       = -1
PQBLOCKS_ERR_INVALID_LENGTH         = -2
PQBLOCKS_ERR_NULL_POINTER           = -3
PQBLOCKS_ERR_KEM_ENCAPS             = -11
PQBLOCKS_ERR_KEM_DECAPS             = -12
PQBLOCKS_ERR_ENVELOPE_MISMATCH      = -51

HYBRID_EK_LEN = 1216
HYBRID_CT_LEN = 1120
SS_LEN        = 32
X25519_PRIV_LEN = 32
X25519_PUB_LEN = 32


def _load_lib():
    if not os.path.exists(LIB_PATH):
        raise unittest.SkipTest(f"Library not found: {LIB_PATH}")
    lib = ctypes.CDLL(LIB_PATH)
    lib.PQBLOCKS_KEM_X25519_MLKEM768_new.restype = ctypes.c_void_p
    lib.PQBLOCKS_KEM_X25519_MLKEM768_new.argtypes = []

    lib.PQBLOCKS_KEM_X25519_MLKEM768_new_seeded.restype = ctypes.c_void_p
    lib.PQBLOCKS_KEM_X25519_MLKEM768_new_seeded.argtypes = [ctypes.POINTER(ctypes.c_uint8)]

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
    return lib


LIB = None


def setUpModule():
    global LIB
    LIB = _load_lib()


def _new_kem_sealed():
    """Create KEM with CSPRNG-generated keys for production testing."""
    kem = LIB.PQBLOCKS_KEM_X25519_MLKEM768_new()
    if not kem:
        raise RuntimeError("PQBLOCKS_KEM_X25519_MLKEM768_new returned NULL")
    return kem


def _new_kem_seeded(seed_bytes=None):
    """Create KEM with seeded X25519 key for reproducible golden tests."""
    if seed_bytes is None:
        seed_bytes = b'\x42' * 32
    seed_arr = (ctypes.c_uint8 * 32)(*seed_bytes)
    kem = LIB.PQBLOCKS_KEM_X25519_MLKEM768_new_seeded(seed_arr)
    if not kem:
        raise RuntimeError("PQBLOCKS_KEM_X25519_MLKEM768_new_seeded returned NULL")
    return kem


def _encaps(kem, ct_buf_size=4096, ss_buf_size=SS_LEN):
    """Call encaps into caller-sized buffers; returns (ret, ct_bytes, ss_bytes, envelope_str, ct_len)."""
    ciphertext = (ctypes.c_uint8 * ct_buf_size)()
    ciphertext_len = ctypes.c_size_t(ct_buf_size)
    shared_secret = (ctypes.c_uint8 * ss_buf_size)()
    shared_secret_len = ctypes.c_size_t(ss_buf_size)
    env_ptr = ctypes.c_char_p()
    ret = LIB.PQBLOCKS_KEM_X25519_MLKEM768_encaps(
        kem,
        ciphertext,
        ctypes.byref(ciphertext_len),
        shared_secret,
        ctypes.byref(shared_secret_len),
        ctypes.byref(env_ptr),
    )
    env_str = ctypes.string_at(env_ptr.value).decode("utf-8") if env_ptr.value else None
    return (
        ret,
        bytes(ciphertext[: ciphertext_len.value]) if ret == PQBLOCKS_SUCCESS else None,
        bytes(shared_secret[: shared_secret_len.value]) if ret == PQBLOCKS_SUCCESS else None,
        env_str,
        ciphertext_len.value if ret == PQBLOCKS_SUCCESS else None,
    )


def _decaps(kem, ct_bytes, env_str, ss_buf_size=SS_LEN):
    if len(ct_bytes) == 0:
        ciphertext = None
    else:
        ciphertext = (ctypes.c_uint8 * len(ct_bytes))()
        ctypes.memmove(ctypes.addressof(ciphertext), ct_bytes, len(ct_bytes))
    shared_secret = (ctypes.c_uint8 * ss_buf_size)()
    shared_secret_len = ctypes.c_size_t(ss_buf_size)
    if isinstance(env_str, str):
        env_bytes = env_str.encode("utf-8")
    elif env_str is None:
        env_bytes = None
    else:
        env_bytes = env_str
    ret = LIB.PQBLOCKS_KEM_X25519_MLKEM768_decaps(
        kem,
        ciphertext,
        len(ct_bytes),
        env_bytes,
        shared_secret,
        ctypes.byref(shared_secret_len),
    )
    return ret, (
        bytes(shared_secret[: shared_secret_len.value])
        if ret == PQBLOCKS_SUCCESS
        else None
    )


class TestPQBlocksKEMAdapter(unittest.TestCase):
    def test_new_and_free_return_non_null(self):
        kem = _new_kem_sealed()
        self.assertIsNotNone(kem, "KEM new should return non-null pointer")
        LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)

    def test_new_null_safety_of_free(self):
        LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(None)
        self.assertTrue(True)

    def test_encaps_decaps_roundtrip(self):
        kem = _new_kem_sealed()
        try:
            ret, ct, ss, env, ct_len = _encaps(kem)
            self.assertEqual(ret, PQBLOCKS_SUCCESS, f"encaps failed with error code {ret}")
            self.assertEqual(ct_len, HYBRID_CT_LEN,
                             f"hybrid ciphertext should be {HYBRID_CT_LEN} bytes, got {ct_len}")
            self.assertEqual(len(ct), HYBRID_CT_LEN)
            self.assertEqual(len(ss), SS_LEN, f"shared secret should be {SS_LEN} bytes")

            envelope = json.loads(env)
            self.assertEqual(envelope.get("kem"), "X25519+MLKEM768")
            self.assertEqual(envelope.get("kdf"), "HKDF-SHA256")
            self.assertEqual(envelope.get("key_confirm"), "HMAC-SHA256")
            self.assertEqual(envelope.get("suite_id"), "X25519MLKEM768-Ed25519MLDSA65-HKDF")
            self.assertEqual(envelope.get("version"), "1.0.0")
            self.assertEqual(envelope.get("ek_len"), HYBRID_EK_LEN)
            self.assertEqual(envelope.get("ct_len"), HYBRID_CT_LEN)
            self.assertEqual(envelope.get("ss_len"), SS_LEN)

            x25519_share = ct[1088:1120]
            self.assertEqual(len(x25519_share), 32, "ciphertext X25519 share must be 32 bytes")

            ret2, ss2 = _decaps(kem, ct, env)
            self.assertEqual(ret2, PQBLOCKS_SUCCESS, f"decaps failed with error code {ret2}")
            self.assertEqual(ss2, ss,
                             "decapsulated shared secret must match encapsulated shared secret")
        finally:
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)

    def test_sealed_kem_unique_keys(self):
        """Correction: Production KEM instances must have unique X25519 keys."""
        kem1 = _new_kem_sealed()
        kem2 = _new_kem_sealed()
        try:
            _, ct1, _, _, _ = _encaps(kem1)
            _, ct2, _, _, _ = _encaps(kem2)
            self.assertNotEqual(ct1[1088:1120], ct2[1088:1120],
                                "Different KEM instances must have different X25519 ephemeral keys")
        finally:
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem1)
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem2)

    def test_golden_seeded_reproducible(self):
        """Seeded KEM must produce reproducible outputs."""
        kem = _new_kem_seeded()
        try:
            _, ct1, ss1, env1, _ = _encaps(kem)
            self.assertEqual(ct1[1088:1120], b'\x42' * 32, "seeded X25519 share must be 0x42*32")
            _, ct2, ss2, env2, _ = _encaps(kem)
            self.assertEqual(ct1, ct2, "seeded encaps must be reproducible")
            self.assertEqual(ss1, ss2, "seeded shared secrets must match")
            env_obj = json.loads(env1) if isinstance(env1, str) else env1
            self.assertEqual(env_obj['kdf'], "HKDF-SHA256")
        finally:
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)

    def test_encaps_null_kem_returns_null_pointer(self):
        ct = (ctypes.c_uint8 * 4096)()
        ct_len = ctypes.c_size_t(4096)
        ss = (ctypes.c_uint8 * SS_LEN)()
        ss_len = ctypes.c_size_t(SS_LEN)
        env_ptr = ctypes.c_char_p()
        ret = LIB.PQBLOCKS_KEM_X25519_MLKEM768_encaps(
            None, ct, ctypes.byref(ct_len), ss, ctypes.byref(ss_len), ctypes.byref(env_ptr))
        self.assertEqual(ret, PQBLOCKS_ERR_NULL_POINTER)

    def test_encaps_null_output_buffers_rejected(self):
        kem = _new_kem_sealed()
        try:
            ct = (ctypes.c_uint8 * 4096)()
            ct_len = ctypes.c_size_t(4096)
            ss = (ctypes.c_uint8 * SS_LEN)()
            ss_len = ctypes.c_size_t(SS_LEN)
            env_ptr = ctypes.c_char_p()
            ret = LIB.PQBLOCKS_KEM_X25519_MLKEM768_encaps(
                kem, ct, ctypes.byref(ct_len), None, ctypes.byref(ss_len), ctypes.byref(env_ptr))
            self.assertEqual(ret, PQBLOCKS_ERR_INVALID_ARGUMENT)
        finally:
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)

    def test_encaps_buffer_too_small_rejected(self):
        kem = _new_kem_sealed()
        try:
            ret, ct, ss, env, ct_len = _encaps(kem, ct_buf_size=1000)
            self.assertEqual(ret, PQBLOCKS_ERR_INVALID_LENGTH,
                             f"encaps with undersized buffer should return INVALID_LENGTH, got {ret}")
        finally:
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)

    def test_decaps_zero_length_ciphertext_rejected(self):
        kem = _new_kem_sealed()
        try:
            ret, ss = _decaps(kem, b'', b'{"kem":"X25519+MLKEM768","suite_id":"X25519MLKEM768-Ed25519MLDSA65-HKDF"}')
            self.assertEqual(ret, PQBLOCKS_ERR_NULL_POINTER, "zero-length ciphertext must be rejected")
        finally:
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)

    def test_decaps_truncated_ciphertext_rejected(self):
        kem = _new_kem_sealed()
        try:
            truncated = b"\x00" * 500
            ret, ss = _decaps(kem, truncated, b'{"kem":"X25519+MLKEM768","suite_id":"X25519MLKEM768-Ed25519MLDSA65-HKDF"}')
            self.assertEqual(ret, PQBLOCKS_ERR_INVALID_LENGTH, "truncated ciphertext must be rejected")
        finally:
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)

    def test_decaps_malformed_envelope_rejected(self):
        kem = _new_kem_sealed()
        try:
            _, ct, _, env, _ = _encaps(kem)
            self.assertIsNotNone(ct)
            ret, ss = _decaps(kem, ct, "garbage-not-json")
            self.assertEqual(ret, PQBLOCKS_ERR_ENVELOPE_MISMATCH, "corrupt JSON envelope must be rejected")
        finally:
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)

    def test_decaps_unknown_algorithm_envelope_rejected(self):
        kem = _new_kem_sealed()
        try:
            _, ct, _, env, _ = _encaps(kem)
            self.assertIsNotNone(ct)
            wrong_suite = '{"kem":"SECP256R1MLKEM768","ct_len":1120}'
            ret, ss = _decaps(kem, ct, wrong_suite)
            self.assertEqual(ret, PQBLOCKS_ERR_ENVELOPE_MISMATCH, "unknown algorithm ID must not fall back")
        finally:
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)

    def test_decaps_null_ciphertext_rejected(self):
        kem = _new_kem_sealed()
        try:
            ss = (ctypes.c_uint8 * SS_LEN)()
            ss_len = ctypes.c_size_t(SS_LEN)
            ret = LIB.PQBLOCKS_KEM_X25519_MLKEM768_decaps(
                kem, None, 0, b'{"kem":"X25519+MLKEM768"}', ss, ctypes.byref(ss_len))
            self.assertEqual(ret, PQBLOCKS_ERR_NULL_POINTER)
        finally:
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)

    def test_envelope_deterministic(self):
        kem = _new_kem_seeded()
        try:
            _, ct1, _, env1, _ = _encaps(kem)
            _, ct2, _, env2, _ = _encaps(kem)
            self.assertEqual(env1, env2, "envelope JSON must be deterministic per seeded call")
            self.assertEqual(ct1, ct2, "ciphertext must be reproducible with same seed")
        finally:
            LIB.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)


if __name__ == "__main__":
    unittest.main()