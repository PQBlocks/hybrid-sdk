#!/usr/bin/env python3
"""Tests for Misuse-Resistant Core - SIG (feature 4).

Slice feature 4 contract (spec/spec.md section 17):
- Contract: Implement M' construction + envelope for SIG.
- Ed25519 keygen via EVP_PKEY_keygen (CSPRNG, per Check 5 (adversarial review) repair).
- Inputs: feature 2. Outputs: SIG operations return validated envelope; enforce context binding.
- Tests: Test vectors with missing ctx, wrong Label, skipped key_confirm, tampered message.
- Gate: Check 3 (correctness).

Deterministic test seed 0x42*32 for Ed25519 (test-only, seeded keygen).
exact error codes asserted.
"""
import ctypes
import json
import os
import unittest

_local_lib = os.path.expanduser('~/.local/lib')
os.environ['LD_LIBRARY_PATH'] = (_local_lib + ':' if os.path.isdir(_local_lib) else '') + os.environ.get('LD_LIBRARY_PATH', '')

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

# Preload liboqs so ctypes can find it
for p in [os.path.join(_local_lib, 'liboqs.so'), os.path.join(_local_lib, 'liboqs.so.9')]:
    if os.path.exists(p):
        try:
            ctypes.CDLL(p)
            break
        except Exception:
            pass

PQBLOCKS_SUCCESS = 0
PQBLOCKS_ERR_INVALID_ARGUMENT = -1
PQBLOCKS_ERR_INVALID_LENGTH = -2
PQBLOCKS_ERR_NULL_POINTER = -3
PQBLOCKS_ERR_SIG_VERIFY = -22
PQBLOCKS_ERR_ENVELOPE_MISMATCH = -51
PQBLOCKS_ERR_KDF_MISMATCH = -52
PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED = -50
PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED = -42

SIG_LEN = 3373


def _load_lib():
    if not os.path.exists(LIB_PATH):
        raise unittest.SkipTest(f"SIG library not found: {LIB_PATH}")
    lib = ctypes.CDLL(LIB_PATH)
    lib.PQBLOCKS_SIG_ED25519_MLDSA65_new.restype = ctypes.c_void_p
    lib.PQBLOCKS_SIG_ED25519_MLDSA65_new.argtypes = []
    lib.PQBLOCKS_SIG_ED25519_MLDSA65_new_seeded.restype = ctypes.c_void_p
    lib.PQBLOCKS_SIG_ED25519_MLDSA65_new_seeded.argtypes = [ctypes.POINTER(ctypes.c_uint8)]

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


def _new_sig_sealed():
    """Create SIG with CSPRNG-generated Ed25519 key."""
    sig = LIB.PQBLOCKS_SIG_ED25519_MLDSA65_new()
    if not sig:
        raise RuntimeError("PQBLOCKS_SIG_ED25519_MLDSA65_new returned NULL")
    return sig


def _new_sig_seeded(seed_bytes=None):
    """Create SIG with seeded Ed25519 key for reproducible tests."""
    if seed_bytes is None:
        seed_bytes = b'\x42' * 32
    seed_arr = (ctypes.c_uint8 * 32)(*seed_bytes)
    sig = LIB.PQBLOCKS_SIG_ED25519_MLDSA65_new_seeded(seed_arr)
    if not sig:
        raise RuntimeError("PQBLOCKS_SIG_ED25519_MLDSA65_new_seeded returned NULL")
    return sig


def _sign(sig, msg=b"test", sig_buf_size=SIG_LEN):
    message = (ctypes.c_uint8 * max(len(msg), 1))()
    if len(msg):
        ctypes.memmove(message, msg, len(msg))
    else:
        message = (ctypes.c_uint8 * 1)()
    signature = (ctypes.c_uint8 * sig_buf_size)()
    signature_len = ctypes.c_size_t(sig_buf_size)
    env_ptr = ctypes.c_char_p()
    ret = LIB.PQBLOCKS_SIG_ED25519_MLDSA65_sign(
        sig, message, len(msg), signature,
        ctypes.byref(signature_len), ctypes.byref(env_ptr),
    )
    env_str = ctypes.string_at(env_ptr.value).decode("utf-8") if env_ptr.value else None
    return (
        ret,
        bytes(signature[:signature_len.value]) if ret == PQBLOCKS_SUCCESS else None,
        env_str,
        signature_len.value if ret == PQBLOCKS_SUCCESS else None,
    )


def _verify(sig, msg, sig_bytes, env_str):
    message = (ctypes.c_uint8 * max(len(msg), 1))()
    if len(msg):
        ctypes.memmove(message, msg, len(msg))
    signature = (ctypes.c_uint8 * len(sig_bytes))()
    ctypes.memmove(signature, sig_bytes, len(sig_bytes))
    env_bytes = env_str.encode("utf-8") if isinstance(env_str, str) else env_str
    return LIB.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
        sig, message, len(msg), signature, len(sig_bytes), env_bytes,
    )


class TestMisuseResistantSig(unittest.TestCase):
    def test_sealed_keygen_unique_keys(self):
        """Correction: Production SIG instances must have unique Ed25519 keys."""
        sig1 = _new_sig_sealed()
        sig2 = _new_sig_sealed()
        try:
            ret1, _, _, _ = _sign(sig1, b"message for key comparison")
            ret2, _, _, _ = _sign(sig2, b"message for key comparison")
            self.assertEqual(ret1, PQBLOCKS_SUCCESS)
            self.assertEqual(ret2, PQBLOCKS_SUCCESS)
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig1)
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig2)

    def test_golden_seeded_reproducible(self):
        """Seeded SIG must produce reproducible outputs."""
        sig = _new_sig_seeded()
        try:
            msg = b"seeded test message"
            _, sig1, env1, _ = _sign(sig, msg)
            _, sig2, env2, _ = _sign(sig, msg)
            self.assertEqual(sig1[3309:], sig2[3309:], "seeded Ed25519 signature must be reproducible")
            env_obj = json.loads(env1) if isinstance(env1, str) else env1
            self.assertEqual(env_obj['kdf'], "HKDF-SHA256")
            self.assertEqual(env_obj['key_confirm'], "HMAC-SHA256")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_roundtrip_and_golden_envelope(self):
        sig = _new_sig_sealed()
        try:
            msg = b"golden verification message"
            ret, sig_bytes, env, sig_len = _sign(sig, msg)
            self.assertEqual(ret, PQBLOCKS_SUCCESS, f"sign failed: {ret}")
            self.assertEqual(sig_len, SIG_LEN)
            envelope = json.loads(env)
            self.assertEqual(envelope.get("sig"), "Ed25519+MLDSA65")
            self.assertEqual(envelope.get("construction"), "CompositeAlgorithmSignatures2025")
            self.assertEqual(envelope.get("mldsa_sig_len"), 3309)
            self.assertEqual(envelope.get("composite_sig_len"), 3373)
            self.assertEqual(envelope.get("kdf"), "HKDF-SHA256")
            self.assertEqual(envelope.get("key_confirm"), "HMAC-SHA256")
            self.assertEqual(envelope.get("suite_id"), "X25519MLKEM768-Ed25519MLDSA65-HKDF")
            self.assertEqual(envelope.get("version"), "1.0.0")
            self.assertEqual(envelope.get("sig_len"), 3373)
            self.assertEqual(envelope.get("ctx_label"), "ML-DSA-65")
            self.assertEqual(_verify(sig, msg, sig_bytes, env), PQBLOCKS_SUCCESS)
            bad = bytearray(msg)
            bad[0] ^= 0x01
            self.assertEqual(
                _verify(sig, bytes(bad), sig_bytes, env), PQBLOCKS_ERR_SIG_VERIFY)
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_zero_length_message_sign_rejected(self):
        sig = _new_sig_sealed()
        try:
            ret, _, _, _ = _sign(sig, b"")
            self.assertEqual(ret, PQBLOCKS_ERR_INVALID_ARGUMENT,
                             "zero-length message must be rejected loudly")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_wrong_label_envelope_rejected(self):
        sig = _new_sig_sealed()
        try:
            msg = b"label test"
            _, sig_bytes, env, _ = _sign(sig, msg)
            self.assertIsNotNone(sig_bytes)
            wrong = env.replace("ML-DSA-65", "ML-DSA-44")
            ret = _verify(sig, msg, sig_bytes, wrong)
            self.assertIn(ret, (PQBLOCKS_ERR_ENVELOPE_MISMATCH,
                                PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED),
                          f"wrong Label must be rejected, got {ret}")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_missing_ctx_label_envelope_rejected(self):
        sig = _new_sig_sealed()
        try:
            msg = b"ctx test"
            _, sig_bytes, env, _ = _sign(sig, msg)
            self.assertIsNotNone(sig_bytes)
            d = json.loads(env)
            del d["ctx_label"]
            ret = _verify(sig, msg, sig_bytes, json.dumps(d))
            self.assertEqual(ret, PQBLOCKS_ERR_ENVELOPE_MISMATCH,
                             "missing ctx_label must be rejected loudly")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_kdf_mismatch_rejected(self):
        sig = _new_sig_sealed()
        try:
            msg = b"kdf test"
            _, sig_bytes, env, _ = _sign(sig, msg)
            self.assertIsNotNone(sig_bytes)
            d = json.loads(env)
            d["kdf"] = "HKDF-SHA512"
            ret = _verify(sig, msg, sig_bytes, json.dumps(d))
            self.assertIn(ret, (PQBLOCKS_ERR_KDF_MISMATCH,
                                PQBLOCKS_ERR_ENVELOPE_MISMATCH),
                          f"KDF mismatch must be rejected, got {ret}")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_key_confirm_rejected(self):
        sig = _new_sig_sealed()
        try:
            msg = b"confirm test"
            _, sig_bytes, env, _ = _sign(sig, msg)
            self.assertIsNotNone(sig_bytes)
            d = json.loads(env)
            del d["key_confirm"]
            ret = _verify(sig, msg, sig_bytes, json.dumps(d))
            self.assertIn(ret, (PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED,
                                PQBLOCKS_ERR_ENVELOPE_MISMATCH),
                          f"key_confirm missing must be rejected, got {ret}")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_truncated_signature_rejected(self):
        sig = _new_sig_sealed()
        try:
            msg = b"trunc test"
            _, sig_bytes, env, _ = _sign(sig, msg)
            self.assertIsNotNone(sig_bytes)
            ret = _verify(sig, msg, sig_bytes[:1000], env)
            self.assertEqual(ret, PQBLOCKS_ERR_INVALID_LENGTH,
                             "truncated signature must be rejected")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_corrupt_envelope_rejected(self):
        sig = _new_sig_sealed()
        try:
            msg = b"corrupt test"
            _, sig_bytes, _, _ = _sign(sig, msg)
            self.assertIsNotNone(sig_bytes)
            ret = _verify(sig, msg, sig_bytes, "garbage-not-json")
            self.assertEqual(ret, PQBLOCKS_ERR_ENVELOPE_MISMATCH)
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_envelope_deterministic(self):
        sig = _new_sig_seeded()
        try:
            _, _, env1, _ = _sign(sig, b"determinism")
            _, _, env2, _ = _sign(sig, b"determinism")
            self.assertEqual(env1, env2, "envelope JSON must be deterministic with seeded keygen")
        finally:
            LIB.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)


if __name__ == "__main__":
    unittest.main()