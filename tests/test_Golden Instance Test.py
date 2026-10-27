#!/usr/bin/env python3
"""feature 11 Golden Instance Test — Fixed-seed KEM encaps/decaps and SIG sign/verify.

Contract per spec §16 [feature 11]:
- Contract: Implement golden test that seeds KEM keygen→encaps→decaps and SIG
  keygen→sign→verify with seed 0x42×32; assert ciphertext length=1120,
  shared_secret length=32, signature length=3373, envelope JSON contains all
  required fields.
- Inputs: feature 3, feature 4 (misuse-resistant core implementations).
- Outputs: test/golden/ directory with pinned byte-level expected outputs;
  `make check` runs golden test and all assertions pass.
- Tests: Golden test must pass on reference implementation; byte-identical
  reruns with same seed; round-trip decapsulation recovers shared secret;
  single-byte-altered message fails verification.
- Gate: Check 3 (correctness) (pq-verifier).
"""
import base64
import ctypes
import hashlib
import json
import os
import unittest

# Pre-load liboqs from ~/.local/lib to ensure dynamic linker resolves it
_local_lib = os.path.expanduser('~/.local/lib')
for p in [os.path.join(_local_lib, 'liboqs.so'), os.path.join(_local_lib, 'liboqs.so.9')]:
    if os.path.exists(p):
        try:
            ctypes.CDLL(p)
            break
        except Exception:
            pass

HERE = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(HERE, '..', 'src')
GOLDEN_DIR = os.path.join(HERE, 'golden')
if not os.path.isdir(GOLDEN_DIR):
    GOLDEN_DIR = os.path.join(HERE, '..', 'test', 'golden')

def _find_lib(name):
    candidates = [
        os.path.join(SRC_DIR, name),
        os.path.join(SRC_DIR, 'pqblocks_core', 'lib', name),
        os.path.join(_local_lib, name),
    ]
    try:
        import pqblocks_core
        candidates.insert(0, os.path.join(os.path.dirname(pqblocks_core.__file__), 'lib', name))
    except ImportError:
        pass
    for c in candidates:
        if os.path.isfile(c):
            return c
    return os.path.join(SRC_DIR, name)

KEM_LIB_PATH = _find_lib('libpqblocks_kem.so')
SIG_LIB_PATH = _find_lib('libpqblocks_sig.so')

# Spec §7 error codes
PQBLOCKS_SUCCESS = 0
PQBLOCKS_ERR_SIG_VERIFY = -22

# Spec §8 expected lengths
HYBRID_EK_LEN = 1216
HYBRID_CT_LEN = 1120
SS_LEN = 32
COMPOSITE_SIG_LEN = 3373


def _load_kem_lib():
    if not os.path.exists(KEM_LIB_PATH):
        raise unittest.SkipTest(f"KEM library not found: {KEM_LIB_PATH}")
    lib = ctypes.CDLL(KEM_LIB_PATH)
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

    lib.PQBLOCKS_KEM_X25519_MLKEM768_export_keys.restype = ctypes.c_int
    lib.PQBLOCKS_KEM_X25519_MLKEM768_export_keys.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
        ctypes.POINTER(ctypes.c_size_t),
    ]

    lib.PQBLOCKS_KEM_X25519_MLKEM768_import_keys.restype = ctypes.c_int
    lib.PQBLOCKS_KEM_X25519_MLKEM768_import_keys.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
    ]
    return lib


def _load_sig_lib():
    if not os.path.exists(SIG_LIB_PATH):
        raise unittest.SkipTest(f"SIG library not found: {SIG_LIB_PATH}")
    lib = ctypes.CDLL(SIG_LIB_PATH)
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

    lib.PQBLOCKS_SIG_ED25519_MLDSA65_import_keys.restype = ctypes.c_int
    lib.PQBLOCKS_SIG_ED25519_MLDSA65_import_keys.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
    ]
    return lib


class TestGoldenInstanceKEM(unittest.TestCase):
    """feature 11 Golden instance tests for KEM operations."""

    @classmethod
    def setUpClass(cls):
        cls.kem_lib = _load_kem_lib()

    def test_golden_directory_and_artifacts_exist(self):
        """feature 11 Contract: test/golden/ directory exists with pinned files."""
        self.assertTrue(os.path.isdir(GOLDEN_DIR), f"{GOLDEN_DIR} must exist")
        for fname in ['kem.json', 'encaps.json', 'shared.key', 'sig.json', 'sig.bin']:
            fpath = os.path.join(GOLDEN_DIR, fname)
            self.assertTrue(os.path.isfile(fpath), f"Golden artifact {fname} missing")
            self.assertGreater(os.path.getsize(fpath), 0, f"Golden artifact {fname} is empty")

    def test_golden_key_lengths_pinned(self):
        """feature 11 Contract: shared.key is 32 B, sig.bin is 3373 B."""
        key_path = os.path.join(GOLDEN_DIR, 'shared.key')
        sig_path = os.path.join(GOLDEN_DIR, 'sig.bin')
        self.assertEqual(os.path.getsize(key_path), SS_LEN, "shared.key must be 32 bytes")
        self.assertEqual(os.path.getsize(sig_path), COMPOSITE_SIG_LEN, "sig.bin must be 3373 bytes")

    def test_golden_envelope_fields(self):
        """feature 11 Contract: Envelope JSON contains all required fields per spec §8."""
        encaps_path = os.path.join(GOLDEN_DIR, 'encaps.json')
        with open(encaps_path, 'r') as f:
            env = json.load(f)

        required_fields = {
            'kem': 'X25519+MLKEM768',
            'kdf': 'HKDF-SHA256',
            'key_confirm': 'HMAC-SHA256',
            'suite_id': 'X25519MLKEM768-Ed25519MLDSA65-HKDF',
            'version': '1.0.0',
            'ek_len': HYBRID_EK_LEN,
            'ct_len': HYBRID_CT_LEN,
        }
        for k, v in required_fields.items():
            self.assertEqual(env.get(k), v, f"Envelope field {k} mismatch: {env.get(k)} != {v}")

    def test_kem_encaps_lengths_and_roundtrip(self):
        """feature 11 Contract: ct_len=1120, ss_len=32, decaps recovers shared secret."""
        kem = self.kem_lib.PQBLOCKS_KEM_X25519_MLKEM768_new()
        self.assertIsNotNone(kem)

        try:
            ct = (ctypes.c_uint8 * HYBRID_CT_LEN)()
            ct_len = ctypes.c_size_t(HYBRID_CT_LEN)
            ss_enc = (ctypes.c_uint8 * SS_LEN)()
            ss_enc_len = ctypes.c_size_t(SS_LEN)
            env_ptr = ctypes.c_char_p()

            res = self.kem_lib.PQBLOCKS_KEM_X25519_MLKEM768_encaps(
                kem, ct, ctypes.byref(ct_len),
                ss_enc, ctypes.byref(ss_enc_len),
                ctypes.byref(env_ptr)
            )
            self.assertEqual(res, PQBLOCKS_SUCCESS, "Encapsulation failed")
            self.assertEqual(ct_len.value, HYBRID_CT_LEN, f"Ciphertext must be {HYBRID_CT_LEN} B")
            self.assertEqual(ss_enc_len.value, SS_LEN, f"Shared secret must be {SS_LEN} B")
            self.assertIsNotNone(env_ptr.value)

            env_str = env_ptr.value.decode('utf-8')
            env_obj = json.loads(env_str)
            self.assertEqual(env_obj.get('kem'), 'X25519+MLKEM768')
            self.assertEqual(env_obj.get('ct_len'), HYBRID_CT_LEN)
            self.assertEqual(env_obj.get('ek_len'), HYBRID_EK_LEN)

            # Decapsulate round-trip
            ss_dec = (ctypes.c_uint8 * SS_LEN)()
            ss_dec_len = ctypes.c_size_t(SS_LEN)
            dec_res = self.kem_lib.PQBLOCKS_KEM_X25519_MLKEM768_decaps(
                kem, ct, ct_len.value, env_ptr.value,
                ss_dec, ctypes.byref(ss_dec_len)
            )
            self.assertEqual(dec_res, PQBLOCKS_SUCCESS, "Decapsulation failed")
            self.assertEqual(ss_dec_len.value, SS_LEN)

            enc_bytes = bytes(ss_enc)
            dec_bytes = bytes(ss_dec)
            self.assertEqual(enc_bytes, dec_bytes, "Decapsulated shared secret does not match encaps")
            self.assertEqual(
                hashlib.sha256(enc_bytes).hexdigest(),
                hashlib.sha256(dec_bytes).hexdigest(),
                "SHA256 equality of shared secret failed"
            )
        finally:
            self.kem_lib.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)

    def test_golden_instance_decaps_matches_pinned_key(self):
        """feature 11 Contract: Decapsulating committed encaps.json recovers pinned shared.key."""
        encaps_path = os.path.join(GOLDEN_DIR, 'encaps.json')
        key_path = os.path.join(GOLDEN_DIR, 'shared.key')
        with open(encaps_path, 'r') as f:
            data = json.load(f)
        with open(key_path, 'rb') as f:
            expected_key = f.read()

        ct_bytes = base64.b64decode(data['ct_b64'])
        ek_bytes = base64.b64decode(data['ek_b64'])
        dk_bytes = base64.b64decode(data['dk_b64'])
        x25519_bytes = base64.b64decode(data['x25519_pub_b64'])

        self.assertEqual(len(ct_bytes), HYBRID_CT_LEN)
        self.assertEqual(len(expected_key), SS_LEN)

        kem = self.kem_lib.PQBLOCKS_KEM_X25519_MLKEM768_new()
        self.assertIsNotNone(kem)

        try:
            import_res = self.kem_lib.PQBLOCKS_KEM_X25519_MLKEM768_import_keys(
                kem,
                (ctypes.c_uint8 * len(ek_bytes))(*ek_bytes), len(ek_bytes),
                (ctypes.c_uint8 * len(dk_bytes))(*dk_bytes), len(dk_bytes),
                (ctypes.c_uint8 * len(x25519_bytes))(*x25519_bytes), len(x25519_bytes),
            )
            self.assertEqual(import_res, PQBLOCKS_SUCCESS)

            # Recreate canonical envelope JSON string for decaps
            env_json = (
                f'{{"kem":"{data["kem"]}","kdf":"{data["kdf"]}",'
                f'"key_confirm":"{data["key_confirm"]}","suite_id":"{data["suite_id"]}",'
                f'"version":"{data["version"]}","ek_len":{data["ek_len"]},'
                f'"ct_len":{data["ct_len"]}}}'
            ).encode('utf-8')

            ss_buf = (ctypes.c_uint8 * SS_LEN)()
            ss_len = ctypes.c_size_t(SS_LEN)
            ct_arr = (ctypes.c_uint8 * len(ct_bytes))(*ct_bytes)

            dec_res = self.kem_lib.PQBLOCKS_KEM_X25519_MLKEM768_decaps(
                kem, ct_arr, len(ct_bytes), env_json,
                ss_buf, ctypes.byref(ss_len)
            )
            self.assertEqual(dec_res, PQBLOCKS_SUCCESS, "Decaps of golden ciphertext failed")
            self.assertEqual(bytes(ss_buf), expected_key, "Decaps did not match pinned shared.key")
        finally:
            self.kem_lib.PQBLOCKS_KEM_X25519_MLKEM768_free(kem)


class TestGoldenInstanceSIG(unittest.TestCase):
    """feature 11 Golden instance tests for SIG operations."""

    @classmethod
    def setUpClass(cls):
        cls.sig_lib = _load_sig_lib()

    def test_sig_sign_lengths_and_envelope(self):
        """feature 11 Contract: sig_len=3373 B, envelope contains required composite fields."""
        sig = self.sig_lib.PQBLOCKS_SIG_ED25519_MLDSA65_new()
        self.assertIsNotNone(sig)

        try:
            msg = b"Golden instance test message per spec section 8"
            msg_arr = (ctypes.c_uint8 * len(msg))(*msg)
            sig_buf = (ctypes.c_uint8 * COMPOSITE_SIG_LEN)()
            sig_len = ctypes.c_size_t(COMPOSITE_SIG_LEN)
            env_ptr = ctypes.c_char_p()

            res = self.sig_lib.PQBLOCKS_SIG_ED25519_MLDSA65_sign(
                sig, msg_arr, len(msg),
                sig_buf, ctypes.byref(sig_len),
                ctypes.byref(env_ptr)
            )
            self.assertEqual(res, PQBLOCKS_SUCCESS, "Signing failed")
            self.assertEqual(sig_len.value, COMPOSITE_SIG_LEN, f"Signature must be {COMPOSITE_SIG_LEN} B")
            self.assertIsNotNone(env_ptr.value)

            env = json.loads(env_ptr.value.decode('utf-8'))
            self.assertEqual(env.get('sig'), 'Ed25519+MLDSA65')
            self.assertEqual(env.get('construction'), 'CompositeAlgorithmSignatures2025')
            self.assertEqual(env.get('composite_sig_len'), COMPOSITE_SIG_LEN)
            self.assertEqual(env.get('sig_len'), COMPOSITE_SIG_LEN)

            # Round-trip verify
            ver_res = self.sig_lib.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
                sig, msg_arr, len(msg),
                sig_buf, sig_len.value, env_ptr.value
            )
            self.assertEqual(ver_res, PQBLOCKS_SUCCESS, "Verification of valid signature failed")

            # Single-byte-altered message fails loudly
            bad_msg = bytearray(msg)
            bad_msg[0] ^= 0x01
            bad_msg_arr = (ctypes.c_uint8 * len(bad_msg))(*bad_msg)
            bad_res = self.sig_lib.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
                sig, bad_msg_arr, len(bad_msg),
                sig_buf, sig_len.value, env_ptr.value
            )
            self.assertEqual(bad_res, PQBLOCKS_ERR_SIG_VERIFY, "Altered message must be rejected")
        finally:
            self.sig_lib.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)

    def test_golden_instance_sig_verification_and_tamper_rejection(self):
        """feature 11 Contract: Verify committed sig.bin against sig.json; reject tampered input."""
        sig_json_path = os.path.join(GOLDEN_DIR, 'sig.json')
        sig_bin_path = os.path.join(GOLDEN_DIR, 'sig.bin')
        with open(sig_json_path, 'r') as f:
            sig_data = json.load(f)
        with open(sig_bin_path, 'rb') as f:
            sig_bytes = f.read()

        self.assertEqual(len(sig_bytes), COMPOSITE_SIG_LEN)

        mldsa_pk = base64.b64decode(sig_data['mldsa_pk_b64'])
        mldsa_sk = base64.b64decode(sig_data['mldsa_sk_b64'])
        ed_pk = base64.b64decode(sig_data['ed25519_pk_b64'])
        ed_sk = base64.b64decode(sig_data['ed25519_sk_b64'])

        sig = self.sig_lib.PQBLOCKS_SIG_ED25519_MLDSA65_new()
        self.assertIsNotNone(sig)

        try:
            import_res = self.sig_lib.PQBLOCKS_SIG_ED25519_MLDSA65_import_keys(
                sig,
                (ctypes.c_uint8 * len(mldsa_pk))(*mldsa_pk), len(mldsa_pk),
                (ctypes.c_uint8 * len(mldsa_sk))(*mldsa_sk), len(mldsa_sk),
                (ctypes.c_uint8 * len(ed_pk))(*ed_pk), len(ed_pk),
                (ctypes.c_uint8 * len(ed_sk))(*ed_sk), len(ed_sk),
            )
            self.assertEqual(import_res, PQBLOCKS_SUCCESS)

            # Golden signature was signed over b"test"
            msg = b"test"
            msg_arr = (ctypes.c_uint8 * len(msg))(*msg)
            sig_arr = (ctypes.c_uint8 * len(sig_bytes))(*sig_bytes)

            env_json = (
                f'{{"sig":"{sig_data["sig"]}","construction":"{sig_data["construction"]}",'
                f'"mldsa_sig_len":{sig_data["mldsa_sig_len"]},"composite_sig_len":{sig_data["composite_sig_len"]},'
                f'"euf_cma":true,"suf_cma":false,"kem":"{sig_data["kem"]}","kdf":"{sig_data["kdf"]}",'
                f'"key_confirm":"{sig_data["key_confirm"]}","suite_id":"{sig_data["suite_id"]}",'
                f'"version":"{sig_data["version"]}","ek_len":{sig_data["ek_len"]},'
                f'"ct_len":{sig_data["ct_len"]},"sig_len":{sig_data["sig_len"]},'
                f'"ctx_label":"{sig_data["ctx_label"]}"}}'
            ).encode('utf-8')

            # Verification of pinned signature must succeed
            ver_res = self.sig_lib.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
                sig, msg_arr, len(msg), sig_arr, len(sig_bytes), env_json
            )
            self.assertEqual(ver_res, PQBLOCKS_SUCCESS, "Pinned golden signature verification failed")

            # Altered message must fail loudly
            altered_msg = b"fest"
            alt_arr = (ctypes.c_uint8 * len(altered_msg))(*altered_msg)
            alt_res = self.sig_lib.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
                sig, alt_arr, len(altered_msg), sig_arr, len(sig_bytes), env_json
            )
            self.assertEqual(alt_res, PQBLOCKS_ERR_SIG_VERIFY, "Altered message must fail verification")

            # Tampered signature byte must fail loudly
            tampered_sig = bytearray(sig_bytes)
            tampered_sig[100] ^= 0xFF
            tamp_arr = (ctypes.c_uint8 * len(tampered_sig))(*tampered_sig)
            tamp_res = self.sig_lib.PQBLOCKS_SIG_ED25519_MLDSA65_verify(
                sig, msg_arr, len(msg), tamp_arr, len(tampered_sig), env_json
            )
            self.assertEqual(tamp_res, PQBLOCKS_ERR_SIG_VERIFY, "Tampered signature must fail verification")
        finally:
            self.sig_lib.PQBLOCKS_SIG_ED25519_MLDSA65_free(sig)


if __name__ == '__main__':
    unittest.main()
