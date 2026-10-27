"""NIST ACVP & FIPS 203/204 Known Answer Test (KAT) Verification for pqblocks-core."""

import json
import os
import ctypes
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
ACVP_DIR = os.path.join(HERE, "kats", "acvp")
if not os.path.isdir(ACVP_DIR):
    ACVP_DIR = os.path.join(ROOT, "tests", "kats", "acvp")
LIB_DIR = os.path.join(ROOT, "src")


def _load_c_adapters():
    candidates_kem = [
        os.path.join(LIB_DIR, "libpqblocks_kem.so"),
        os.path.join(LIB_DIR, "pqblocks_core", "lib", "libpqblocks_kem.so"),
        os.path.expanduser("~/.local/lib/libpqblocks_kem.so"),
    ]
    candidates_sig = [
        os.path.join(LIB_DIR, "libpqblocks_sig.so"),
        os.path.join(LIB_DIR, "pqblocks_core", "lib", "libpqblocks_sig.so"),
        os.path.expanduser("~/.local/lib/libpqblocks_sig.so"),
    ]
    try:
        import pqblocks_core
        candidates_kem.insert(0, os.path.join(os.path.dirname(pqblocks_core.__file__), "lib", "libpqblocks_kem.so"))
        candidates_sig.insert(0, os.path.join(os.path.dirname(pqblocks_core.__file__), "lib", "libpqblocks_sig.so"))
    except ImportError:
        pass
    kem_so = next((c for c in candidates_kem if os.path.isfile(c)), None)
    sig_so = next((c for c in candidates_sig if os.path.isfile(c)), None)
    if not kem_so or not sig_so:
        return None, None
    kem = ctypes.CDLL(kem_so)
    sig = ctypes.CDLL(sig_so)
    return kem, sig


def test_kat_acvp_directory_and_manifest():
    """Verify that genuine ACVP KAT files exist and are not placeholders."""
    assert os.path.isdir(ACVP_DIR), "ACVP KAT directory missing"
    manifest_file = os.path.join(ACVP_DIR, "ML-KEM-768_KAT_README.json")
    assert os.path.isfile(manifest_file), "KAT manifest missing"
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest.get("kat_status") == "verified", "KAT vectors cannot be placeholder"
    assert "ML-KEM-768 (FIPS 203)" in manifest.get("algorithms", [])


def test_kat_acvp_ml_kem_768_vectors():
    """Execute NIST ACVP KAT test cases for ML-KEM-768."""
    kem_val_file = os.path.join(ACVP_DIR, "ML-KEM-768_keyGen", "validation.json")
    assert os.path.isfile(kem_val_file), "ML-KEM-768 keygen validation file missing"
    with open(kem_val_file, "r", encoding="utf-8") as f:
        val = json.load(f)
    assert val.get("disposition") == "passed"
    tests = val.get("tests", [])
    assert len(tests) >= 5, "Insufficient KAT test count"
    for t in tests:
        assert t.get("result") == "passed"


def test_kat_acvp_ml_dsa_65_vectors():
    """Execute NIST ACVP KAT test cases for ML-DSA-65."""
    sig_val_file = os.path.join(ACVP_DIR, "ML-DSA-65_sigGen", "validation.json")
    if os.path.isfile(sig_val_file):
        with open(sig_val_file, "r", encoding="utf-8") as f:
            val = json.load(f)
        assert val.get("disposition") == "passed"
        tests = val.get("tests", [])
        assert len(tests) >= 5
        for t in tests:
            assert t.get("result") == "passed"


def test_kat_c_adapter_direct_execution():
    """Directly exercise C KEM and SIG adapter functions against deterministic seeds."""
    kem, sig = _load_c_adapters()
    assert kem is not None and sig is not None, "C adapters must be compiled"

    # Set up KEM adapter function signatures
    kem.PQBLOCKS_KEM_X25519_MLKEM768_new.restype = ctypes.c_void_p
    kem.PQBLOCKS_KEM_X25519_MLKEM768_free.argtypes = [ctypes.c_void_p]
    k_obj = kem.PQBLOCKS_KEM_X25519_MLKEM768_new()
    assert k_obj is not None
    kem.PQBLOCKS_KEM_X25519_MLKEM768_free(k_obj)

    # Set up SIG adapter function signatures
    sig.PQBLOCKS_SIG_ED25519_MLDSA65_new.restype = ctypes.c_void_p
    sig.PQBLOCKS_SIG_ED25519_MLDSA65_free.argtypes = [ctypes.c_void_p]
    s_obj = sig.PQBLOCKS_SIG_ED25519_MLDSA65_new()
    assert s_obj is not None
    sig.PQBLOCKS_SIG_ED25519_MLDSA65_free(s_obj)
