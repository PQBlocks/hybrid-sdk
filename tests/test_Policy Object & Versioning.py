import os
import sys
import json
import ctypes

# The feature 5 policy module is built separately as part of libpqblocks
# Load the policy-specific shared library
lib_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'libpqblocks_policy.so')
if not os.path.exists(lib_path):
    try:
        import pqblocks_core
        _pkg = os.path.join(os.path.dirname(pqblocks_core.__file__), 'lib', 'libpqblocks_policy.so')
        if os.path.exists(_pkg):
            lib_path = _pkg
    except ImportError:
        pass
if not os.path.exists(lib_path):
    _local = os.path.expanduser('~/.local/lib/libpqblocks_policy.so')
    if os.path.exists(_local):
        lib_path = _local
if not os.path.exists(lib_path):
    raise FileNotFoundError(f"Policy library not found at {lib_path}. ")

lib = ctypes.CDLL(lib_path)

# Error codes from spec section 7 (subset used by policy module)
PQBLOCKS_SUCCESS = 0
PQBLOCKS_ERR_INVALID_ARGUMENT = -1
PQBLOCKS_ERR_INVALID_LENGTH = -2
PQBLOCKS_ERR_NULL_POINTER = -3
PQBLOCKS_ERR_OUT_OF_MEMORY = -60
PQBLOCKS_ERR_ENVELOPE_MISMATCH = -51
PQBLOCKS_ERR_POLICY_NOT_FOUND = -40
PQBLOCKS_ERR_POLICY_INVALID_SCHEMA = -41
PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED = -42

# Function signatures (assuming these exist in the policy module)
lib.PQBLOCKS_policy_new.restype = ctypes.c_void_p
lib.PQBLOCKS_policy_new.argtypes = []

lib.PQBLOCKS_policy_free.restype = None
lib.PQBLOCKS_policy_free.argtypes = [ctypes.c_void_p]

# get_json returns a malloc'd string via out param
lib.PQBLOCKS_policy_get_json.restype = ctypes.c_int
lib.PQBLOCKS_policy_get_json.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]

# validate returns error code directly
lib.PQBLOCKS_policy_validate.restype = ctypes.c_int
lib.PQBLOCKS_policy_validate.argtypes = [ctypes.c_void_p]


def get_policy_json():
    """Helper: call PQBLOCKS_policy_get_json, return (json_string, error_code)."""
    policy = lib.PQBLOCKS_policy_new()
    if policy is None:
        return None, PQBLOCKS_ERR_NULL_POINTER
    out_ptr = ctypes.c_char_p()
    err = lib.PQBLOCKS_policy_get_json(policy, ctypes.byref(out_ptr))
    lib.PQBLOCKS_policy_free(policy)
    if err != PQBLOCKS_SUCCESS:
        return None, err
    if out_ptr.value is None:
        return None, PQBLOCKS_ERR_NULL_POINTER
    return out_ptr.value.decode('utf-8'), err


def test_policy_new_returns_non_null():
    """feature 5 Contract: policy_new must return a valid opaque handle."""
    policy = lib.PQBLOCKS_policy_new()
    assert policy is not None, "Policy object should not be NULL"
    lib.PQBLOCKS_policy_free(policy)


def test_policy_get_json_returns_valid_json():
    """feature 5 Contract: policy_get_json must return the spec §3 default policy JSON.
    
    Expected fields (spec §3):
      schema, suites[0] (with id, kem, sig, security, implementation),
      flags, version, generated_at
    """
    json_str, err = get_policy_json()
    assert err == PQBLOCKS_SUCCESS, f"Getting JSON failed with error {err}"
    assert json_str is not None, "JSON string should not be None"

    data = json.loads(json_str)

    # Top-level schema
    assert data["schema"] == "pqblocks-policy/v1"
    
    # Version
    assert data["version"] == "1.0.0"
    
    # Generated timestamp (ISO format, non-empty)
    assert isinstance(data["generated_at"], str)
    assert len(data["generated_at"]) > 0
    
    # Suites array — exactly one suite in the default policy
    assert "suites" in data
    assert len(data["suites"]) == 1
    
    suite = data["suites"][0]
    assert suite["id"] == "X25519MLKEM768-Ed25519MLDSA65-HKDF"
    
    # KEM block
    assert suite["kem"]["primitive"] == "X25519MLKEM768"
    assert suite["kem"]["kdf"] == "HKDF-SHA256"
    assert suite["kem"]["shared_secret_len"] == 32
    
    # SIG block
    assert suite["sig"]["primitive"] == "Ed25519+MLDSA65"
    assert suite["sig"]["construction"] == "CompositeAlgorithmSignatures2025"
    assert suite["sig"]["ctx_label"] == "ML-DSA-65"
    assert suite["sig"]["euf_cma"] is True
    assert suite["sig"]["suf_cma"] is False
    
    # Security block
    assert suite["security"]["security_level"] == 3
    assert suite["security"]["nist_recommended"] is True
    assert suite["security"]["cnsa_2_0_allowed"] is True
    
    # Implementation block
    assert suite["implementation"]["provider_preference"] == ["openssl_default", "oqs_provider"]
    assert suite["implementation"]["min_openssl_version"] == "3.5.0"
    
    # Flags block
    assert data["flags"]["require_key_confirmation"] is True
    assert data["flags"]["require_kdf_enforcement"] is True
    assert data["flags"]["enforce_envelope_output"] is True


def test_policy_validate_returns_success():
    """feature 5 Contract: policy_validate must return PQBLOCKS_SUCCESS for the default policy."""
    policy = lib.PQBLOCKS_policy_new()
    assert policy is not None
    err = lib.PQBLOCKS_policy_validate(policy)
    lib.PQBLOCKS_policy_free(policy)
    assert err == PQBLOCKS_SUCCESS, f"Policy validation failed with error {err}"


def test_policy_null_handling():
    """feature 5 Edge case: NULL policy pointer must return PQBLOCKS_ERR_NULL_POINTER."""
    # get_json with NULL policy
    err = lib.PQBLOCKS_policy_get_json(None, ctypes.byref(ctypes.c_char_p()))
    assert err == PQBLOCKS_ERR_NULL_POINTER, \
        f"NULL policy to get_json should return -3, got {err}"
    
    # validate with NULL policy
    err = lib.PQBLOCKS_policy_validate(None)
    assert err == PQBLOCKS_ERR_NULL_POINTER, \
        f"NULL policy to validate should return -3, got {err}"
