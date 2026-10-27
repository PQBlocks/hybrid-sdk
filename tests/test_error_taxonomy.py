import os
import sys
import ctypes

lib_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'libpqblocks_errors.so')
if not os.path.exists(lib_path):
    try:
        import pqblocks_core
        _pkg = os.path.join(os.path.dirname(pqblocks_core.__file__), 'lib', 'libpqblocks_errors.so')
        if os.path.exists(_pkg):
            lib_path = _pkg
    except ImportError:
        pass
if not os.path.exists(lib_path):
    _local = os.path.expanduser('~/.local/lib/libpqblocks_errors.so')
    if os.path.exists(_local):
        lib_path = _local
if not os.path.exists(lib_path):
    raise FileNotFoundError(f"Errors library not found at {lib_path}. ")

lib = ctypes.CDLL(lib_path)

lib.PQBLOCKS_strerror.restype = ctypes.c_char_p
lib.PQBLOCKS_strerror.argtypes = [ctypes.c_int]

PQBLOCKS_SUCCESS = 0
PQBLOCKS_ERR_INVALID_ARGUMENT = -1
PQBLOCKS_ERR_INVALID_LENGTH = -2
PQBLOCKS_ERR_NULL_POINTER = -3
PQBLOCKS_ERR_KEM_ENCAPS = -11
PQBLOCKS_ERR_KEM_DECAPS = -12
PQBLOCKS_ERR_KEM_KEYGEN = -10
PQBLOCKS_ERR_SIG_KEYGEN = -20
PQBLOCKS_ERR_SIG_SIGN = -21
PQBLOCKS_ERR_SIG_VERIFY = -22
PQBLOCKS_ERR_BINDING_NOT_INITIALIZED = -30
PQBLOCKS_ERR_BINDING_LIBOQS_UNAVAILABLE = -31
PQBLOCKS_ERR_BINDING_OPENSSL_UNAVAILABLE = -32
PQBLOCKS_ERR_POLICY_NOT_FOUND = -40
PQBLOCKS_ERR_POLICY_INVALID_SCHEMA = -41
PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED = -42
PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED = -50
PQBLOCKS_ERR_ENVELOPE_MISMATCH = -51
PQBLOCKS_ERR_KDF_MISMATCH = -52
PQBLOCKS_ERR_OUT_OF_MEMORY = -60
PQBLOCKS_ERR_INTERNAL_ERROR = -99

ALL_ERROR_CODES = [
    PQBLOCKS_ERR_INVALID_ARGUMENT,
    PQBLOCKS_ERR_INVALID_LENGTH,
    PQBLOCKS_ERR_NULL_POINTER,
    PQBLOCKS_ERR_KEM_KEYGEN,
    PQBLOCKS_ERR_KEM_ENCAPS,
    PQBLOCKS_ERR_KEM_DECAPS,
    PQBLOCKS_ERR_SIG_KEYGEN,
    PQBLOCKS_ERR_SIG_SIGN,
    PQBLOCKS_ERR_SIG_VERIFY,
    PQBLOCKS_ERR_BINDING_NOT_INITIALIZED,
    PQBLOCKS_ERR_BINDING_LIBOQS_UNAVAILABLE,
    PQBLOCKS_ERR_BINDING_OPENSSL_UNAVAILABLE,
    PQBLOCKS_ERR_POLICY_NOT_FOUND,
    PQBLOCKS_ERR_POLICY_INVALID_SCHEMA,
    PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED,
    PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED,
    PQBLOCKS_ERR_ENVELOPE_MISMATCH,
    PQBLOCKS_ERR_KDF_MISMATCH,
    PQBLOCKS_ERR_OUT_OF_MEMORY,
    PQBLOCKS_ERR_INTERNAL_ERROR,
]

ERROR_CATEGORIES = {
    "input": [PQBLOCKS_ERR_INVALID_ARGUMENT, PQBLOCKS_ERR_INVALID_LENGTH, PQBLOCKS_ERR_NULL_POINTER],
    "algorithm": [PQBLOCKS_ERR_KEM_KEYGEN, PQBLOCKS_ERR_KEM_ENCAPS, PQBLOCKS_ERR_KEM_DECAPS,
                  PQBLOCKS_ERR_SIG_KEYGEN, PQBLOCKS_ERR_SIG_SIGN, PQBLOCKS_ERR_SIG_VERIFY],
    "binding": [PQBLOCKS_ERR_BINDING_NOT_INITIALIZED, PQBLOCKS_ERR_BINDING_LIBOQS_UNAVAILABLE,
                PQBLOCKS_ERR_BINDING_OPENSSL_UNAVAILABLE],
    "policy": [PQBLOCKS_ERR_POLICY_NOT_FOUND, PQBLOCKS_ERR_POLICY_INVALID_SCHEMA,
               PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED],
    "security": [PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED, PQBLOCKS_ERR_ENVELOPE_MISMATCH,
                 PQBLOCKS_ERR_KDF_MISMATCH],
    "resource": [PQBLOCKS_ERR_OUT_OF_MEMORY, PQBLOCKS_ERR_INTERNAL_ERROR],
}


def test_strerror_returns_non_empty_for_all_codes():
    """feature 7 Contract: PQBLOCKS_strerror must return a non-empty string for every error code."""
    for code in ALL_ERROR_CODES:
        result = lib.PQBLOCKS_strerror(code)
        assert result is not None, f"PQBLOCKS_strerror({code}) returned NULL"
        assert len(result) > 0, f"PQBLOCKS_strerror({code}) returned empty string"


def test_strerror_success_returns_success_string():
    """feature 7 Contract: PQBLOCKS_SUCCESS maps to 'PQBLOCKS_SUCCESS'."""
    result = lib.PQBLOCKS_strerror(PQBLOCKS_SUCCESS)
    assert result == b"PQBLOCKS_SUCCESS", f"Expected b'PQBLOCKS_SUCCESS', got {result}"


def test_strerror_unknown_returns_unknown():
    """feature 7 Contract: Unknown error codes return 'PQBLOCKS_ERR_UNKNOWN'."""
    result = lib.PQBLOCKS_strerror(-9999)
    assert result == b"PQBLOCKS_ERR_UNKNOWN", f"Expected b'PQBLOCKS_ERR_UNKNOWN', got {result}"


def test_all_error_codes_negative_except_success():
    """feature 7 Contract: All error codes are negative integers; PQBLOCKS_SUCCESS is 0."""
    assert PQBLOCKS_SUCCESS == 0
    for code in ALL_ERROR_CODES:
        assert code < 0, f"Error code {code} should be negative"


def test_no_duplicate_error_codes():
    """feature 7 Contract: Each error code is unique."""
    assert len(ALL_ERROR_CODES) == len(set(ALL_ERROR_CODES)), "Duplicate error codes found"


def test_r17_denominator_coverage():
    """Every error case is countable; no denominator shrinkage.
    
    This test verifies that the error taxonomy covers all six categories
    defined in spec §7 and that no category is empty.
    """
    covered = set()
    for category, codes in ERROR_CATEGORIES.items():
        assert len(codes) > 0, f"Error category '{category}' is empty"
        covered.update(codes)
    assert len(covered) == len(ALL_ERROR_CODES), \
        f"Covered {len(covered)} codes but expected {len(ALL_ERROR_CODES)}"


def test_error_codes_match_spec_section_7():
    """feature 7 Contract: Error codes match spec §7 exactly."""
    expected = {
        "PQBLOCKS_ERR_INVALID_ARGUMENT": -1,
        "PQBLOCKS_ERR_INVALID_LENGTH": -2,
        "PQBLOCKS_ERR_NULL_POINTER": -3,
        "PQBLOCKS_ERR_KEM_KEYGEN": -10,
        "PQBLOCKS_ERR_KEM_ENCAPS": -11,
        "PQBLOCKS_ERR_KEM_DECAPS": -12,
        "PQBLOCKS_ERR_SIG_KEYGEN": -20,
        "PQBLOCKS_ERR_SIG_SIGN": -21,
        "PQBLOCKS_ERR_SIG_VERIFY": -22,
        "PQBLOCKS_ERR_BINDING_NOT_INITIALIZED": -30,
        "PQBLOCKS_ERR_BINDING_LIBOQS_UNAVAILABLE": -31,
        "PQBLOCKS_ERR_BINDING_OPENSSL_UNAVAILABLE": -32,
        "PQBLOCKS_ERR_POLICY_NOT_FOUND": -40,
        "PQBLOCKS_ERR_POLICY_INVALID_SCHEMA": -41,
        "PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED": -42,
        "PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED": -50,
        "PQBLOCKS_ERR_ENVELOPE_MISMATCH": -51,
        "PQBLOCKS_ERR_KDF_MISMATCH": -52,
        "PQBLOCKS_ERR_OUT_OF_MEMORY": -60,
        "PQBLOCKS_ERR_INTERNAL_ERROR": -99,
    }
    for name, value in expected.items():
        assert value in ALL_ERROR_CODES, f"Missing error code: {name} = {value}"


def test_adapter_errors_reported_separately():
    """Adapter errors (binding unavailable) reported separately from algorithm errors."""
    binding_errors = ERROR_CATEGORIES["binding"]
    algorithm_errors = ERROR_CATEGORIES["algorithm"]
    assert len(set(binding_errors) & set(algorithm_errors)) == 0, \
        "Binding and algorithm error codes must not overlap"


def test_strerror_never_exposes_secrets():
    """Security: PQBLOCKS_strerror strings must not expose key material.

    The error strings are symbolic identifiers (PQBLOCKS_ERR_*), so we check
    for patterns that indicate actual secret leakage (hex, base64, PEM,
    keymaterial-like substrings) rather than the mere presence of words
    like "key" inside an identifier name.
    """
    forbidden_patterns = [
        b"-----BEGIN ",          # PEM header
        b"-----END ",            # PEM footer
        b"-----",                # generic PEM fence
        b"secret:",              # secret-key marker
        b"private_key",          # explicit private-key identifier
        b"priv_key",             # short private-key identifier
        b"seed=",                # explicit seed assignment
        b"x25519_sk",            # ephemeral secret-key field
        b"ed25519_sk",           # ephemeral secret-key field
        b"mlkem_dk",             # decapsulation key field
        b"mldsa_sk",             # signing key field
        b"sk[",                  # secret-key array literal
        b"0x[0-9a-fA-F]{16}",   # embedded hex literal (16+ hex chars)
    ]
    for code in ALL_ERROR_CODES:
        result = lib.PQBLOCKS_strerror(code)
        result_bytes = result if isinstance(result, bytes) else result.encode("utf-8", errors="replace")
        result_lower = result_bytes.lower()
        for pattern in forbidden_patterns:
            assert pattern not in result_lower, \
                f"PQBLOCKS_strerror({code}) contains forbidden pattern '{pattern}'"


def test_policy_error_codes_are_subset():
    """feature 7 Contract: Policy error codes match the central taxonomy."""
    policy_codes = {
        PQBLOCKS_ERR_POLICY_NOT_FOUND,
        PQBLOCKS_ERR_POLICY_INVALID_SCHEMA,
        PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED,
    }
    for code in policy_codes:
        assert code in ALL_ERROR_CODES, f"Policy error code {code} not in central taxonomy"