import os
import re
import sys

"""
HSM Integration Points — Documentation Review Tests

Contract: Define PKCS#11 integration surfaces (no implementation).
Tests: Documentation review; no runtime test.

These tests verify that the HSM integration header file exists,
contains the required engine delegation pattern declarations, and
is consistent with the specification. No runtime tests — there is no
HSM implementation in this core library.
"""

HERE = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(HERE, "..", "src")
HEADER = os.path.join(SRC_DIR, "pqblocks_core", "pqblocks_hsm.h")
if not os.path.isfile(HEADER):
    HEADER = os.path.join(SRC_DIR, "pqblocks_hsm.h")
if not os.path.isfile(HEADER):
    try:
        import pqblocks_core
        _pkg_header = os.path.join(os.path.dirname(pqblocks_core.__file__), "pqblocks_hsm.h")
        if os.path.isfile(_pkg_header):
            HEADER = _pkg_header
    except ImportError:
        pass

SPEC_SECTION_11 = """
PKCS#11 / HSM Integration Points:
- PKCS#11 not implemented; defined as future integration surface
- API designed for HSM delegation via engine pattern
- Current scope: Software-only binding to liboqs/OpenSSL
- Envelope JSON suitable for HSM-attested operations (HSM signs envelope)
- Policy object usable by HSM management software for allowed-suite enforcement
- HSM vendors to implement PQBLOCKS engine delegating to their ML-KEM/ML-DSA
- Envelope provides algorithm identification for HSM audit logs
- No secure key export/import defined; key material remains HSM-bound
- Future release may add PKCS#11 CKM_ML_KEM_768 / CKM_ML_DSA_65 mechanism definitions
"""


def test_header_file_exists():
    """Header file pqblocks_hsm.h must exist."""
    assert os.path.isfile(HEADER), (
        f"HSM header file not found at {HEADER}. "
        "Requires header files showing engine delegation pattern."
    )


def test_header_is_readable():
    """Header file must be readable and non-empty."""
    assert os.path.getsize(HEADER) > 0, "HSM header file is empty"
    with open(HEADER, "r") as f:
        content = f.read()
    assert len(content) > 100, "HSM header file too short to contain meaningful content"


def test_header_has_include_guard():
    """Header must have include guard."""
    with open(HEADER, "r") as f:
        content = f.read()
    assert "#ifndef PQBLOCKS_HSM_H" in content, "Missing #ifndef PQBLOCKS_HSM_H"
    assert "#define PQBLOCKS_HSM_H" in content, "Missing #define PQBLOCKS_HSM_H"
    assert "#endif /* PQBLOCKS_HSM_H */" in content, "Missing #endif with comment"


def test_engine_delegation_pattern():
    """Header must define engine delegation pattern.

    API designed for HSM delegation via engine pattern.
    Must declare PQBLOCKS_ENGINE struct and set_engine functions.
    """
    with open(HEADER, "r") as f:
        content = f.read()

    # PQBLOCKS_ENGINE struct
    assert "typedef struct" in content, "Missing typedef struct for engine"
    assert "PQBLOCKS_ENGINE" in content, "Missing PQBLOCKS_ENGINE type"

    # Engine function pointer types
    assert "pqblocks_kem_keygen_fn" in content, "Missing kem_keygen function pointer type"
    assert "pqblocks_kem_encaps_fn" in content, "Missing kem_encaps function pointer type"
    assert "pqblocks_kem_decaps_fn" in content, "Missing kem_decaps function pointer type"
    assert "pqblocks_sig_keygen_fn" in content, "Missing sig_keygen function pointer type"
    assert "pqblocks_sig_sign_fn" in content, "Missing sig_sign function pointer type"
    assert "pqblocks_sig_verify_fn" in content, "Missing sig_verify function pointer type"

    # set_engine functions
    assert "PQBLOCKS_KEM_set_engine" in content, "Missing PQBLOCKS_KEM_set_engine"
    assert "PQBLOCKS_SIG_set_engine" in content, "Missing PQBLOCKS_SIG_set_engine"

    # has_engine / get_engine_name query functions
    assert "PQBLOCKS_KEM_has_engine" in content, "Missing PQBLOCKS_KEM_has_engine"
    assert "PQBLOCKS_SIG_has_engine" in content, "Missing PQBLOCKS_SIG_has_engine"
    assert "PQBLOCKS_KEM_get_engine_name" in content, "Missing PQBLOCKS_KEM_get_engine_name"
    assert "PQBLOCKS_SIG_get_engine_name" in content, "Missing PQBLOCKS_SIG_get_engine_name"


def test_pkcs11_ckm_placeholders():
    """Header must define CKM mechanism placeholders.

    Future feature may add PKCS#11 CKM_ML_KEM_768 / CKM_ML_DSA_65
    mechanism definitions.
    """
    with open(HEADER, "r") as f:
        content = f.read()

    assert "PQBLOCKS_CKM_ML_KEM_768" in content, "Missing CKM_ML_KEM_768 placeholder"
    assert "PQBLOCKS_CKM_ML_DSA_65" in content, "Missing CKM_ML_DSA_65 placeholder"
    assert "PQBLOCKS_CKM_MECHANISM" in content, "Missing PQBLOCKS_CKM_MECHANISM struct"
    assert "pqblocks_ckm_table" in content, "Missing pkcs11 mechanism table"


def test_hsm_audit_binding():
    """Header must define HSM audit log envelope binding.

    Envelope provides algorithm identification for HSM audit logs.
    """
    with open(HEADER, "r") as f:
        content = f.read()

    assert "PQBLOCKS_HSM_AUDIT" in content, "Missing PQBLOCKS_HSM_AUDIT struct"
    assert "hsm_slot" in content, "Missing hsm_slot field"
    assert "hsm_token" in content, "Missing hsm_token field"
    assert "hsm_session_id" in content, "Missing hsm_session_id field"
    assert "hsm_timestamp" in content, "Missing hsm_timestamp field"
    assert "hsm_algorithm" in content, "Missing hsm_algorithm field"
    assert "PQBLOCKS_HSM_get_audit_info" in content, "Missing PQBLOCKS_HSM_get_audit_info"


def test_policy_integration():
    """Header must define policy integration for HSM suite enforcement.

    Policy object usable by HSM management software for allowed-suite enforcement.
    """
    with open(HEADER, "r") as f:
        content = f.read()

    assert "PQBLOCKS_policy_is_suite_allowed_hsm" in content, (
        "Missing policy suite check for HSM enforcement"
    )


def test_key_material_hsm_bound():
    """Header must document that key material remains HSM-bound.

    No secure key export/import defined; key material remains HSM-bound.
    """
    with open(HEADER, "r") as f:
        content = f.read()

    assert "HSM-bound" in content or "hsm-bound" in content, (
        "Missing HSM-bound key material documentation"
    )
    assert "PQBLOCKS_KEM_generate_key_hsm" in content, (
        "Missing HSM key generation placeholder"
    )
    assert "PQBLOCKS_SIG_sign_hsm" in content, (
        "Missing HSM signing placeholder"
    )


def test_no_primitive_implementation():
    """Header must not implement any cryptographic primitive.

    NO reimplementation of lattice arithmetic, NTT, or signature primitives.
    All cryptographic operations delegated to bound libraries.
    """
    with open(HEADER, "r") as f:
        content = f.read()

    forbidden_patterns = [
        "ml_kem_768_keygen",
        "ml_kem_768_encaps",
        "ml_kem_768_decaps",
        "mldsa65_sign",
        "mldsa65_verify",
        "ed25519_sign",
        "ed25519_verify",
        "OQS_KEM_new",
        "OQS_SIG_new",
    ]
    for pattern in forbidden_patterns:
        assert pattern not in content.lower(), (
            f"Found primitive implementation pattern '{pattern}' in HSM header — "
            "must not implement cryptographic primitives"
        )


def test_software_only_scope():
    """Header must declare current scope as software-only.

    Current scope is software-only binding to liboqs/OpenSSL.
    """
    with open(HEADER, "r") as f:
        content = f.read()

    assert "software-only" in content.lower() or "software only" in content.lower(), (
        "Missing software-only scope declaration"
    )
    assert "liboqs" in content.lower(), "Missing liboqs reference"
    assert "openssl" in content.lower(), "Missing OpenSSL reference"


def test_future_slice_marker():
    """Header must mark future features for PKCS#11 mechanism definitions."""
    with open(HEADER, "r") as f:
        content = f.read()

    assert "future" in content.lower(), (
        "Missing future marker"
    )
    assert "CKM_ML_KEM_768" in content or "CKM_ML_DSA_65" in content, (
        "Missing CKM mechanism definition placeholders"
    )


def test_cplusplus_compatibility():
    """Header must support C++ linkage."""
    with open(HEADER, "r") as f:
        content = f.read()

    assert "#ifdef __cplusplus" in content, "Missing C++ extern C guard"
    assert "extern \"C\"" in content, "Missing extern C declaration"


def test_no_hype_terminology():
    """Header must not contain forbidden hype terminology.

    Forbidden: 'quantum speedup', 'quantum-powered', 'unbreakable',
    'revolutionary', 'blazingly'.
    """
    with open(HEADER, "r") as f:
        content = f.read().lower()

    forbidden = ["quantum speedup", "quantum-powered", "unbreakable",
                 "revolutionary", "blazingly"]
    for term in forbidden:
        assert term not in content, (
            f"Forbidden hype term '{term}' found in HSM header"
        )
