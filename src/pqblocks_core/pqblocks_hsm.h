/*
 * pqblocks_hsm.h - HSM Integration Points
 *
 * PKCS#11 integration surface definition for future HSM delegation.
 * Header defines the engine delegation pattern for HSM vendors to implement.
 *
 * Contract per specification:
 * - PKCS#11 not implemented; defined as future integration surface
 * - API designed for HSM delegation via engine pattern
 * - Current scope: software-only binding to liboqs/OpenSSL
 * - Envelope JSON suitable for HSM-attested operations
 * - Policy object usable by HSM management software for allowed-suite enforcement
 * - No secure key export/import defined; key material remains HSM-bound
 * - Future release may add PKCS#11 CKM_ML_KEM_768 / CKM_ML_DSA_65 mechanism defs
 *
 * Invariants: no primitive implementation; binds existing libraries only.
 * Quantum-inspired, classically executed, honestly benchmarked.
 */

#ifndef PQBLOCKS_HSM_H
#define PQBLOCKS_HSM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------
 * Engine delegation pattern — future HSM integration surface
 *
 * HSM vendors implement these functions to delegate ML-KEM-768 and
 * ML-DSA-65 operations to their HSM/PKCS#11 module. The PQBLOCKS core
 * calls through these function pointers when an ENGINE is set.
 *
 * Current scope: software-only (liboqs/OpenSSL). These are stubs
 * pending future HSM integration implementation.
 * ------------------------------------------------------------------ */

/* Forward declarations */
typedef struct PQBLOCKS_KEM_X25519_MLKEM768 PQBLOCKS_KEM_X25519_MLKEM768;
typedef struct PQBLOCKS_SIG_ED25519_MLDSA65 PQBLOCKS_SIG_ED25519_MLDSA65;

/* PKCS#11 CKM mechanism types for future use */
#define PQBLOCKS_CKM_ML_KEM_768    0x00002BC4  /* CKM_ML_KEM_768 (tentative) */
#define PQBLOCKS_CKM_ML_DSA_65     0x00002BC5  /* CKM_ML_DSA_65 (tentative) */

/* Engine delegation function types — HSM vendors implement these */
typedef int (*pqblocks_kem_keygen_fn)(PQBLOCKS_KEM_X25519_MLKEM768 *kem);
typedef int (*pqblocks_kem_encaps_fn)(const PQBLOCKS_KEM_X25519_MLKEM768 *kem,
                                      uint8_t *ciphertext, size_t *ciphertext_len,
                                      uint8_t *shared_secret, size_t *shared_secret_len);
typedef int (*pqblocks_kem_decaps_fn)(const PQBLOCKS_KEM_X25519_MLKEM768 *kem,
                                      const uint8_t *ciphertext, size_t ciphertext_len,
                                      uint8_t *shared_secret, size_t *shared_secret_len);
typedef int (*pqblocks_sig_keygen_fn)(PQBLOCKS_SIG_ED25519_MLDSA65 *sig);
typedef int (*pqblocks_sig_sign_fn)(const PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
                                    const uint8_t *message, size_t message_len,
                                    uint8_t *signature, size_t *signature_len);
typedef int (*pqblocks_sig_verify_fn)(const PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
                                      const uint8_t *message, size_t message_len,
                                      const uint8_t *signature, size_t signature_len);

/* Engine structure — HSM vendor populates this with their PKCS#11 bindings */
typedef struct {
    const char *name;           /* Human-readable engine name */
    const char *pkcs11_slot;    /* PKCS#11 slot identifier */
    const char *pkcs11_token;   /* PKCS#11 token label */
    const char *pkcs11_pin;     /* PKCS#11 PIN (optional, may be NULL) */

    /* KEM delegation */
    pqblocks_kem_keygen_fn  kem_keygen;
    pqblocks_kem_encaps_fn  kem_encaps;
    pqblocks_kem_decaps_fn  kem_decaps;

    /* SIG delegation */
    pqblocks_sig_keygen_fn  sig_keygen;
    pqblocks_sig_sign_fn    sig_sign;
    pqblocks_sig_verify_fn  sig_verify;

    /* Vendor-specific context */
    void *vendor_ctx;
} PQBLOCKS_ENGINE;

/*
 * Set the HSM engine for KEM operations.
 * Passing NULL reverts to software-only (liboqs/OpenSSL) binding.
 * Returns 0 on success, error code on failure.
 */
int PQBLOCKS_KEM_set_engine(PQBLOCKS_KEM_X25519_MLKEM768 *kem,
                            const PQBLOCKS_ENGINE *engine);

/*
 * Set the HSM engine for SIG operations.
 * Passing NULL reverts to software-only (liboqs/OpenSSL) binding.
 * Returns 0 on success, error code on failure.
 */
int PQBLOCKS_SIG_set_engine(PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
                            const PQBLOCKS_ENGINE *engine);

/*
 * Query whether an HSM engine is currently set for the given KEM handle.
 * Returns 1 if engine is set, 0 if software-only, -1 on NULL pointer.
 */
int PQBLOCKS_KEM_has_engine(const PQBLOCKS_KEM_X25519_MLKEM768 *kem);

/*
 * Query whether an HSM engine is currently set for the given SIG handle.
 * Returns 1 if engine is set, 0 if software-only, -1 on NULL pointer.
 */
int PQBLOCKS_SIG_has_engine(const PQBLOCKS_SIG_ED25519_MLDSA65 *sig);

/*
 * Get the engine name currently bound to the KEM handle.
 * Returns NULL if no engine is set (software-only mode).
 */
const char *PQBLOCKS_KEM_get_engine_name(const PQBLOCKS_KEM_X25519_MLKEM768 *kem);

/*
 * Get the engine name currently bound to the SIG handle.
 * Returns NULL if no engine is set (software-only mode).
 */
const char *PQBLOCKS_SIG_get_engine_name(const PQBLOCKS_SIG_ED25519_MLDSA65 *sig);

/* ------------------------------------------------------------------
 * HSM audit log envelope binding
 *
 * The envelope JSON includes algorithm identification fields that
 * HSM audit logs can use to record which HSM module performed the
 * operation and which algorithm suite was used.
 * ------------------------------------------------------------------ */

/* HSM audit log fields appended to envelope JSON when engine is set */
typedef struct {
    const char *hsm_slot;        /* PKCS#11 slot identifier */
    const char *hsm_token;       /* PKCS#11 token label */
    const char *hsm_session_id;  /* HSM session identifier */
    uint64_t    hsm_timestamp;   /* Unix timestamp of operation */
    const char *hsm_algorithm;   /* Algorithm identifier used */
} PQBLOCKS_HSM_AUDIT;

/*
 * Populate HSM audit fields from the current engine context.
 * Fills the PQBLOCKS_HSM_AUDIT structure with the engine's slot,
 * token, and algorithm information. Returns 0 on success.
 */
int PQBLOCKS_HSM_get_audit_info(const PQBLOCKS_KEM_X25519_MLKEM768 *kem,
                                PQBLOCKS_HSM_AUDIT *audit);

int PQBLOCKS_HSM_get_audit_info_sig(const PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
                                    PQBLOCKS_HSM_AUDIT *audit);

/* ------------------------------------------------------------------
 * Policy integration for HSM suite enforcement
 *
 * The policy object is usable by HSM management software for
 * allowed-suite enforcement. HSM vendors query the policy to determine
 * which algorithm suites are permitted.
 * ------------------------------------------------------------------ */

/*
 * Check whether a given suite ID is permitted by the policy for HSM use.
 * Returns 1 if permitted, 0 if not permitted, -1 on error.
 * This is a software-only check; the HSM may enforce additionally.
 */
int PQBLOCKS_policy_is_suite_allowed_hsm(const char *suite_id);

/* ------------------------------------------------------------------
 * Key material handling — HSM-bound
 *
 * No secure key export/import is defined. Key material
 * remains HSM-bound when an engine is set. The following functions
 * are placeholders for future HSM key management.
 * ------------------------------------------------------------------ */

/*
 * Generate a key pair inside the HSM (future release).
 * Currently returns PQBLOCKS_ERR_BINDING_NOT_INITIALIZED (software-only).
 */
int PQBLOCKS_KEM_generate_key_hsm(PQBLOCKS_KEM_X25519_MLKEM768 *kem);

/*
 * Sign a message inside the HSM (future release).
 * Currently returns PQBLOCKS_ERR_BINDING_NOT_INITIALIZED (software-only).
 */
int PQBLOCKS_SIG_sign_hsm(const PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
                          const uint8_t *message, size_t message_len,
                          uint8_t *signature, size_t *signature_len);

/* ------------------------------------------------------------------
 * Future: PKCS#11 CKM mechanism definitions
 *
 * Future release may add CKM_ML_KEM_768 / CKM_ML_DSA_65 mechanism
 * definitions for PKCS#11 C_EncryptInit / C_SignInit.
 * ------------------------------------------------------------------ */

/* Mechanism definition structure for future PKCS#11 integration */
typedef struct {
    uint32_t mechanism;          /* CKM mechanism type */
    const char *algorithm_id;    /* Corresponding PQBLOCKS algorithm ID */
    size_t     key_size;         /* Key size in bytes */
    size_t     param_size;       /* Parameter size in bytes */
} PQBLOCKS_CKM_MECHANISM;

/* Placeholder mechanism table — populated in future release */
extern const PQBLOCKS_CKM_MECHANISM pqblocks_ckm_table[];
extern const size_t pqblocks_ckm_table_len;

#ifdef __cplusplus
}
#endif

#endif /* PQBLOCKS_HSM_H */
