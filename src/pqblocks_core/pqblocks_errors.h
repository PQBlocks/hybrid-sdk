/*
 * pqblocks_errors.h - Error Taxonomy & R17 Compliance (S:7)
 *
 * Defines the complete PQBLOCKS_ERROR enum and PQBLOCKS_strerror().
 * All error codes from spec §7 are centralized here.
 *
 * R17: every error case is countable; no error is silently mapped to success.
 * R8: honest framing — quantum-inspired, classically executed, honestly benchmarked.
 */

#ifndef PQBLOCKS_ERRORS_H
#define PQBLOCKS_ERRORS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PQBLOCKS_SUCCESS = 0,

    /* Input errors */
    PQBLOCKS_ERR_INVALID_ARGUMENT = -1,
    PQBLOCKS_ERR_INVALID_LENGTH = -2,
    PQBLOCKS_ERR_NULL_POINTER = -3,

    /* Algorithm-specific */
    PQBLOCKS_ERR_KEM_KEYGEN = -10,
    PQBLOCKS_ERR_KEM_ENCAPS = -11,
    PQBLOCKS_ERR_KEM_DECAPS = -12,
    PQBLOCKS_ERR_SIG_KEYGEN = -20,
    PQBLOCKS_ERR_SIG_SIGN = -21,
    PQBLOCKS_ERR_SIG_VERIFY = -22,

    /* Binding errors */
    PQBLOCKS_ERR_BINDING_NOT_INITIALIZED = -30,
    PQBLOCKS_ERR_BINDING_LIBOQS_UNAVAILABLE = -31,
    PQBLOCKS_ERR_BINDING_OPENSSL_UNAVAILABLE = -32,

    /* Policy errors */
    PQBLOCKS_ERR_POLICY_NOT_FOUND = -40,
    PQBLOCKS_ERR_POLICY_INVALID_SCHEMA = -41,
    PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED = -42,

    /* Security errors */
    PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED = -50,
    PQBLOCKS_ERR_ENVELOPE_MISMATCH = -51,
    PQBLOCKS_ERR_KDF_MISMATCH = -52,

    /* Resource errors */
    PQBLOCKS_ERR_OUT_OF_MEMORY = -60,
    PQBLOCKS_ERR_INTERNAL_ERROR = -99
} PQBLOCKS_ERROR;

/* Error-to-string for logging (never exposes secrets). */
const char *PQBLOCKS_strerror(PQBLOCKS_ERROR err);

#ifdef __cplusplus
}
#endif

#endif /* PQBLOCKS_ERRORS_H */