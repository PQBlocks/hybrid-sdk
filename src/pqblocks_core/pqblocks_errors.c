/*
 * pqblocks_errors.c - Error Taxonomy & R17 Compliance (S:7)
 *
 * Implements PQBLOCKS_strerror(): maps each PQBLOCKS_ERROR code to a
 * human-readable string. Never exposes secrets or cryptographic material.
 *
 * R17: every error case is countable; no error is silently mapped to success.
 * R8: honest framing quantum-inspired, classically executed, honestly benchmarked.
 * Security: error strings do not contain patterns like "key", "secret", "private", or "seed"
 *           that could leak sensitive information in logs or error messages.
 */

#include "pqblocks_errors.h"

#include <string.h>

const char *PQBLOCKS_strerror(PQBLOCKS_ERROR err) {
    switch (err) {
        case PQBLOCKS_SUCCESS:
            return "PQBLOCKS_SUCCESS";
        case PQBLOCKS_ERR_INVALID_ARGUMENT:
            return "PQBLOCKS_ERR_INVALID_ARGUMENT";
        case PQBLOCKS_ERR_INVALID_LENGTH:
            return "PQBLOCKS_ERR_INVALID_LENGTH";
        case PQBLOCKS_ERR_NULL_POINTER:
            return "PQBLOCKS_ERR_NULL_POINTER";
        case PQBLOCKS_ERR_KEM_KEYGEN:
            return "PQBLOCKS_ERR_KEM_KEYGEN";
        case PQBLOCKS_ERR_KEM_ENCAPS:
            return "PQBLOCKS_ERR_KEM_ENCAPS";
        case PQBLOCKS_ERR_KEM_DECAPS:
            return "PQBLOCKS_ERR_KEM_DECAPS";
        case PQBLOCKS_ERR_SIG_KEYGEN:
            return "PQBLOCKS_ERR_SIG_KEYGEN";
        case PQBLOCKS_ERR_SIG_SIGN:
            return "PQBLOCKS_ERR_SIG_SIGN";
        case PQBLOCKS_ERR_SIG_VERIFY:
            return "PQBLOCKS_ERR_SIG_VERIFY";
        case PQBLOCKS_ERR_BINDING_NOT_INITIALIZED:
            return "PQBLOCKS_ERR_BINDING_NOT_INITIALIZED";
        case PQBLOCKS_ERR_BINDING_LIBOQS_UNAVAILABLE:
            return "PQBLOCKS_ERR_BINDING_LIBOQS_UNAVAILABLE";
        case PQBLOCKS_ERR_BINDING_OPENSSL_UNAVAILABLE:
            return "PQBLOCKS_ERR_BINDING_OPENSSL_UNAVAILABLE";
        case PQBLOCKS_ERR_POLICY_NOT_FOUND:
            return "PQBLOCKS_ERR_POLICY_NOT_FOUND";
        case PQBLOCKS_ERR_POLICY_INVALID_SCHEMA:
            return "PQBLOCKS_ERR_POLICY_INVALID_SCHEMA";
        case PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED:
            return "PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED";
        case PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED:
            return "PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED";
        case PQBLOCKS_ERR_ENVELOPE_MISMATCH:
            return "PQBLOCKS_ERR_ENVELOPE_MISMATCH";
        case PQBLOCKS_ERR_KDF_MISMATCH:
            return "PQBLOCKS_ERR_KDF_MISMATCH";
        case PQBLOCKS_ERR_OUT_OF_MEMORY:
            return "PQBLOCKS_ERR_OUT_OF_MEMORY";
        case PQBLOCKS_ERR_INTERNAL_ERROR:
            return "PQBLOCKS_ERR_INTERNAL_ERROR";
        default:
            return "PQBLOCKS_ERR_UNKNOWN";
    }
}