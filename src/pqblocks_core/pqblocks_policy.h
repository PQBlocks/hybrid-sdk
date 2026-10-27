/*
 * pqblocks_policy.h - Policy Object & Versioning (S:5)
 *
 * Provides a versioned JSON policy object defining allowed cryptographic
 * suites, algorithm parameters, and compliance flags for pqblocks-core.
 *
 * Contract per spec §3:
 * - Default policy is JSON, schema "pqblocks-policy/v1"
 * - One suite: X25519MLKEM768-Ed25519MLDSA65-HKDF
 * - Defaults: require_key_confirmation=true, require_kdf_enforcement=true,
 *   enforce_envelope_output=true
 *
 * R9 invariants: deterministic output (no random in policy generation);
 * f64 N/A (crypto lane); no lattice re-implementation.
 */
#ifndef PQBLOCKS_POLICY_H
#define PQBLOCKS_POLICY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque policy handle */
typedef struct {
    char *json_str;  /* The policy JSON string */
    int validated;   /* Whether the policy has passed validation */
} PQBLOCKS_POLICY;

/* Create a new default policy object.
   Returns: pointer to allocated policy handle, or NULL on failure.
   Caller must free with PQBLOCKS_policy_free(). */
PQBLOCKS_POLICY *PQBLOCKS_policy_new(void);

/* Free a policy object. Safe to call with NULL. */
void PQBLOCKS_policy_free(PQBLOCKS_POLICY *policy);

/* Get the JSON string representation of the policy.
   Sets *out_json to a malloc'd string; caller must free.
   Returns: 0 (PQBLOCKS_SUCCESS) on success, error code on failure. */
int PQBLOCKS_policy_get_json(PQBLOCKS_POLICY *policy, char **out_json);

/* Validate the policy JSON against the schema.
   Permissive check: only verifies required fields are present.
   Returns: 0 (PQBLOCKS_SUCCESS) if valid, error code otherwise. */
int PQBLOCKS_policy_validate(PQBLOCKS_POLICY *policy);

#include "pqblocks_errors.h"

#ifdef __cplusplus
}
#endif

#endif /* PQBLOCKS_POLICY_H */