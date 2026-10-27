/*
 * pqblocks_policy.c - Policy Object & Versioning (S:5)
 *
 * Implements the versioned JSON policy object defining allowed cryptographic
 * suites, algorithm parameters, and compliance flags for pqblocks-core.
 *
 * This file implements the S:5 slice: Policy Object & Versioning.
 *
 * Spec §3 defines the default policy JSON. Spec §17 S:5 describes the
 * contract: design/implement policy object JSON schema + versioning;
 * outputs: libpqblocks policy API + default policy object.
 */
#define _GNU_SOURCE  /* for asprintf */
#include "pqblocks_policy.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Static policy JSON string - deterministic for reproducibility.
   Field order matches spec §3 for exact byte-identical output. */
static const char DEFAULT_POLICY_JSON[] =
    "{\n"
    "  \"schema\": \"pqblocks-policy/v1\",\n"
    "  \"suites\": [\n"
    "    {\n"
    "      \"id\": \"X25519MLKEM768-Ed25519MLDSA65-HKDF\",\n"
    "      \"kem\": {\n"
    "        \"primitive\": \"X25519MLKEM768\",\n"
    "        \"kdf\": \"HKDF-SHA256\",\n"
    "        \"shared_secret_len\": 32\n"
    "      },\n"
    "      \"sig\": {\n"
    "        \"primitive\": \"Ed25519+MLDSA65\",\n"
    "        \"construction\": \"CompositeAlgorithmSignatures2025\",\n"
    "        \"ctx_label\": \"ML-DSA-65\",\n"
    "        \"euf_cma\": true,\n"
    "        \"suf_cma\": false\n"
    "      },\n"
    "      \"security\": {\n"
    "        \"security_level\": 3,\n"
    "        \"nist_recommended\": true,\n"
    "        \"cnsa_2_0_allowed\": true\n"
    "      },\n"
    "      \"implementation\": {\n"
    "        \"provider_preference\": [\"openssl_default\", \"oqs_provider\"],\n"
    "        \"min_openssl_version\": \"3.5.0\"\n"
    "      }\n"
    "    }\n"
    "  ],\n"
    "  \"flags\": {\n"
    "    \"require_key_confirmation\": true,\n"
    "    \"require_kdf_enforcement\": true,\n"
    "    \"enforce_envelope_output\": true\n"
    "  },\n"
    "  \"version\": \"1.0.0\",\n"
    "  \"generated_at\": \"2026-09-14T00:00:00Z\"\n"
    "}\n";

PQBLOCKS_POLICY *PQBLOCKS_policy_new(void) {
    PQBLOCKS_POLICY *policy = calloc(1, sizeof(*policy));
    if (policy == NULL)
        return NULL;

    /* Duplicate the static JSON string so caller can free it */
    policy->json_str = strdup(DEFAULT_POLICY_JSON);
    if (policy->json_str == NULL) {
        free(policy);
        return NULL;
    }

    policy->validated = 0;  /* Not yet validated */
    return policy;
}

void PQBLOCKS_policy_free(PQBLOCKS_POLICY *policy) {
    if (policy == NULL)
        return;
    if (policy->json_str != NULL)
        free(policy->json_str);
    free(policy);
}

int PQBLOCKS_policy_get_json(PQBLOCKS_POLICY *policy, char **out_json) {
    if (policy == NULL || out_json == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;
    if (policy->json_str == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;

    /* Return a copy of the JSON string */
    *out_json = strdup(policy->json_str);
    if (*out_json == NULL)
        return PQBLOCKS_ERR_OUT_OF_MEMORY;

    return PQBLOCKS_SUCCESS;
}

int PQBLOCKS_policy_validate(PQBLOCKS_POLICY *policy) {
    if (policy == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;
    if (policy->json_str == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;

    /* Permissive validation: check for required fields.
       In a real implementation, we would parse the JSON and validate each field.
       For this slice, we do a simple substring check for the required top-level
       keys and the suite ID. This ensures the policy hasn't been corrupted. */
    if (strstr(policy->json_str, "\"schema\": \"pqblocks-policy/v1\"") == NULL)
        return PQBLOCKS_ERR_POLICY_INVALID_SCHEMA;
    if (strstr(policy->json_str, "\"id\": \"X25519MLKEM768-Ed25519MLDSA65-HKDF\"") == NULL)
        return PQBLOCKS_ERR_POLICY_NOT_FOUND;
    if (strstr(policy->json_str, "\"version\": \"1.0.0\"") == NULL)
        return PQBLOCKS_ERR_POLICY_INVALID_SCHEMA;
    if (strstr(policy->json_str, "\"require_key_confirmation\": true") == NULL)
        return PQBLOCKS_ERR_POLICY_INVALID_SCHEMA;
    if (strstr(policy->json_str, "\"require_kdf_enforcement\": true") == NULL)
        return PQBLOCKS_ERR_POLICY_INVALID_SCHEMA;
    if (strstr(policy->json_str, "\"enforce_envelope_output\": true") == NULL)
        return PQBLOCKS_ERR_POLICY_INVALID_SCHEMA;

    policy->validated = 1;
    return PQBLOCKS_SUCCESS;
}