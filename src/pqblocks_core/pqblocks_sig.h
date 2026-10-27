#define _GNU_SOURCE
#ifndef PQBLOCKS_SIG_H
#define PQBLOCKS_SIG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OQS_SIG OQS_SIG;

typedef struct {
    OQS_SIG *mldsa65;
    uint8_t pk[1952];
    uint8_t sk[4032];
    uint8_t ed25519_pk[32];
    uint8_t ed25519_sk[32];
    int is_seeded;
    uint8_t seed[32];
} PQBLOCKS_SIG_ED25519_MLDSA65;

PQBLOCKS_SIG_ED25519_MLDSA65 *PQBLOCKS_SIG_ED25519_MLDSA65_new(void);
PQBLOCKS_SIG_ED25519_MLDSA65 *PQBLOCKS_SIG_ED25519_MLDSA65_new_seeded(const uint8_t seed[32]);
void PQBLOCKS_SIG_ED25519_MLDSA65_free(PQBLOCKS_SIG_ED25519_MLDSA65 *);

int PQBLOCKS_SIG_ED25519_MLDSA65_sign(
    const PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
    const uint8_t *message, size_t message_len,
    uint8_t *signature, size_t *signature_len,
    char **envelope_json
);

int PQBLOCKS_SIG_ED25519_MLDSA65_verify(
    const PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len,
    const char *envelope_json
);

#define PQBLOCKS_SIG_ED25519_MLDSA65_SIGNATURE_LEN 3373

int PQBLOCKS_SIG_ED25519_MLDSA65_export_keys(
    const PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
    uint8_t **mldsa_pk, size_t *mldsa_pk_len,
    uint8_t **mldsa_sk, size_t *mldsa_sk_len,
    uint8_t **ed25519_pk, size_t *ed25519_pk_len,
    uint8_t **ed25519_sk, size_t *ed25519_sk_len
);

int PQBLOCKS_SIG_ED25519_MLDSA65_import_keys(
    PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
    const uint8_t *mldsa_pk, size_t mldsa_pk_len,
    const uint8_t *mldsa_sk, size_t mldsa_sk_len,
    const uint8_t *ed25519_pk, size_t ed25519_pk_len,
    const uint8_t *ed25519_sk, size_t ed25519_sk_len
);

#ifdef __cplusplus
}
#endif

#endif