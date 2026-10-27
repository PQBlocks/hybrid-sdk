#ifndef PQBLOCKS_KEM_H
#define PQBLOCKS_KEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OQS_KEM OQS_KEM;

#define MLKEM768_EK_LEN  1184
#define MLKEM768_DK_LEN  2400
#define MLKEM768_CT_LEN  1088
#define MLKEM768_SS_LEN   32
#define X25519_PUB_LEN    32
#define X25519_PRIV_LEN   32

#define HYBRID_EK_LEN (MLKEM768_EK_LEN + X25519_PUB_LEN)
#define HYBRID_CT_LEN (MLKEM768_CT_LEN + X25519_PUB_LEN)

typedef struct {
    OQS_KEM *mlkem768;
    uint8_t ek[MLKEM768_EK_LEN];
    uint8_t dk[MLKEM768_DK_LEN];
    uint8_t x25519_priv[X25519_PRIV_LEN];
    uint8_t x25519_pub[X25519_PUB_LEN];
    int is_seeded;
    uint8_t seed[32];
} PQBLOCKS_KEM_X25519_MLKEM768;

PQBLOCKS_KEM_X25519_MLKEM768 *PQBLOCKS_KEM_X25519_MLKEM768_new(void);
PQBLOCKS_KEM_X25519_MLKEM768 *PQBLOCKS_KEM_X25519_MLKEM768_new_seeded(const uint8_t seed[32]);
void PQBLOCKS_KEM_X25519_MLKEM768_free(PQBLOCKS_KEM_X25519_MLKEM768 *);

int PQBLOCKS_KEM_X25519_MLKEM768_encaps(
    const PQBLOCKS_KEM_X25519_MLKEM768 *kem,
    uint8_t *ciphertext, size_t *ciphertext_len,
    uint8_t *shared_secret, size_t *shared_secret_len,
    char **envelope_json
);

int PQBLOCKS_KEM_X25519_MLKEM768_decaps(
    const PQBLOCKS_KEM_X25519_MLKEM768 *kem,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const char *envelope_json,
    uint8_t *shared_secret, size_t *shared_secret_len
);

#define PQBLOCKS_KEM_X25519_MLKEM768_SHARED_SECRET_LEN 32

int PQBLOCKS_KEM_X25519_MLKEM768_export_keys(
    const PQBLOCKS_KEM_X25519_MLKEM768 *kem,
    uint8_t **ek, size_t *ek_len,
    uint8_t **dk, size_t *dk_len,
    uint8_t **x25519_pub, size_t *x25519_pub_len
);

int PQBLOCKS_KEM_X25519_MLKEM768_import_keys(
    PQBLOCKS_KEM_X25519_MLKEM768 *kem,
    const uint8_t *ek, size_t ek_len,
    const uint8_t *dk, size_t dk_len,
    const uint8_t *x25519_pub, size_t x25519_pub_len
);

#ifdef __cplusplus
}
#endif

#endif