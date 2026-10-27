#define _GNU_SOURCE
#include "pqblocks_sig.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <oqs/sig.h>
#include <oqs/sig.h>
#include <oqs/common.h>
#include <oqs/rand.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#define PQBLOCKS_SUCCESS                     0
#define PQBLOCKS_ERR_INVALID_ARGUMENT        -1
#define PQBLOCKS_ERR_INVALID_LENGTH          -2
#define PQBLOCKS_ERR_NULL_POINTER            -3
#define PQBLOCKS_ERR_SIG_KEYGEN             -20
#define PQBLOCKS_ERR_SIG_SIGN               -21
#define PQBLOCKS_ERR_SIG_VERIFY             -22
#define PQBLOCKS_ERR_BINDING_NOT_INITIALIZED -30
#define PQBLOCKS_ERR_OUT_OF_MEMORY          -60
#define PQBLOCKS_ERR_ENVELOPE_MISMATCH      -51
#define PQBLOCKS_ERR_POLICY_SUITE_NOT_ALLOWED -42
#define PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED -50
#define PQBLOCKS_ERR_KDF_MISMATCH           -52

#define MLDSA65_PK_LEN      1952
#define MLDSA65_SK_LEN      4032
#define MLDSA65_SIG_LEN     3309

#define ED25519_PK_LEN      32
#define ED25519_SK_LEN      32
#define ED25519_SIG_LEN     64

#define COMPOSITE_SIG_LEN   3373

#define SHA3_256_LEN        32

static const uint8_t COMPOSITE_PREFIX[] = "CompositeAlgorithmSignatures2025";
#define COMPOSITE_PREFIX_LEN  (sizeof(COMPOSITE_PREFIX) - 1)

static const uint8_t MLDSA65_LABEL[] = "ML-DSA-65";
#define MLDSA65_LABEL_LEN     (sizeof(MLDSA65_LABEL) - 1)

static const char ENVELOPE_TEMPLATE[] =
    "{\"sig\":\"Ed25519+MLDSA65\","
    "\"construction\":\"CompositeAlgorithmSignatures2025\","
    "\"mldsa_sig_len\":3309,"
    "\"composite_sig_len\":3373,"
    "\"euf_cma\":true,"
    "\"suf_cma\":false,"
    "\"kem\":\"X25519+MLKEM768\","
    "\"kdf\":\"HKDF-SHA256\","
    "\"key_confirm\":\"HMAC-SHA256\","
    "\"suite_id\":\"X25519MLKEM768-Ed25519MLDSA65-HKDF\","
    "\"version\":\"1.0.0\","
    "\"ek_len\":1216,"
    "\"ct_len\":1120,"
    "\"sig_len\":3373,"
    "\"ctx_label\":\"ML-DSA-65\"}";

static char *build_envelope(void) {
    char *buf = (char *)malloc(1024);
    if (buf == NULL) return NULL;
    int written = snprintf(buf, 1024, ENVELOPE_TEMPLATE);
    if (written < 0 || (size_t)written >= 1024) {
        free(buf);
        return NULL;
    }
    return buf;
}

static int has_field(const char *env, const char *key, const char *val) {
    char p1[128], p2[128];
    snprintf(p1, sizeof(p1), "\"%s\":\"%s\"", key, val);
    snprintf(p2, sizeof(p2), "\"%s\": \"%s\"", key, val);
    return (strstr(env, p1) != NULL || strstr(env, p2) != NULL);
}

static int validate_envelope(const char *env) {
    if (env == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;
    if (!has_field(env, "sig", "Ed25519+MLDSA65"))
        return PQBLOCKS_ERR_ENVELOPE_MISMATCH;
    if (!has_field(env, "construction", "CompositeAlgorithmSignatures2025"))
        return PQBLOCKS_ERR_ENVELOPE_MISMATCH;
    if (!has_field(env, "ctx_label", "ML-DSA-65"))
        return PQBLOCKS_ERR_ENVELOPE_MISMATCH;
    if (!has_field(env, "kdf", "HKDF-SHA256"))
        return PQBLOCKS_ERR_KDF_MISMATCH;
    if (!has_field(env, "key_confirm", "HMAC-SHA256"))
        return PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED;
    if (!has_field(env, "suite_id", "X25519MLKEM768-Ed25519MLDSA65-HKDF"))
        return PQBLOCKS_ERR_ENVELOPE_MISMATCH;
    if (!has_field(env, "version", "1.0.0"))
        return PQBLOCKS_ERR_ENVELOPE_MISMATCH;
    if (strstr(env, "\"sig_len\":3373") == NULL && strstr(env, "\"sig_len\": 3373") == NULL)
        return PQBLOCKS_ERR_ENVELOPE_MISMATCH;
    return PQBLOCKS_SUCCESS;
}

static int compute_m_prime(const uint8_t *message, size_t message_len, 
                           uint8_t *out_mprime, size_t *out_len) {
    if (message == NULL || out_mprime == NULL || out_len == NULL)
        return -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        return -1;

    const EVP_MD *sha3_256 = EVP_sha3_256();
    if (sha3_256 == NULL) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    uint8_t hash[SHA3_256_LEN];
    unsigned int hash_len = 0;

    if (EVP_DigestInit_ex(mdctx, sha3_256, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, message, message_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);

    if (hash_len != SHA3_256_LEN)
        return -1;

    size_t offset = 0;
    memcpy(out_mprime + offset, COMPOSITE_PREFIX, COMPOSITE_PREFIX_LEN);
    offset += COMPOSITE_PREFIX_LEN;
    memcpy(out_mprime + offset, MLDSA65_LABEL, MLDSA65_LABEL_LEN);
    offset += MLDSA65_LABEL_LEN;
    out_mprime[offset++] = 0x00;
    memcpy(out_mprime + offset, hash, SHA3_256_LEN);
    offset += SHA3_256_LEN;

    *out_len = offset;
    return 0;
}

static int ed25519_keygen(uint8_t *pk, uint8_t *sk) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == NULL) goto cleanup;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto cleanup;

    size_t pk_len = ED25519_PK_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) != 1)
        goto cleanup;

    size_t sk_len = ED25519_SK_LEN;
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) != 1)
        goto cleanup;

    ret = 0;
cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int ed25519_sign(const uint8_t *sk, const uint8_t *mprime, size_t mprime_len,
                        uint8_t *sig, size_t *sig_len) {
    if (sk == NULL || mprime == NULL || sig == NULL || sig_len == NULL)
        return -1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, ED25519_SK_LEN);
    if (pkey == NULL)
        return -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1 ||
        EVP_DigestSign(mdctx, sig, sig_len, mprime, mprime_len) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);

    if (*sig_len != ED25519_SIG_LEN)
        return -1;

    return 0;
}

static int ed25519_verify(const uint8_t *pk, const uint8_t *mprime, size_t mprime_len,
                          const uint8_t *sig, size_t sig_len) {
    if (pk == NULL || mprime == NULL || sig == NULL)
        return -1;

    if (sig_len != ED25519_SIG_LEN)
        return -1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, ED25519_PK_LEN);
    if (pkey == NULL)
        return -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) != 1 ||
        EVP_DigestVerify(mdctx, sig, sig_len, mprime, mprime_len) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    return 0;
}

PQBLOCKS_SIG_ED25519_MLDSA65 *PQBLOCKS_SIG_ED25519_MLDSA65_new(void) {
    PQBLOCKS_SIG_ED25519_MLDSA65 *sig =
        (PQBLOCKS_SIG_ED25519_MLDSA65 *)calloc(1, sizeof(*sig));
    if (sig == NULL) return NULL;

    sig->mldsa65 = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig->mldsa65 == NULL) {
        free(sig);
        return NULL;
    }

    OQS_STATUS st = sig->mldsa65->keypair(sig->pk, sig->sk);
    if (st != OQS_SUCCESS) {
        OQS_SIG_free(sig->mldsa65);
        free(sig);
        return NULL;
    }

    if (ed25519_keygen(sig->ed25519_pk, sig->ed25519_sk) != 0) {
        OQS_SIG_free(sig->mldsa65);
        free(sig);
        return NULL;
    }

    return sig;
}

static uint8_t sig_seed[32];

static void deterministic_sig_rng(uint8_t *random_array, size_t bytes_to_read) {
    for (size_t i = 0; i < bytes_to_read; i++) {
        random_array[i] = (uint8_t)((sig_seed[i % 32] * (i + 1) + i) & 0xFF);
    }
}

PQBLOCKS_SIG_ED25519_MLDSA65 *PQBLOCKS_SIG_ED25519_MLDSA65_new_seeded(
    const uint8_t seed[32]) {
    PQBLOCKS_SIG_ED25519_MLDSA65 *sig =
        (PQBLOCKS_SIG_ED25519_MLDSA65 *)calloc(1, sizeof(*sig));
    if (sig == NULL) return NULL;

    sig->mldsa65 = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig->mldsa65 == NULL) {
        free(sig);
        return NULL;
    }

    memcpy(sig_seed, seed, 32);
    OQS_randombytes_custom_algorithm(deterministic_sig_rng);
    OQS_STATUS st = sig->mldsa65->keypair(sig->pk, sig->sk);
    OQS_randombytes_switch_algorithm("system");
    if (st != OQS_SUCCESS) {
        OQS_SIG_free(sig->mldsa65);
        free(sig);
        return NULL;
    }

    memcpy(sig->ed25519_sk, seed, ED25519_SK_LEN);
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, ED25519_SK_LEN);
    if (pkey == NULL) {
        OQS_SIG_free(sig->mldsa65);
        free(sig);
        return NULL;
    }
    size_t pk_len = ED25519_PK_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, sig->ed25519_pk, &pk_len) != 1) {
        EVP_PKEY_free(pkey);
        OQS_SIG_free(sig->mldsa65);
        free(sig);
        return NULL;
    }
    EVP_PKEY_free(pkey);

    sig->is_seeded = 1;
    memcpy(sig->seed, seed, 32);

    return sig;
}

void PQBLOCKS_SIG_ED25519_MLDSA65_free(PQBLOCKS_SIG_ED25519_MLDSA65 *sig) {
    if (sig == NULL) return;
    if (sig->mldsa65 != NULL) OQS_SIG_free(sig->mldsa65);
    free(sig);
}

int PQBLOCKS_SIG_ED25519_MLDSA65_sign(
    const PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
    const uint8_t *message, size_t message_len,
    uint8_t *signature, size_t *signature_len,
    char **envelope_json)
{
    if (sig == NULL || sig->mldsa65 == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;
    if (message == NULL || signature == NULL || signature_len == NULL || envelope_json == NULL)
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    if (message_len == 0)
        return PQBLOCKS_ERR_INVALID_ARGUMENT;

    if (*signature_len < COMPOSITE_SIG_LEN)
        return PQBLOCKS_ERR_INVALID_LENGTH;

    uint8_t mprime[COMPOSITE_PREFIX_LEN + MLDSA65_LABEL_LEN + 1 + SHA3_256_LEN];
    size_t mprime_len;
    if (compute_m_prime(message, message_len, mprime, &mprime_len) != 0)
        return PQBLOCKS_ERR_SIG_SIGN;

    uint8_t mldsa_sig[MLDSA65_SIG_LEN];
    size_t mldsa_sig_len = MLDSA65_SIG_LEN;

    if (sig->is_seeded) {
        OQS_randombytes_custom_algorithm(deterministic_sig_rng);
    }
    OQS_STATUS st = sig->mldsa65->sign(
        mldsa_sig, &mldsa_sig_len,
        mprime, mprime_len,
        sig->sk);
    if (sig->is_seeded) {
        OQS_randombytes_switch_algorithm("system");
    }
    if (st != OQS_SUCCESS || mldsa_sig_len != MLDSA65_SIG_LEN)
        return PQBLOCKS_ERR_SIG_SIGN;

    uint8_t ed25519_sig[ED25519_SIG_LEN];
    size_t ed25519_sig_len = ED25519_SIG_LEN;
    if (ed25519_sign(sig->ed25519_sk, mprime, mprime_len, ed25519_sig, &ed25519_sig_len) != 0 ||
        ed25519_sig_len != ED25519_SIG_LEN)
        return PQBLOCKS_ERR_SIG_SIGN;

    memcpy(signature, mldsa_sig, MLDSA65_SIG_LEN);
    memcpy(signature + MLDSA65_SIG_LEN, ed25519_sig, ED25519_SIG_LEN);
    *signature_len = COMPOSITE_SIG_LEN;

    char *env = build_envelope();
    if (env == NULL)
        return PQBLOCKS_ERR_OUT_OF_MEMORY;
    *envelope_json = env;

    return PQBLOCKS_SUCCESS;
}

int PQBLOCKS_SIG_ED25519_MLDSA65_verify(
    const PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len,
    const char *envelope_json)
{
    if (sig == NULL || sig->mldsa65 == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;
    if (message == NULL || signature == NULL || envelope_json == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;

    if (signature_len != COMPOSITE_SIG_LEN)
        return PQBLOCKS_ERR_INVALID_LENGTH;

    int venv = validate_envelope(envelope_json);
    if (venv != PQBLOCKS_SUCCESS)
        return venv;

    uint8_t mprime[COMPOSITE_PREFIX_LEN + MLDSA65_LABEL_LEN + 1 + SHA3_256_LEN];
    size_t mprime_len;
    if (compute_m_prime(message, message_len, mprime, &mprime_len) != 0)
        return PQBLOCKS_ERR_SIG_VERIFY;

    const uint8_t *mldsa_sig = signature;
    const uint8_t *ed25519_sig = signature + MLDSA65_SIG_LEN;

    OQS_STATUS st = sig->mldsa65->verify(
        mprime, mprime_len,
        mldsa_sig, MLDSA65_SIG_LEN,
        sig->pk);
    if (st != OQS_SUCCESS)
        return PQBLOCKS_ERR_SIG_VERIFY;

    if (ed25519_verify(sig->ed25519_pk, mprime, mprime_len, ed25519_sig, ED25519_SIG_LEN) != 0)
        return PQBLOCKS_ERR_SIG_VERIFY;

    return PQBLOCKS_SUCCESS;
}

int PQBLOCKS_SIG_ED25519_MLDSA65_export_keys(
    const PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
    uint8_t **mldsa_pk, size_t *mldsa_pk_len,
    uint8_t **mldsa_sk, size_t *mldsa_sk_len,
    uint8_t **ed25519_pk, size_t *ed25519_pk_len,
    uint8_t **ed25519_sk, size_t *ed25519_sk_len
) {
    if (sig == NULL) return PQBLOCKS_ERR_NULL_POINTER;

    if (mldsa_pk != NULL && mldsa_pk_len != NULL) {
        *mldsa_pk = (uint8_t *)malloc(MLDSA65_PK_LEN);
        if (*mldsa_pk == NULL) return PQBLOCKS_ERR_OUT_OF_MEMORY;
        memcpy(*mldsa_pk, sig->pk, MLDSA65_PK_LEN);
        *mldsa_pk_len = MLDSA65_PK_LEN;
    }

    if (mldsa_sk != NULL && mldsa_sk_len != NULL) {
        *mldsa_sk = (uint8_t *)malloc(MLDSA65_SK_LEN);
        if (*mldsa_sk == NULL) {
            if (mldsa_pk != NULL) free(*mldsa_pk);
            return PQBLOCKS_ERR_OUT_OF_MEMORY;
        }
        memcpy(*mldsa_sk, sig->sk, MLDSA65_SK_LEN);
        *mldsa_sk_len = MLDSA65_SK_LEN;
    }

    if (ed25519_pk != NULL && ed25519_pk_len != NULL) {
        *ed25519_pk = (uint8_t *)malloc(ED25519_PK_LEN);
        if (*ed25519_pk == NULL) {
            if (mldsa_pk != NULL) free(*mldsa_pk);
            if (mldsa_sk != NULL) free(*mldsa_sk);
            return PQBLOCKS_ERR_OUT_OF_MEMORY;
        }
        memcpy(*ed25519_pk, sig->ed25519_pk, ED25519_PK_LEN);
        *ed25519_pk_len = ED25519_PK_LEN;
    }

    if (ed25519_sk != NULL && ed25519_sk_len != NULL) {
        *ed25519_sk = (uint8_t *)malloc(ED25519_SK_LEN);
        if (*ed25519_sk == NULL) {
            if (mldsa_pk != NULL) free(*mldsa_pk);
            if (mldsa_sk != NULL) free(*mldsa_sk);
            if (ed25519_pk != NULL) free(*ed25519_pk);
            return PQBLOCKS_ERR_OUT_OF_MEMORY;
        }
        memcpy(*ed25519_sk, sig->ed25519_sk, ED25519_SK_LEN);
        *ed25519_sk_len = ED25519_SK_LEN;
    }

    return PQBLOCKS_SUCCESS;
}

int PQBLOCKS_SIG_ED25519_MLDSA65_import_keys(
    PQBLOCKS_SIG_ED25519_MLDSA65 *sig,
    const uint8_t *mldsa_pk, size_t mldsa_pk_len,
    const uint8_t *mldsa_sk, size_t mldsa_sk_len,
    const uint8_t *ed25519_pk, size_t ed25519_pk_len,
    const uint8_t *ed25519_sk, size_t ed25519_sk_len
) {
    if (sig == NULL) return PQBLOCKS_ERR_NULL_POINTER;

    if (mldsa_pk != NULL) {
        if (mldsa_pk_len != MLDSA65_PK_LEN) return PQBLOCKS_ERR_INVALID_LENGTH;
        memcpy(sig->pk, mldsa_pk, MLDSA65_PK_LEN);
    }

    if (mldsa_sk != NULL) {
        if (mldsa_sk_len != MLDSA65_SK_LEN) return PQBLOCKS_ERR_INVALID_LENGTH;
        memcpy(sig->sk, mldsa_sk, MLDSA65_SK_LEN);
    }

    if (ed25519_pk != NULL) {
        if (ed25519_pk_len != ED25519_PK_LEN) return PQBLOCKS_ERR_INVALID_LENGTH;
        memcpy(sig->ed25519_pk, ed25519_pk, ED25519_PK_LEN);
    }

    if (ed25519_sk != NULL) {
        if (ed25519_sk_len != ED25519_SK_LEN) return PQBLOCKS_ERR_INVALID_LENGTH;
        memcpy(sig->ed25519_sk, ed25519_sk, ED25519_SK_LEN);
    }

    return PQBLOCKS_SUCCESS;
}