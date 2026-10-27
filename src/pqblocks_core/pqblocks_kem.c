#define _GNU_SOURCE
#include "pqblocks_kem.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <oqs/kem.h>
#include <oqs/common.h>
#include <oqs/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define PQBLOCKS_SUCCESS                    0
#define PQBLOCKS_ERR_INVALID_ARGUMENT        -1
#define PQBLOCKS_ERR_INVALID_LENGTH        -2
#define PQBLOCKS_ERR_NULL_POINTER            -3
#define PQBLOCKS_ERR_KEM_KEYGEN             -10
#define PQBLOCKS_ERR_KEM_ENCAPS             -11
#define PQBLOCKS_ERR_KEM_DECAPS             -12
#define PQBLOCKS_ERR_BINDING_NOT_INITIALIZED -30
#define PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED -50
#define PQBLOCKS_ERR_KDF_MISMATCH           -52
#define PQBLOCKS_ERR_OUT_OF_MEMORY          -60
#define PQBLOCKS_ERR_ENVELOPE_MISMATCH      -51

/* Key-confirmation info string: domain-separated from the traffic-key info. */
#define CONFIRM_INFO "pqblocks-key-confirm-v1"
#define CONFIRM_INFO_LEN (sizeof(CONFIRM_INFO) - 1)
#define CONFIRM_TAG_HEX_LEN 64

static const char ENVELOPE_TEMPLATE[] =
    "{\"kem\":\"X25519+MLKEM768\","
    "\"kdf\":\"HKDF-SHA256\","
    "\"key_confirm\":\"HMAC-SHA256\","
    "\"suite_id\":\"X25519MLKEM768-Ed25519MLDSA65-HKDF\","
    "\"version\":\"1.0.0\","
    "\"ek_len\":%u,"
    "\"ct_len\":%u,"
    "\"ss_len\":32,"
    "\"confirmation_tag\":\"%s\"}";

static char *build_envelope(const char *tag_hex) {
    char *buf = (char *)malloc(640);
    if (buf == NULL) return NULL;
    int written = snprintf(buf, 640, ENVELOPE_TEMPLATE,
                           (unsigned)HYBRID_EK_LEN, (unsigned)HYBRID_CT_LEN,
                           tag_hex ? tag_hex : "");
    if (written < 0 || (size_t)written >= 640) {
        free(buf);
        return NULL;
    }
    return buf;
}

/* Extract the 64-hex confirmation_tag from an envelope. Returns 0 on success. */
static int parse_confirmation_tag(const char *env, uint8_t tag[32]) {
    static const char KEY[] = "\"confirmation_tag\":\"";
    const char *p;
    if (env == NULL || tag == NULL)
        return -1;
    p = strstr(env, KEY);
    if (p == NULL)
        return -1;
    p += sizeof(KEY) - 1;
    if (strlen(p) < CONFIRM_TAG_HEX_LEN + 1)
        return -1;
    for (size_t i = 0; i < 32; i++) {
        unsigned int byte = 0;
        char hi = p[2 * i], lo = p[2 * i + 1];
        if (hi >= '0' && hi <= '9') byte = (unsigned)(hi - '0') << 4;
        else if (hi >= 'a' && hi <= 'f') byte = (unsigned)(hi - 'a' + 10) << 4;
        else if (hi >= 'A' && hi <= 'F') byte = (unsigned)(hi - 'A' + 10) << 4;
        else return -1;
        if (lo >= '0' && lo <= '9') byte |= (unsigned)(lo - '0');
        else if (lo >= 'a' && lo <= 'f') byte |= (unsigned)(lo - 'a' + 10);
        else if (lo >= 'A' && lo <= 'F') byte |= (unsigned)(lo - 'A' + 10);
        else return -1;
        tag[i] = (uint8_t)byte;
    }
    if (p[CONFIRM_TAG_HEX_LEN] != '"')
        return -1;
    return 0;
}

static void bin_to_hex(const uint8_t *bin, size_t bin_len, char *hex_out) {
    static const char DIGITS[] = "0123456789abcdef";
    for (size_t i = 0; i < bin_len; i++) {
        hex_out[2 * i] = DIGITS[(bin[i] >> 4) & 0xF];
        hex_out[2 * i + 1] = DIGITS[bin[i] & 0xF];
    }
    hex_out[2 * bin_len] = '\0';
}

static int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
    for (size_t i = 0; i < bin_len; i++) {
        unsigned int hi = 0, lo = 0;
        if (hex[2 * i] >= '0' && hex[2 * i] <= '9') hi = hex[2 * i] - '0';
        else if (hex[2 * i] >= 'a' && hex[2 * i] <= 'f') hi = hex[2 * i] - 'a' + 10;
        else if (hex[2 * i] >= 'A' && hex[2 * i] <= 'F') hi = hex[2 * i] - 'A' + 10;
        else return PQBLOCKS_ERR_INVALID_ARGUMENT;
        if (hex[2 * i + 1] >= '0' && hex[2 * i + 1] <= '9') lo = hex[2 * i + 1] - '0';
        else if (hex[2 * i + 1] >= 'a' && hex[2 * i + 1] <= 'f') lo = hex[2 * i + 1] - 'a' + 10;
        else if (hex[2 * i + 1] >= 'A' && hex[2 * i + 1] <= 'F') lo = hex[2 * i + 1] - 'A' + 10;
        else return PQBLOCKS_ERR_INVALID_ARGUMENT;
        bin[i] = (uint8_t)((hi << 4) | lo);
    }
    return PQBLOCKS_SUCCESS;
}

/* Extract confirmation_tag hex string from JSON envelope. Returns PQBLOCKS_SUCCESS on found. */
static int extract_confirmation_tag(const char *env, char *tag_out, size_t tag_out_len) {
    const char *needle = "\"confirmation_tag\":\"";
    const char *start = strstr(env, needle);
    if (start == NULL) return PQBLOCKS_ERR_ENVELOPE_MISMATCH;
    start += strlen(needle);
    const char *end = strchr(start, '"');
    if (end == NULL) return PQBLOCKS_ERR_ENVELOPE_MISMATCH;
    size_t len = end - start;
    if (len >= tag_out_len) return PQBLOCKS_ERR_INVALID_LENGTH;
    memcpy(tag_out, start, len);
    tag_out[len] = '\0';
    return PQBLOCKS_SUCCESS;
}

/* HMAC-SHA256(key, data) -> 32-byte tag. Returns PQBLOCKS_SUCCESS or an error. */
static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t tag[32]) {
    unsigned int out_len = 0;
    if (key == NULL || data == NULL || tag == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;
    if (HMAC(EVP_sha256(), key, (int)key_len, data, data_len, tag, &out_len) == NULL)
        return PQBLOCKS_ERR_OUT_OF_MEMORY;
    if (out_len != 32)
        return PQBLOCKS_ERR_OUT_OF_MEMORY;
    return PQBLOCKS_SUCCESS;
}

static int envelope_ok(const char *env) {
    if (env == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;
    if (strstr(env, "\"kem\":\"X25519+MLKEM768\"") == NULL)
        return PQBLOCKS_ERR_ENVELOPE_MISMATCH;
    if (strstr(env, "\"suite_id\":\"X25519MLKEM768-Ed25519MLDSA65-HKDF\"") == NULL)
        return PQBLOCKS_ERR_ENVELOPE_MISMATCH;
    if (strstr(env, "\"kdf\":\"HKDF-SHA256\"") == NULL)
        return PQBLOCKS_ERR_KDF_MISMATCH;
    if (strstr(env, "\"key_confirm\":\"HMAC-SHA256\"") == NULL)
        return PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED;
    return PQBLOCKS_SUCCESS;
}

static int derive_hkdf_info(uint8_t *out, const uint8_t *hybrid_ss,
                             const uint8_t *salt, size_t salt_len,
                             const char *info, size_t info_len) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5];
    int ret = PQBLOCKS_SUCCESS;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        return PQBLOCKS_ERR_OUT_OF_MEMORY;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        return PQBLOCKS_ERR_OUT_OF_MEMORY;
    }

    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", (void *)hybrid_ss, 64);
    params[2] = OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len);
    params[3] = OSSL_PARAM_construct_octet_string("info", (void *)info, info_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, 32, params) <= 0) {
        ret = PQBLOCKS_ERR_OUT_OF_MEMORY;
    }
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int derive_hkdf(uint8_t *out, const uint8_t *hybrid_ss,
                       const uint8_t *salt, size_t salt_len) {
    return derive_hkdf_info(out, hybrid_ss, salt, salt_len,
                            "pqblocks-x25519-mlkem768-v1",
                            sizeof("pqblocks-x25519-mlkem768-v1") - 1);
}

static int x25519_ecdh(uint8_t *ss, const uint8_t my_priv[32], 
                       const uint8_t their_pub[32]) {
    EVP_PKEY *my_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ret = PQBLOCKS_SUCCESS;

    my_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, my_priv, 32);
    if (my_key == NULL)
        return PQBLOCKS_ERR_OUT_OF_MEMORY;

    ctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (ctx == NULL) {
        EVP_PKEY_free(my_key);
        return PQBLOCKS_ERR_OUT_OF_MEMORY;
    }

    EVP_PKEY *their_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, their_pub, 32);
    if (their_key == NULL) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(my_key);
        return PQBLOCKS_ERR_OUT_OF_MEMORY;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        ret = PQBLOCKS_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(ctx, their_key) <= 0) {
        ret = PQBLOCKS_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }

    size_t ss_len = 32;
    if (EVP_PKEY_derive(ctx, ss, &ss_len) <= 0) {
        ret = PQBLOCKS_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }

cleanup:
    EVP_PKEY_free(their_key);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(my_key);
    return ret;
}

static void deterministic_rng(uint8_t *random_array, size_t bytes_to_read) {
    for (size_t i = 0; i < bytes_to_read; i++) {
        random_array[i] = (uint8_t)((i * 37 + 0x42) & 0xFF);
    }
}

PQBLOCKS_KEM_X25519_MLKEM768 *PQBLOCKS_KEM_X25519_MLKEM768_new(void) {
    PQBLOCKS_KEM_X25519_MLKEM768 *kem =
        (PQBLOCKS_KEM_X25519_MLKEM768 *)calloc(1, sizeof(*kem));
    if (kem == NULL) return NULL;

    kem->mlkem768 = OQS_KEM_new("ML-KEM-768");
    if (kem->mlkem768 == NULL) {
        free(kem);
        return NULL;
    }

    OQS_STATUS st = kem->mlkem768->keypair(kem->ek, kem->dk);
    if (st != OQS_SUCCESS) {
        OQS_KEM_free(kem->mlkem768);
        free(kem);
        return NULL;
    }

    SHA256(kem->dk, 32, kem->x25519_priv);

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, 
                                                   kem->x25519_priv, X25519_PRIV_LEN);
    if (pkey == NULL) {
        OQS_KEM_free(kem->mlkem768);
        free(kem);
        return NULL;
    }

    size_t pub_len = X25519_PUB_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, kem->x25519_pub, &pub_len) != 1 || 
        pub_len != X25519_PUB_LEN) {
        EVP_PKEY_free(pkey);
        OQS_KEM_free(kem->mlkem768);
        free(kem);
        return NULL;
    }
    EVP_PKEY_free(pkey);

    return kem;
}

PQBLOCKS_KEM_X25519_MLKEM768 *PQBLOCKS_KEM_X25519_MLKEM768_new_seeded(
    const uint8_t seed[32]) {
    PQBLOCKS_KEM_X25519_MLKEM768 *kem =
        (PQBLOCKS_KEM_X25519_MLKEM768 *)calloc(1, sizeof(*kem));
    if (kem == NULL) return NULL;

    kem->mlkem768 = OQS_KEM_new("ML-KEM-768");
    if (kem->mlkem768 == NULL) {
        free(kem);
        return NULL;
    }

    OQS_randombytes_custom_algorithm(deterministic_rng);
    OQS_STATUS st = kem->mlkem768->keypair(kem->ek, kem->dk);
    OQS_randombytes_switch_algorithm("system");
    if (st != OQS_SUCCESS) {
        OQS_KEM_free(kem->mlkem768);
        free(kem);
        return NULL;
    }

    SHA256(kem->dk, 32, kem->x25519_priv);
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, 
                                                   kem->x25519_priv, X25519_PRIV_LEN);
    if (pkey != NULL) {
        size_t pub_len = X25519_PUB_LEN;
        EVP_PKEY_get_raw_public_key(pkey, kem->x25519_pub, &pub_len);
        EVP_PKEY_free(pkey);
    }
    kem->is_seeded = 1;
    memcpy(kem->seed, seed, 32);

    return kem;
}

void PQBLOCKS_KEM_X25519_MLKEM768_free(PQBLOCKS_KEM_X25519_MLKEM768 *kem) {
    if (kem == NULL) return;
    if (kem->mlkem768 != NULL) OQS_KEM_free(kem->mlkem768);
    free(kem);
}

int PQBLOCKS_KEM_X25519_MLKEM768_encaps(
    const PQBLOCKS_KEM_X25519_MLKEM768 *kem,
    uint8_t *ciphertext, size_t *ciphertext_len,
    uint8_t *shared_secret, size_t *shared_secret_len,
    char **envelope_json)
{
    if (kem == NULL || kem->mlkem768 == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;
    if (ciphertext == NULL || ciphertext_len == NULL ||
        shared_secret == NULL || shared_secret_len == NULL ||
        envelope_json == NULL)
        return PQBLOCKS_ERR_INVALID_ARGUMENT;

    if (*ciphertext_len < HYBRID_CT_LEN)
        return PQBLOCKS_ERR_INVALID_LENGTH;

    uint8_t ss_mlkem[MLKEM768_SS_LEN];
    if (kem->is_seeded) {
        OQS_randombytes_custom_algorithm(deterministic_rng);
    }
    OQS_STATUS status = kem->mlkem768->encaps(ciphertext, ss_mlkem, kem->ek);
    if (kem->is_seeded) {
        OQS_randombytes_switch_algorithm("system");
    }
    if (status != OQS_SUCCESS)
        return PQBLOCKS_ERR_KEM_ENCAPS;

    uint8_t eph_priv[X25519_PRIV_LEN];
    uint8_t eph_pub[X25519_PUB_LEN];
    if (kem->is_seeded) {
        memcpy(eph_priv, kem->seed, X25519_PRIV_LEN);
        memcpy(eph_pub, kem->seed, X25519_PUB_LEN);
    } else {
        if (RAND_bytes(eph_priv, X25519_PRIV_LEN) != 1)
            return PQBLOCKS_ERR_KEM_ENCAPS;

        EVP_PKEY *eph_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                          eph_priv, X25519_PRIV_LEN);
        if (!eph_key)
            return PQBLOCKS_ERR_KEM_ENCAPS;
        size_t pub_len = X25519_PUB_LEN;
        if (EVP_PKEY_get_raw_public_key(eph_key, eph_pub, &pub_len) != 1) {
            EVP_PKEY_free(eph_key);
            return PQBLOCKS_ERR_KEM_ENCAPS;
        }
        EVP_PKEY_free(eph_key);
    }

    uint8_t ss_x25519[32];
    if (x25519_ecdh(ss_x25519, eph_priv, kem->x25519_pub) != PQBLOCKS_SUCCESS)
        return PQBLOCKS_ERR_KEM_ENCAPS;

    uint8_t hybrid_ss[64];
    memcpy(hybrid_ss, ss_mlkem, 32);
    memcpy(hybrid_ss + 32, ss_x25519, 32);

    uint8_t salt[32] = {0};
    uint8_t derived_ss[32];
    if (derive_hkdf(derived_ss, hybrid_ss, salt, 32) != PQBLOCKS_SUCCESS)
        return PQBLOCKS_ERR_KEM_ENCAPS;

    /* Publish the final hybrid ciphertext first so the confirmation
       transcript below is computed over exactly what decaps will see. */
    memcpy(ciphertext + MLKEM768_CT_LEN, eph_pub, X25519_PUB_LEN);
    *ciphertext_len = HYBRID_CT_LEN;

    /* Compute HMAC-SHA256 confirmation_tag for key confirmation.
       Transcript (both sides identical): hybrid_ek (mlkem ek || x25519 pub)
       || hybrid_ct (mlkem ct || eph pub) || eph pub. */
    uint8_t confirm_tag[32];
    uint8_t transcript[HYBRID_EK_LEN + HYBRID_CT_LEN + 64];
    size_t transcript_len = 0;
    memcpy(transcript + transcript_len, kem->ek, MLKEM768_EK_LEN);
    transcript_len += MLKEM768_EK_LEN;
    memcpy(transcript + transcript_len, kem->x25519_pub, X25519_PUB_LEN);
    transcript_len += X25519_PUB_LEN;
    memcpy(transcript + transcript_len, ciphertext, HYBRID_CT_LEN);
    transcript_len += HYBRID_CT_LEN;
    memcpy(transcript + transcript_len, eph_pub, X25519_PUB_LEN);
    transcript_len += X25519_PUB_LEN;
    if (hmac_sha256(derived_ss, 32, transcript, transcript_len, confirm_tag) != PQBLOCKS_SUCCESS)
        return PQBLOCKS_ERR_OUT_OF_MEMORY;

    char confirm_tag_hex[CONFIRM_TAG_HEX_LEN + 1];
    bin_to_hex(confirm_tag, 32, confirm_tag_hex);

    memcpy(shared_secret, derived_ss, 32);
    *shared_secret_len = 32;

    char *env = build_envelope(confirm_tag_hex);
    if (env == NULL)
        return PQBLOCKS_ERR_OUT_OF_MEMORY;
    *envelope_json = env;

    return PQBLOCKS_SUCCESS;
}

int PQBLOCKS_KEM_X25519_MLKEM768_decaps(
    const PQBLOCKS_KEM_X25519_MLKEM768 *kem,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const char *envelope_json,
    uint8_t *shared_secret, size_t *shared_secret_len)
{
    if (kem == NULL || kem->mlkem768 == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;
    if (ciphertext == NULL || shared_secret == NULL ||
        shared_secret_len == NULL || envelope_json == NULL)
        return PQBLOCKS_ERR_NULL_POINTER;

    if (ciphertext_len < HYBRID_CT_LEN)
        return PQBLOCKS_ERR_INVALID_LENGTH;

    if (envelope_ok(envelope_json) != 0)
        return PQBLOCKS_ERR_ENVELOPE_MISMATCH;

    uint8_t mlkem_ct[MLKEM768_CT_LEN];
    memcpy(mlkem_ct, ciphertext, MLKEM768_CT_LEN);

    const uint8_t *x25519_ephemeral = ciphertext + MLKEM768_CT_LEN;

    /* Verify X25519 ephemeral key is on the curve */
    EVP_PKEY *eph_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                            x25519_ephemeral, X25519_PUB_LEN);
    if (eph_key == NULL)
        return PQBLOCKS_ERR_KEM_DECAPS;
    EVP_PKEY_free(eph_key);

    uint8_t ss_mlkem[MLKEM768_SS_LEN];
    OQS_STATUS status = kem->mlkem768->decaps(ss_mlkem, mlkem_ct, kem->dk);
    if (status != OQS_SUCCESS)
        return -121;

    uint8_t ss_x25519[32];
    if (x25519_ecdh(ss_x25519, kem->x25519_priv, x25519_ephemeral) != PQBLOCKS_SUCCESS)
        return -122;

    uint8_t hybrid_ss[64];
    memcpy(hybrid_ss, ss_mlkem, 32);
    memcpy(hybrid_ss + 32, ss_x25519, 32);

    uint8_t salt[32] = {0};
    uint8_t derived_ss[32];
    if (derive_hkdf(derived_ss, hybrid_ss, salt, 32) != PQBLOCKS_SUCCESS)
        return -123;

    /* Verify HMAC-SHA256 confirmation_tag from envelope if present */
    char envelope_tag_hex[CONFIRM_TAG_HEX_LEN + 1];
    if (extract_confirmation_tag(envelope_json, envelope_tag_hex, sizeof(envelope_tag_hex)) == PQBLOCKS_SUCCESS) {
        uint8_t expected_tag[32];
        uint8_t transcript[HYBRID_EK_LEN + HYBRID_CT_LEN + 64];
        size_t transcript_len = 0;
        memcpy(transcript + transcript_len, kem->ek, MLKEM768_EK_LEN);
        transcript_len += MLKEM768_EK_LEN;
        memcpy(transcript + transcript_len, kem->x25519_pub, X25519_PUB_LEN);
        transcript_len += X25519_PUB_LEN;
        memcpy(transcript + transcript_len, ciphertext, HYBRID_CT_LEN);
        transcript_len += HYBRID_CT_LEN;
        memcpy(transcript + transcript_len, x25519_ephemeral, X25519_PUB_LEN);
        transcript_len += X25519_PUB_LEN;
        if (hmac_sha256(derived_ss, 32, transcript, transcript_len, expected_tag) != PQBLOCKS_SUCCESS)
            return PQBLOCKS_ERR_OUT_OF_MEMORY;

        uint8_t tag_buf[32];
        if (hex_to_bin(envelope_tag_hex, tag_buf, 32) != PQBLOCKS_SUCCESS)
            return PQBLOCKS_ERR_ENVELOPE_MISMATCH;
        if (memcmp(expected_tag, tag_buf, 32) != 0) {
            return PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED;
        }
    }

    memcpy(shared_secret, derived_ss, 32);
    *shared_secret_len = 32;
    return PQBLOCKS_SUCCESS;
}

int PQBLOCKS_KEM_X25519_MLKEM768_export_keys(
    const PQBLOCKS_KEM_X25519_MLKEM768 *kem,
    uint8_t **ek, size_t *ek_len,
    uint8_t **dk, size_t *dk_len,
    uint8_t **x25519_pub, size_t *x25519_pub_len
) {
    if (kem == NULL) return PQBLOCKS_ERR_NULL_POINTER;

    if (ek != NULL && ek_len != NULL) {
        *ek = (uint8_t *)malloc(HYBRID_EK_LEN);
        if (*ek == NULL) return PQBLOCKS_ERR_OUT_OF_MEMORY;
        memcpy(*ek, kem->ek, MLKEM768_EK_LEN);
        memcpy(*ek + MLKEM768_EK_LEN, kem->x25519_pub, X25519_PUB_LEN);
        *ek_len = HYBRID_EK_LEN;
    }

    if (dk != NULL && dk_len != NULL) {
        *dk = (uint8_t *)malloc(MLKEM768_DK_LEN);
        if (*dk == NULL) {
            if (ek != NULL) free(*ek);
            return PQBLOCKS_ERR_OUT_OF_MEMORY;
        }
        memcpy(*dk, kem->dk, MLKEM768_DK_LEN);
        *dk_len = MLKEM768_DK_LEN;
    }

    if (x25519_pub != NULL && x25519_pub_len != NULL) {
        *x25519_pub = (uint8_t *)malloc(X25519_PUB_LEN);
        if (*x25519_pub == NULL) {
            if (ek != NULL) free(*ek);
            if (dk != NULL) free(*dk);
            return PQBLOCKS_ERR_OUT_OF_MEMORY;
        }
        memcpy(*x25519_pub, kem->x25519_pub, X25519_PUB_LEN);
        *x25519_pub_len = X25519_PUB_LEN;
    }

    return PQBLOCKS_SUCCESS;
}

int PQBLOCKS_KEM_X25519_MLKEM768_import_keys(
    PQBLOCKS_KEM_X25519_MLKEM768 *kem,
    const uint8_t *ek, size_t ek_len,
    const uint8_t *dk, size_t dk_len,
    const uint8_t *x25519_pub, size_t x25519_pub_len
) {
    if (kem == NULL) return PQBLOCKS_ERR_NULL_POINTER;

    if (ek != NULL) {
        if (ek_len == MLKEM768_EK_LEN) {
            memcpy(kem->ek, ek, MLKEM768_EK_LEN);
        } else if (ek_len == HYBRID_EK_LEN) {
            memcpy(kem->ek, ek, MLKEM768_EK_LEN);
            memcpy(kem->x25519_pub, ek + MLKEM768_EK_LEN, X25519_PUB_LEN);
        } else {
            return PQBLOCKS_ERR_INVALID_LENGTH;
        }
    }

    if (x25519_pub != NULL) {
        if (x25519_pub_len != X25519_PUB_LEN) return PQBLOCKS_ERR_INVALID_LENGTH;
        memcpy(kem->x25519_pub, x25519_pub, X25519_PUB_LEN);
    }

    if (dk != NULL) {
        if (dk_len != MLKEM768_DK_LEN && dk_len != MLKEM768_EK_LEN) return PQBLOCKS_ERR_INVALID_LENGTH;
        memcpy(kem->dk, dk, dk_len);
        SHA256(kem->dk, 32, kem->x25519_priv);
    }

    return PQBLOCKS_SUCCESS;
}