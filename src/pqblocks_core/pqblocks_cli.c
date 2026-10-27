/*
 * pqblocks_cli.c - CLI Tool (S:6)
 *
 * Implements the `pqblocks` command-line tool as specified in §12.
 * Binds to the C core library via dynamic loading (dlopen).
 *
 * Usage:
 *   pqblocks kem keygen --out file.json
 *   pqblocks kem encaps --in file.json --out file.json
 *   pqblocks kem decaps --in file.json --out file.key
 *   pqblocks sig keygen --out file.json
 *   pqblocks sig sign --in file.json --msg message.txt --out sig.bin
 *   pqblocks sig verify --in file.json --msg message.txt --sig sig.bin
 *
 * Key material is persisted in the JSON files (base64-encoded) so that
 * sign/verify and encaps/decaps use the same keys across invocations.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>
#include "pqblocks_errors.h"
#include <math.h>
#include <sys/stat.h>

/* Error codes (subset from §7) */
#define PQBLOCKS_SUCCESS 0
#define PQBLOCKS_ERR_INVALID_ARGUMENT -1
#define PQBLOCKS_ERR_NULL_POINTER -3
#define PQBLOCKS_ERR_FILE_IO -99
#define PQBLOCKS_ERR_UNKNOWN_COMMAND -100

/* Key sizes (from C library defines) */
#define MLKEM768_EK_LEN 1184
#define MLKEM768_DK_LEN 2400
#define X25519_PUB_LEN 32
#define MLDSA65_PK_LEN 1952
#define MLDSA65_SK_LEN 4032
#define ED25519_PK_LEN 32
#define ED25519_SK_LEN 32

/* Function pointer types for KEM */
typedef void* (*KemNewFn)(void);
typedef void (*KemFreeFn)(void*);
typedef int (*KemEncapsFn)(const void*, uint8_t*, size_t*, uint8_t*, size_t*, char**);
typedef int (*KemDecapsFn)(const void*, const uint8_t*, size_t, const char*, uint8_t*, size_t*);
typedef int (*KemExportKeysFn)(const void*, uint8_t**, size_t*, uint8_t**, size_t*, uint8_t**, size_t*);
typedef int (*KemImportKeysFn)(void*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);

/* Function pointer types for SIG */
typedef void* (*SigNewFn)(void);
typedef void (*SigFreeFn)(void*);
typedef int (*SigSignFn)(const void*, const uint8_t*, size_t, uint8_t*, size_t*, char**);
typedef int (*SigVerifyFn)(const void*, const uint8_t*, size_t, const uint8_t*, size_t, const char*);
typedef int (*SigExportKeysFn)(const void*, uint8_t**, size_t*, uint8_t**, size_t*, uint8_t**, size_t*, uint8_t**, size_t*);
typedef int (*SigImportKeysFn)(void*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);

/* Global function pointers */
static KemNewFn kem_new_fn = NULL;
static KemFreeFn kem_free_fn = NULL;
static KemEncapsFn kem_encaps_fn = NULL;
static KemDecapsFn kem_decaps_fn = NULL;
static KemExportKeysFn kem_export_keys_fn = NULL;
static KemImportKeysFn kem_import_keys_fn = NULL;

static SigNewFn sig_new_fn = NULL;
static SigFreeFn sig_free_fn = NULL;
static SigSignFn sig_sign_fn = NULL;
static SigVerifyFn sig_verify_fn = NULL;
static SigExportKeysFn sig_export_keys_fn = NULL;
static SigImportKeysFn sig_import_keys_fn = NULL;

static void* kem_lib_handle = NULL;
static void* sig_lib_handle = NULL;

/* Load the KEM library */
static int load_kem_library(void) {
    if (kem_lib_handle != NULL)
        return PQBLOCKS_SUCCESS;

    kem_lib_handle = dlopen("libpqblocks_kem.so", RTLD_NOW);
    if (kem_lib_handle == NULL) {
        kem_lib_handle = dlopen("libpqblocks_kem.so", RTLD_NOW);
    }
    if (kem_lib_handle == NULL) {
        fprintf(stderr, "Error: Failed to load KEM library: %s\n", dlerror());
        return PQBLOCKS_ERR_FILE_IO;
    }

    kem_new_fn = (KemNewFn)dlsym(kem_lib_handle, "PQBLOCKS_KEM_X25519_MLKEM768_new");
    kem_free_fn = (KemFreeFn)dlsym(kem_lib_handle, "PQBLOCKS_KEM_X25519_MLKEM768_free");
    kem_encaps_fn = (KemEncapsFn)dlsym(kem_lib_handle, "PQBLOCKS_KEM_X25519_MLKEM768_encaps");
    kem_decaps_fn = (KemDecapsFn)dlsym(kem_lib_handle, "PQBLOCKS_KEM_X25519_MLKEM768_decaps");
    kem_export_keys_fn = (KemExportKeysFn)dlsym(kem_lib_handle, "PQBLOCKS_KEM_X25519_MLKEM768_export_keys");
    kem_import_keys_fn = (KemImportKeysFn)dlsym(kem_lib_handle, "PQBLOCKS_KEM_X25519_MLKEM768_import_keys");

    if (kem_new_fn == NULL || kem_free_fn == NULL || kem_encaps_fn == NULL || kem_decaps_fn == NULL) {
        fprintf(stderr, "Error: Missing core KEM symbols in libpqblocks_kem.so\n");
        dlclose(kem_lib_handle);
        kem_lib_handle = NULL;
        return PQBLOCKS_ERR_FILE_IO;
    }

    return PQBLOCKS_SUCCESS;
}

/* Load the SIG library */
static int load_sig_library(void) {
    if (sig_lib_handle != NULL)
        return PQBLOCKS_SUCCESS;

    sig_lib_handle = dlopen("libpqblocks_sig.so", RTLD_NOW);
    if (sig_lib_handle == NULL) {
        sig_lib_handle = dlopen("libpqblocks_sig.so", RTLD_NOW);
    }
    if (sig_lib_handle == NULL) {
        fprintf(stderr, "Error: Failed to load SIG library: %s\n", dlerror());
        return PQBLOCKS_ERR_FILE_IO;
    }

    sig_new_fn = (SigNewFn)dlsym(sig_lib_handle, "PQBLOCKS_SIG_ED25519_MLDSA65_new");
    sig_free_fn = (SigFreeFn)dlsym(sig_lib_handle, "PQBLOCKS_SIG_ED25519_MLDSA65_free");
    sig_sign_fn = (SigSignFn)dlsym(sig_lib_handle, "PQBLOCKS_SIG_ED25519_MLDSA65_sign");
    sig_verify_fn = (SigVerifyFn)dlsym(sig_lib_handle, "PQBLOCKS_SIG_ED25519_MLDSA65_verify");
    sig_export_keys_fn = (SigExportKeysFn)dlsym(sig_lib_handle, "PQBLOCKS_SIG_ED25519_MLDSA65_export_keys");
    sig_import_keys_fn = (SigImportKeysFn)dlsym(sig_lib_handle, "PQBLOCKS_SIG_ED25519_MLDSA65_import_keys");

    if (sig_new_fn == NULL || sig_free_fn == NULL || sig_sign_fn == NULL || sig_verify_fn == NULL) {
        fprintf(stderr, "Error: Missing core SIG symbols in libpqblocks_sig.so\n");
        dlclose(sig_lib_handle);
        sig_lib_handle = NULL;
        return PQBLOCKS_ERR_FILE_IO;
    }

    return PQBLOCKS_SUCCESS;
}

/*
 * Base64 encoding/decoding for key material storage in JSON files.
 * We use a simple base64 implementation to avoid external dependencies.
 */

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encode binary data to base64 string (caller must free). Returns NULL on failure. */
static char *b64_encode(const uint8_t *data, size_t len) {
    if (data == NULL || len == 0)
        return strdup("");

    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char *out = (char *)malloc(out_len);
    if (out == NULL)
        return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t triple = 0;
        int remaining = (int)(len - i);
        uint8_t b0, b1, b2;

        b0 = data[i];
        i++;
        b1 = (remaining > 1) ? data[i] : 0;
        if (remaining > 1) i++;
        b2 = (remaining > 2) ? data[i] : 0;
        if (remaining > 2) i++;

        triple = ((uint32_t)b0 << 16) | ((uint32_t)b1 << 8) | (uint32_t)b2;

        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (remaining > 1) ? b64_table[(triple >> 6) & 0x3F] : '=';
        out[j++] = (remaining > 2) ? b64_table[triple & 0x3F] : '=';
    }
    out[j] = '\0';
    return out;
}

static int b64_char_to_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Decode base64 string to binary. Returns malloc'd buffer (caller must free).
   Returns NULL on failure, *out_len set to 0. */
static uint8_t *b64_decode(const char *b64str, size_t *out_len) {
    if (b64str == NULL)
        return NULL;

    size_t b64_len = strlen(b64str);
    /* Remove padding */
    size_t padded = b64_len;
    while (padded > 0 && b64str[padded - 1] == '=')
        padded--;

    size_t out_size = (padded * 3) / 4 + 1;
    uint8_t *out = (uint8_t *)malloc(out_size);
    if (out == NULL)
        return NULL;

    size_t i, j;
    int bits = 0;
    uint32_t acc = 0;

    for (i = 0, j = 0; i < padded; i++) {
        int v = b64_char_to_val(b64str[i]);
        if (v < 0) {
            free(out);
            *out_len = 0;
            return NULL;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }

    *out_len = j;
    return out;
}

/* JSON string escaping helper: escape backslashes and quotes for JSON string values */
static char *json_escape(const char *input) {
    size_t in_len = strlen(input);
    size_t out_cap = in_len * 2 + 1;
    char *out = (char *)malloc(out_cap);
    if (out == NULL)
        return NULL;

    size_t i, j = 0;
    for (i = 0; i < in_len; i++) {
        char c = input[i];
        switch (c) {
            case '"': out[j++] = '\\'; out[j++] = '"'; break;
            case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
            case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
            case '\t': out[j++] = '\\'; out[j++] = 't'; break;
            case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
            default: out[j++] = c; break;
        }
    }
    out[j] = '\0';
    return out;
}

/* Write JSON content to a file */
static int write_json_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        perror("fopen write");
        return PQBLOCKS_ERR_FILE_IO;
    }
    fprintf(f, "%s", content);
    fclose(f);
    return PQBLOCKS_SUCCESS;
}

/* Read JSON content from a file */
static int read_json_file(const char *path, char **out_content) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        perror("fopen read");
        return PQBLOCKS_ERR_FILE_IO;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = (char *)malloc((size_t)size + 1);
    if (content == NULL) {
        fclose(f);
        return PQBLOCKS_ERR_FILE_IO;
    }

    size_t bytes_read = fread(content, 1, (size_t)size, f);
    if (bytes_read != (size_t)size) {
        fprintf(stderr, "Error: Failed to read %s\n", path);
        free(content);
        fclose(f);
        return PQBLOCKS_ERR_FILE_IO;
    }
    content[size] = '\0';
    fclose(f);

    *out_content = content;
    return PQBLOCKS_SUCCESS;
}

/* Write binary data to a file */
static int write_binary_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        perror("fopen write-binary");
        return PQBLOCKS_ERR_FILE_IO;
    }
    fwrite(data, 1, len, f);
    fclose(f);
    return PQBLOCKS_SUCCESS;
}

/* Read binary data from a file */
static int read_binary_file(const char *path, uint8_t **out_data, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        perror("fopen read-binary");
        return PQBLOCKS_ERR_FILE_IO;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = (uint8_t *)malloc((size_t)size + 1);
    if (data == NULL) {
        fclose(f);
        return PQBLOCKS_ERR_FILE_IO;
    }

    size_t bytes_read = fread(data, 1, (size_t)size, f);
    if (bytes_read != (size_t)size) {
        fprintf(stderr, "Error: Failed to read %s\n", path);
        free(data);
        fclose(f);
        return PQBLOCKS_ERR_FILE_IO;
    }
    fclose(f);

    *out_data = data;
    *out_len = (size_t)size;
    return PQBLOCKS_SUCCESS;
}

/* Parse simple arguments: extract --key value pairs */
static int parse_simple_arg(int argc, char **argv, const char *key, char **value) {
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], key) == 0) {
            *value = argv[i + 1];
            return PQBLOCKS_SUCCESS;
        }
    }
    return PQBLOCKS_ERR_INVALID_ARGUMENT;
}

/* Extract a base64-encoded value from a JSON string by key.
   Finds `"key":"value"` or `"key":value` pattern.
   Returns malloc'd string (caller must free), or NULL if not found. */
static char *json_get_string(const char *json, const char *key) {
    char *search = (char *)malloc(strlen(json) + 1);
    if (search == NULL) return NULL;
    strcpy(search, json);

    /* Find the key */
    char *key_pattern = (char *)malloc(strlen(key) + 8);
    if (key_pattern == NULL) { free(search); return NULL; }
    sprintf(key_pattern, "\"%s\":", key);

    char *found = strstr(search, key_pattern);
    size_t key_pattern_len = strlen(key_pattern);
    free(key_pattern);
    if (found == NULL) {
        free(search);
        return NULL;
    }

    found += key_pattern_len;
    while (*found == ' ' || *found == '\t' || *found == '\r' || *found == '\n') {
        found++;
    }

    /* Check if value is a string (starts with quote) */
    if (*found == '"') {
        found++;
        char *end = strchr(found, '"');
        if (end == NULL) {
            free(search);
            return NULL;
        }
        *end = '\0';
        char *result = strdup(found);
        free(search);
        return result;
    }

    /* Otherwise it's a number or other token - skip it */
    free(search);
    return NULL;
}

/* KEM keygen command: generate keys, persist to JSON file */
static int cmd_kem_keygen(int argc, char **argv) {
    char *out_file = NULL;
    if (parse_simple_arg(argc, argv, "--out", &out_file) != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Missing --out argument\n");
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    if (load_kem_library() != PQBLOCKS_SUCCESS)
        return PQBLOCKS_ERR_FILE_IO;

    void *kem = kem_new_fn();
    if (kem == NULL) {
        fprintf(stderr, "Error: Failed to create KEM object\n");
        return PQBLOCKS_ERR_NULL_POINTER;
    }

    /* Export key material */
    uint8_t *ek = NULL; size_t ek_len = 0;
    uint8_t *dk = NULL; size_t dk_len = 0;
    uint8_t *x25519_pub = NULL; size_t x25519_pub_len = 0;

    if (kem_export_keys_fn != NULL) {
        int ret = kem_export_keys_fn(kem, &ek, &ek_len, &dk, &dk_len, &x25519_pub, &x25519_pub_len);
        if (ret != PQBLOCKS_SUCCESS) {
            fprintf(stderr, "Error: Failed to export KEM keys, code %d\n", ret);
            kem_free_fn(kem);
            return ret;
        }
    } else {
        fprintf(stderr, "Error: KEM export_keys not available\n");
        kem_free_fn(kem);
        return PQBLOCKS_ERR_FILE_IO;
    }

    /* Build base64-encoded key material */
    char *ek_b64 = b64_encode(ek, ek_len);
    char *dk_b64 = b64_encode(dk, dk_len);
    char *x25519_b64 = b64_encode(x25519_pub, x25519_pub_len);

    if (ek_b64 == NULL || dk_b64 == NULL || x25519_b64 == NULL) {
        fprintf(stderr, "Error: Failed to encode key material\n");
        free(ek_b64); free(dk_b64); free(x25519_b64);
        free(ek); free(dk); free(x25519_pub);
        kem_free_fn(kem);
        return PQBLOCKS_ERR_FILE_IO;
    }

    /* Build JSON content with envelope + key material */
    char *ek_esc = json_escape(ek_b64);
    char *dk_esc = json_escape(dk_b64);
    char *x25519_esc = json_escape(x25519_b64);

    int json_len = 1024 + strlen(ek_esc) + strlen(dk_esc) + strlen(x25519_esc);
    char *json_content = (char *)malloc(json_len);
    if (json_content == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        free(ek_esc); free(dk_esc); free(x25519_esc);
        free(ek_b64); free(dk_b64); free(x25519_b64);
        free(ek); free(dk); free(x25519_pub);
        kem_free_fn(kem);
        return PQBLOCKS_ERR_FILE_IO;
    }

    sprintf(json_content,
        "{\"kem\":\"X25519+MLKEM768\","
        "\"kdf\":\"HKDF-SHA256\","
        "\"key_confirm\":\"HMAC-SHA256\","
        "\"suite_id\":\"X25519MLKEM768-Ed25519MLDSA65-HKDF\","
        "\"version\":\"1.0.0\","
        "\"ek_len\":1216,"
        "\"ct_len\":1120,"
        "\"ek_b64\":\"%s\","
        "\"dk_b64\":\"%s\","
        "\"x25519_pub_b64\":\"%s\"}\n",
        ek_esc, dk_esc, x25519_esc);

    int ret = write_json_file(out_file, json_content);

    free(json_content);
    free(ek_esc); free(dk_esc); free(x25519_esc);
    free(ek_b64); free(dk_b64); free(x25519_b64);
    free(ek); free(dk); free(x25519_pub);
    kem_free_fn(kem);

    return ret;
}

/* KEM encaps command: read keys, encapsulate, write ciphertext + envelope */
static int cmd_kem_encaps(int argc, char **argv) {
    char *in_file = NULL;
    char *out_file = NULL;
    if (parse_simple_arg(argc, argv, "--in", &in_file) != PQBLOCKS_SUCCESS ||
        parse_simple_arg(argc, argv, "--out", &out_file) != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Missing --in or --out argument\n");
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    if (load_kem_library() != PQBLOCKS_SUCCESS)
        return PQBLOCKS_ERR_FILE_IO;

    /* Read the key file (JSON with key material) */
    char *json_content = NULL;
    int io_ret = read_json_file(in_file, &json_content);
    if (io_ret != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Cannot read input file %s\n", in_file);
        return io_ret;
    }

    /* Extract key material */
    char *ek_b64 = json_get_string(json_content, "ek_b64");
    char *dk_b64 = json_get_string(json_content, "dk_b64");
    char *x25519_b64 = json_get_string(json_content, "x25519_pub_b64");

    if (ek_b64 == NULL || dk_b64 == NULL || x25519_b64 == NULL) {
        fprintf(stderr, "Error: Key material not found in %s\n", in_file);
        free(json_content);
        free(ek_b64); free(dk_b64); free(x25519_b64);
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    /* Decode key material */
    size_t ek_len, dk_len, x25519_len;
    uint8_t *ek = b64_decode(ek_b64, &ek_len);
    uint8_t *dk = b64_decode(dk_b64, &dk_len);
    uint8_t *x25519_pub = b64_decode(x25519_b64, &x25519_len);

    free(ek_b64); free(dk_b64); free(x25519_b64);

    if (ek == NULL || dk == NULL || x25519_pub == NULL) {
        fprintf(stderr, "Error: Failed to decode key material\n");
        free(ek); free(dk); free(x25519_pub);
        free(json_content);
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    /* Create KEM object and import keys */
    void *kem = kem_new_fn();
    if (kem == NULL) {
        fprintf(stderr, "Error: Failed to create KEM object\n");
        free(ek); free(dk); free(x25519_pub);
        free(json_content);
        return PQBLOCKS_ERR_NULL_POINTER;
    }

    if (kem_import_keys_fn != NULL) {
        int ret = kem_import_keys_fn(kem, ek, ek_len, dk, dk_len, x25519_pub, x25519_len);
        if (ret != PQBLOCKS_SUCCESS) {
            fprintf(stderr, "Error: Failed to import KEM keys, code %d\n", ret);
            kem_free_fn(kem);
            free(ek); free(dk); free(x25519_pub);
            free(json_content);
            return ret;
        }
    }

    /* Encapsulate */
    size_t ct_len = 1120;
    size_t ss_len = 32;
    uint8_t *ciphertext = (uint8_t *)malloc(ct_len);
    uint8_t *shared_secret = (uint8_t *)malloc(ss_len);
    char *envelope_json = NULL;

    int ret = kem_encaps_fn(kem, ciphertext, &ct_len, shared_secret, &ss_len, &envelope_json);
    if (ret != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Encaps failed with code %d\n", ret);
        free(ciphertext); free(shared_secret);
        kem_free_fn(kem);
        free(ek); free(dk); free(x25519_pub);
        free(json_content);
        return ret;
    }

    /* Base64-encode the ciphertext for storage.
       The encaps output also carries the key material (ek/dk/x25519) so that
       `pqblocks kem decaps --in encaps.json` works standalone per spec §12
       quickstart (single --in file). Key material in this file is the
       caller's own keypair, not a secret leak beyond their key file. */
    char *ct_b64 = b64_encode(ciphertext, ct_len);
    char *ct_esc = json_escape(ct_b64);
    char *ek_out_b64 = b64_encode(ek, ek_len);
    char *dk_out_b64 = b64_encode(dk, dk_len);
    char *x_out_b64 = b64_encode(x25519_pub, x25519_len);
    char *ek_out_esc = json_escape(ek_out_b64);
    char *dk_out_esc = json_escape(dk_out_b64);
    char *x_out_esc = json_escape(x_out_b64);

    /* Thread the lib-produced confirmation_tag into the stored envelope so
       decaps can verify key confirmation against the same transcript. */
    char *confirm_tag = json_get_string(envelope_json, "confirmation_tag");
    if (confirm_tag == NULL || strlen(confirm_tag) != 64) {
        fprintf(stderr, "Error: Encaps envelope lacks confirmation_tag\n");
        free(confirm_tag);
        free(ct_b64); free(ct_esc);
        free(ek_out_b64); free(dk_out_b64); free(x_out_b64);
        free(ek_out_esc); free(dk_out_esc); free(x_out_esc);
        free(ciphertext); free(shared_secret);
        free(envelope_json);
        kem_free_fn(kem);
        free(ek); free(dk); free(x25519_pub);
        free(json_content);
        return PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED;
    }

    /* Build output JSON: envelope + ciphertext + key material */
    int json_len = 2048 + strlen(ct_esc) + strlen(ek_out_esc)
        + strlen(dk_out_esc) + strlen(x_out_esc) + strlen(confirm_tag);
    char *output_json = (char *)malloc(json_len);
    if (output_json == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        free(ct_b64); free(ct_esc);
        free(ek_out_b64); free(dk_out_b64); free(x_out_b64);
        free(ek_out_esc); free(dk_out_esc); free(x_out_esc);
        free(ciphertext); free(shared_secret);
        free(envelope_json);
        kem_free_fn(kem);
        free(ek); free(dk); free(x25519_pub);
        free(json_content);
        return PQBLOCKS_ERR_FILE_IO;
    }

    sprintf(output_json,
        "{\"kem\":\"X25519+MLKEM768\","
        "\"kdf\":\"HKDF-SHA256\","
        "\"key_confirm\":\"HMAC-SHA256\","
        "\"suite_id\":\"X25519MLKEM768-Ed25519MLDSA65-HKDF\","
        "\"version\":\"1.0.0\","
        "\"ek_len\":1216,"
        "\"ct_len\":1120,"
        "\"confirmation_tag\":\"%s\","
        "\"ct_b64\":\"%s\","
        "\"ek_b64\":\"%s\","
        "\"dk_b64\":\"%s\","
        "\"x25519_pub_b64\":\"%s\"}\n",
        confirm_tag, ct_esc, ek_out_esc, dk_out_esc, x_out_esc);

    int io_ret2 = write_json_file(out_file, output_json);

    free(output_json);
    free(confirm_tag);
    free(ct_b64); free(ct_esc);
    free(ek_out_b64); free(dk_out_b64); free(x_out_b64);
    free(ek_out_esc); free(dk_out_esc); free(x_out_esc);
    free(ciphertext); free(shared_secret);
    free(envelope_json);
    kem_free_fn(kem);
    free(ek); free(dk); free(x25519_pub);
    free(json_content);

    return io_ret2;
}

/* KEM decaps command: read ciphertext + keys, decapsulate, write shared secret */
static int cmd_kem_decaps(int argc, char **argv) {
    char *in_file = NULL;
    char *out_file = NULL;
    if (parse_simple_arg(argc, argv, "--in", &in_file) != PQBLOCKS_SUCCESS ||
        parse_simple_arg(argc, argv, "--out", &out_file) != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Missing --in or --out argument\n");
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    if (load_kem_library() != PQBLOCKS_SUCCESS)
        return PQBLOCKS_ERR_FILE_IO;

    /* Read the encapsulated data (JSON with envelope + ciphertext) */
    char *json_content = NULL;
    int io_ret = read_json_file(in_file, &json_content);
    if (io_ret != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Cannot read input file %s\n", in_file);
        return io_ret;
    }

    char *dk_b64 = json_get_string(json_content, "dk_b64");
    char *ct_b64 = json_get_string(json_content, "ct_b64");
    char *ek_b64 = json_get_string(json_content, "ek_b64");
    char *x25519_b64 = json_get_string(json_content, "x25519_pub_b64");
    char *confirm_tag = json_get_string(json_content, "confirmation_tag");

    if (dk_b64 == NULL || ct_b64 == NULL || ek_b64 == NULL || x25519_b64 == NULL) {
        fprintf(stderr, "Error: Key material not found in %s\n", in_file);
        free(dk_b64); free(ct_b64); free(ek_b64); free(x25519_b64);
        free(confirm_tag);
        free(json_content);
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }
    if (confirm_tag == NULL || strlen(confirm_tag) != 64) {
        fprintf(stderr, "Error: confirmation_tag missing in %s (key confirmation required)\n", in_file);
        free(dk_b64); free(ct_b64); free(ek_b64); free(x25519_b64);
        free(confirm_tag);
        free(json_content);
        return PQBLOCKS_ERR_KEY_CONFIRMATION_FAILED;
    }

    size_t dk_len, ct_len, ek_len, x_len;
    uint8_t *dk = b64_decode(dk_b64, &dk_len);
    uint8_t *ciphertext = b64_decode(ct_b64, &ct_len);
    uint8_t *ek = b64_decode(ek_b64, &ek_len);
    uint8_t *x_pub = b64_decode(x25519_b64, &x_len);

    free(dk_b64); free(ct_b64); free(ek_b64); free(x25519_b64);

    if (dk == NULL || ciphertext == NULL || ek == NULL || x_pub == NULL) {
        fprintf(stderr, "Error: Failed to decode data\n");
        free(dk); free(ciphertext); free(ek); free(x_pub);
        free(json_content);
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    void *kem = kem_new_fn();
    if (kem == NULL) {
        fprintf(stderr, "Error: Failed to create KEM object\n");
        free(dk); free(ciphertext); free(ek); free(x_pub);
        free(json_content);
        return PQBLOCKS_ERR_NULL_POINTER;
    }

    if (kem_import_keys_fn != NULL) {
        int imp = kem_import_keys_fn(kem, ek, ek_len, dk, dk_len, x_pub, x_len);
        if (imp != PQBLOCKS_SUCCESS) {
            fprintf(stderr, "Error: Failed to import KEM keys, code %d (ek_len=%zu dk_len=%zu x_len=%zu dk_start=%.10s)\n", imp, ek_len, dk_len, x_len, dk_b64);
            kem_free_fn(kem);
            free(dk); free(ciphertext); free(ek); free(x_pub);
            free(json_content);
            return imp;
        }
    }
    free(ek); free(x_pub);

    char envelope_template[1024];
    snprintf(envelope_template, sizeof(envelope_template),
        "{\"kem\":\"X25519+MLKEM768\","
        "\"kdf\":\"HKDF-SHA256\","
        "\"key_confirm\":\"HMAC-SHA256\","
        "\"suite_id\":\"X25519MLKEM768-Ed25519MLDSA65-HKDF\","
        "\"version\":\"1.0.0\","
        "\"ek_len\":1216,"
        "\"ct_len\":1120,"
        "\"confirmation_tag\":\"%s\"}",
        confirm_tag);

    size_t ss_len = 32;
    uint8_t *shared_secret = (uint8_t *)malloc(ss_len);

    int ret = kem_decaps_fn(kem, ciphertext, ct_len, envelope_template, shared_secret, &ss_len);
    if (ret != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Decaps failed with code %d\n", ret);
        free(shared_secret);
        kem_free_fn(kem);
        free(dk); free(ciphertext);
        free(confirm_tag);
        free(json_content);
        return ret;
    }

    int io_ret2 = write_binary_file(out_file, shared_secret, ss_len);

    free(shared_secret);
    kem_free_fn(kem);
    free(dk); free(ciphertext);
    free(confirm_tag);
    free(json_content);

    return io_ret2;
}

/* SIG keygen command: generate keys, persist to JSON file */
static int cmd_sig_keygen(int argc, char **argv) {
    char *out_file = NULL;
    if (parse_simple_arg(argc, argv, "--out", &out_file) != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Missing --out argument\n");
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    if (load_sig_library() != PQBLOCKS_SUCCESS)
        return PQBLOCKS_ERR_FILE_IO;

    void *sig = sig_new_fn();
    if (sig == NULL) {
        fprintf(stderr, "Error: Failed to create SIG object\n");
        return PQBLOCKS_ERR_NULL_POINTER;
    }

    /* Export key material */
    uint8_t *mldsa_pk = NULL; size_t mldsa_pk_len = 0;
    uint8_t *mldsa_sk = NULL; size_t mldsa_sk_len = 0;
    uint8_t *ed25519_pk = NULL; size_t ed25519_pk_len = 0;
    uint8_t *ed25519_sk = NULL; size_t ed25519_sk_len = 0;

    if (sig_export_keys_fn == NULL) {
        fprintf(stderr, "Error: SIG export_keys not available\n");
        sig_free_fn(sig);
        return PQBLOCKS_ERR_FILE_IO;
    }

    int ret = sig_export_keys_fn(sig,
        &mldsa_pk, &mldsa_pk_len,
        &mldsa_sk, &mldsa_sk_len,
        &ed25519_pk, &ed25519_pk_len,
        &ed25519_sk, &ed25519_sk_len);

    if (ret != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Failed to export SIG keys, code %d\n", ret);
        sig_free_fn(sig);
        return ret;
    }

    /* Build base64-encoded key material */
    char *mldsa_pk_b64 = b64_encode(mldsa_pk, mldsa_pk_len);
    char *mldsa_sk_b64 = b64_encode(mldsa_sk, mldsa_sk_len);
    char *ed25519_pk_b64 = b64_encode(ed25519_pk, ed25519_pk_len);
    char *ed25519_sk_b64 = b64_encode(ed25519_sk, ed25519_sk_len);

    if (mldsa_pk_b64 == NULL || mldsa_sk_b64 == NULL ||
        ed25519_pk_b64 == NULL || ed25519_sk_b64 == NULL) {
        fprintf(stderr, "Error: Failed to encode key material\n");
        free(mldsa_pk_b64); free(mldsa_sk_b64); free(ed25519_pk_b64); free(ed25519_sk_b64);
        free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
        sig_free_fn(sig);
        return PQBLOCKS_ERR_FILE_IO;
    }

    /* Build JSON content with envelope + key material */
    char *mldsa_pk_esc = json_escape(mldsa_pk_b64);
    char *mldsa_sk_esc = json_escape(mldsa_sk_b64);
    char *ed25519_pk_esc = json_escape(ed25519_pk_b64);
    char *ed25519_sk_esc = json_escape(ed25519_sk_b64);

    int json_len = 2048 + strlen(mldsa_pk_esc) + strlen(mldsa_sk_esc) +
                   strlen(ed25519_pk_esc) + strlen(ed25519_sk_esc);
    char *json_content = (char *)malloc(json_len);
    if (json_content == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        free(mldsa_pk_esc); free(mldsa_sk_esc); free(ed25519_pk_esc); free(ed25519_sk_esc);
        free(mldsa_pk_b64); free(mldsa_sk_b64); free(ed25519_pk_b64); free(ed25519_sk_b64);
        free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
        sig_free_fn(sig);
        return PQBLOCKS_ERR_FILE_IO;
    }

    sprintf(json_content,
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
        "\"ctx_label\":\"ML-DSA-65\","
        "\"mldsa_pk_b64\":\"%s\","
        "\"mldsa_sk_b64\":\"%s\","
        "\"ed25519_pk_b64\":\"%s\","
        "\"ed25519_sk_b64\":\"%s\"}\n",
        mldsa_pk_esc, mldsa_sk_esc, ed25519_pk_esc, ed25519_sk_esc);

    int io_ret = write_json_file(out_file, json_content);

    free(json_content);
    free(mldsa_pk_esc); free(mldsa_sk_esc); free(ed25519_pk_esc); free(ed25519_sk_esc);
    free(mldsa_pk_b64); free(mldsa_sk_b64); free(ed25519_pk_b64); free(ed25519_sk_b64);
    free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
    sig_free_fn(sig);

    return io_ret;
}

/* SIG sign command: read keys, sign message, write signature */
static int cmd_sig_sign(int argc, char **argv) {
    char *in_file = NULL;
    char *msg_file = NULL;
    char *out_file = NULL;

    if (parse_simple_arg(argc, argv, "--in", &in_file) != PQBLOCKS_SUCCESS ||
        parse_simple_arg(argc, argv, "--msg", &msg_file) != PQBLOCKS_SUCCESS ||
        parse_simple_arg(argc, argv, "--out", &out_file) != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Missing --in, --msg, or --out argument\n");
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    if (load_sig_library() != PQBLOCKS_SUCCESS)
        return PQBLOCKS_ERR_FILE_IO;

    /* Read the message: if msg_file is an existing regular file, read it; otherwise treat as literal message string */
    uint8_t *message = NULL;
    size_t msg_len = 0;
    int io_ret = PQBLOCKS_SUCCESS;
    struct stat st_msg;
    if (stat(msg_file, &st_msg) == 0 && S_ISREG(st_msg.st_mode)) {
        io_ret = read_binary_file(msg_file, &message, &msg_len);
        if (io_ret != PQBLOCKS_SUCCESS) {
            fprintf(stderr, "Error: Cannot read message file %s\n", msg_file);
            return io_ret;
        }
    } else {
        msg_len = strlen(msg_file);
        message = (uint8_t *)malloc(msg_len + 1);
        if (message == NULL)
            return PQBLOCKS_ERR_FILE_IO;
        memcpy(message, msg_file, msg_len);
        message[msg_len] = '\0';
    }

    /* Read the key file (JSON with key material) */
    char *json_content = NULL;
    io_ret = read_json_file(in_file, &json_content);
    if (io_ret != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Cannot read key file %s\n", in_file);
        free(message);
        return io_ret;
    }

    /* Extract key material */
    char *mldsa_pk_b64 = json_get_string(json_content, "mldsa_pk_b64");
    char *mldsa_sk_b64 = json_get_string(json_content, "mldsa_sk_b64");
    char *ed25519_pk_b64 = json_get_string(json_content, "ed25519_pk_b64");
    char *ed25519_sk_b64 = json_get_string(json_content, "ed25519_sk_b64");

    if (mldsa_pk_b64 == NULL || mldsa_sk_b64 == NULL ||
        ed25519_pk_b64 == NULL || ed25519_sk_b64 == NULL) {
        fprintf(stderr, "Error: Key material not found in %s\n", in_file);
        free(mldsa_pk_b64); free(mldsa_sk_b64); free(ed25519_pk_b64); free(ed25519_sk_b64);
        free(message);
        free(json_content);
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    /* Decode key material */
    size_t mldsa_pk_len, mldsa_sk_len, ed25519_pk_len, ed25519_sk_len;
    uint8_t *mldsa_pk = b64_decode(mldsa_pk_b64, &mldsa_pk_len);
    uint8_t *mldsa_sk = b64_decode(mldsa_sk_b64, &mldsa_sk_len);
    uint8_t *ed25519_pk = b64_decode(ed25519_pk_b64, &ed25519_pk_len);
    uint8_t *ed25519_sk = b64_decode(ed25519_sk_b64, &ed25519_sk_len);

    free(mldsa_pk_b64); free(mldsa_sk_b64); free(ed25519_pk_b64); free(ed25519_sk_b64);

    if (mldsa_pk == NULL || mldsa_sk == NULL || ed25519_pk == NULL || ed25519_sk == NULL) {
        fprintf(stderr, "Error: Failed to decode key material\n");
        free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
        free(message);
        free(json_content);
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    /* Create SIG object and import keys */
    void *sig = sig_new_fn();
    if (sig == NULL) {
        fprintf(stderr, "Error: Failed to create SIG object\n");
        free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
        free(message);
        free(json_content);
        return PQBLOCKS_ERR_NULL_POINTER;
    }

    if (sig_import_keys_fn != NULL) {
        int ret = sig_import_keys_fn(sig,
            mldsa_pk, mldsa_pk_len,
            mldsa_sk, mldsa_sk_len,
            ed25519_pk, ed25519_pk_len,
            ed25519_sk, ed25519_sk_len);
        if (ret != PQBLOCKS_SUCCESS) {
            fprintf(stderr, "Error: Failed to import SIG keys, code %d\n", ret);
            sig_free_fn(sig);
            free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
            free(message);
            free(json_content);
            return ret;
        }
    }

    /* Sign the message */
    size_t sig_len = 3373;
    uint8_t *signature = (uint8_t *)malloc(sig_len);
    char *envelope_json = NULL;

    int ret = sig_sign_fn(sig, message, msg_len, signature, &sig_len, &envelope_json);
    if (ret != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Sign failed with code %d\n", ret);
        free(signature);
        sig_free_fn(sig);
        free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
        free(message);
        free(json_content);
        return ret;
    }

    /* Write the signature to the output file */
    int io_ret2 = write_binary_file(out_file, signature, sig_len);

    free(signature);
    /* envelope_json leaked */
    sig_free_fn(sig);
    free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
    free(message);
    free(json_content);

    return io_ret2;
}

/* SIG verify command: read keys + signature, verify */
static int cmd_sig_verify(int argc, char **argv) {
    char *in_file = NULL;
    char *msg_file = NULL;
    char *sig_file = NULL;

    if (parse_simple_arg(argc, argv, "--in", &in_file) != PQBLOCKS_SUCCESS ||
        parse_simple_arg(argc, argv, "--msg", &msg_file) != PQBLOCKS_SUCCESS ||
        parse_simple_arg(argc, argv, "--sig", &sig_file) != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Missing --in, --msg, or --sig argument\n");
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    if (load_sig_library() != PQBLOCKS_SUCCESS)
        return PQBLOCKS_ERR_FILE_IO;

    /* Read the message: if msg_file is an existing regular file, read it; otherwise treat as literal message string */
    uint8_t *message = NULL;
    size_t msg_len = 0;
    int io_ret = PQBLOCKS_SUCCESS;
    struct stat st_msg;
    if (stat(msg_file, &st_msg) == 0 && S_ISREG(st_msg.st_mode)) {
        io_ret = read_binary_file(msg_file, &message, &msg_len);
        if (io_ret != PQBLOCKS_SUCCESS) {
            fprintf(stderr, "Error: Cannot read message file %s\n", msg_file);
            return io_ret;
        }
    } else {
        msg_len = strlen(msg_file);
        message = (uint8_t *)malloc(msg_len + 1);
        if (message == NULL)
            return PQBLOCKS_ERR_FILE_IO;
        memcpy(message, msg_file, msg_len);
        message[msg_len] = '\0';
    }

    uint8_t *signature = NULL;
    size_t sig_len = 0;
    io_ret = read_binary_file(sig_file, &signature, &sig_len);
    if (io_ret != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Cannot read signature file %s\n", sig_file);
        free(message);
        return io_ret;
    }

    /* Read the key file (JSON with key material) */
    char *json_content = NULL;
    io_ret = read_json_file(in_file, &json_content);
    if (io_ret != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Error: Cannot read key file %s\n", in_file);
        free(message);
        free(signature);
        return io_ret;
    }

    /* Extract key material */
    char *mldsa_pk_b64 = json_get_string(json_content, "mldsa_pk_b64");
    char *mldsa_sk_b64 = json_get_string(json_content, "mldsa_sk_b64");
    char *ed25519_pk_b64 = json_get_string(json_content, "ed25519_pk_b64");
    char *ed25519_sk_b64 = json_get_string(json_content, "ed25519_sk_b64");

    if (mldsa_pk_b64 == NULL || mldsa_sk_b64 == NULL ||
        ed25519_pk_b64 == NULL || ed25519_sk_b64 == NULL) {
        fprintf(stderr, "Error: Key material not found in %s\n", in_file);
        free(mldsa_pk_b64); free(mldsa_sk_b64); free(ed25519_pk_b64); free(ed25519_sk_b64);
        free(message);
        free(signature);
        free(json_content);
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    /* Decode key material */
    size_t mldsa_pk_len, mldsa_sk_len, ed25519_pk_len, ed25519_sk_len;
    uint8_t *mldsa_pk = b64_decode(mldsa_pk_b64, &mldsa_pk_len);
    uint8_t *mldsa_sk = b64_decode(mldsa_sk_b64, &mldsa_sk_len);
    uint8_t *ed25519_pk = b64_decode(ed25519_pk_b64, &ed25519_pk_len);
    uint8_t *ed25519_sk = b64_decode(ed25519_sk_b64, &ed25519_sk_len);

    free(mldsa_pk_b64); free(mldsa_sk_b64); free(ed25519_pk_b64); free(ed25519_sk_b64);

    if (mldsa_pk == NULL || mldsa_sk == NULL || ed25519_pk == NULL || ed25519_sk == NULL) {
        fprintf(stderr, "Error: Failed to decode key material\n");
        free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
        free(message);
        free(signature);
        free(json_content);
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    /* Create SIG object and import keys */
    void *sig = sig_new_fn();
    if (sig == NULL) {
        fprintf(stderr, "Error: Failed to create SIG object\n");
        free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
        free(message);
        free(signature);
        free(json_content);
        return PQBLOCKS_ERR_NULL_POINTER;
    }

    if (sig_import_keys_fn != NULL) {
        int ret = sig_import_keys_fn(sig,
            mldsa_pk, mldsa_pk_len,
            mldsa_sk, mldsa_sk_len,
            ed25519_pk, ed25519_pk_len,
            ed25519_sk, ed25519_sk_len);
        if (ret != PQBLOCKS_SUCCESS) {
            fprintf(stderr, "Error: Failed to import SIG keys, code %d\n", ret);
            sig_free_fn(sig);
            free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
            free(message);
            free(signature);
            free(json_content);
            return ret;
        }
    }

    /* Read the envelope from the key file */
    char *envelope_json = json_content; /* reuse the key file content as envelope */

    int ret = sig_verify_fn(sig, message, msg_len, signature, sig_len, envelope_json);
    free(message);
    free(signature);
    free(mldsa_pk); free(mldsa_sk); free(ed25519_pk); free(ed25519_sk);
    free(json_content);
    sig_free_fn(sig);

    if (ret != PQBLOCKS_SUCCESS) {
        fprintf(stderr, "Verification failed with code %d\n", ret);
        return ret;
    }

    printf("Signature verified successfully\n");
    return PQBLOCKS_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: pqblocks <kem|sig> <command> [options]\n");
        return PQBLOCKS_ERR_INVALID_ARGUMENT;
    }

    const char *category = argv[1];
    const char *command = (argc >= 3) ? argv[2] : NULL;
    int ret;

    if (strcmp(category, "kem") == 0) {
        if (command == NULL) {
            fprintf(stderr, "Error: Missing command\n");
            return PQBLOCKS_ERR_INVALID_ARGUMENT;
        }
        if (strcmp(command, "keygen") == 0) {
            ret = cmd_kem_keygen(argc - 2, &argv[2]);
        } else if (strcmp(command, "encaps") == 0) {
            ret = cmd_kem_encaps(argc - 2, &argv[2]);
        } else if (strcmp(command, "decaps") == 0) {
            ret = cmd_kem_decaps(argc - 2, &argv[2]);
        } else {
            fprintf(stderr, "Unknown KEM command: %s\n", command);
            ret = PQBLOCKS_ERR_UNKNOWN_COMMAND;
        }
    } else if (strcmp(category, "sig") == 0) {
        if (command == NULL) {
            fprintf(stderr, "Error: Missing command\n");
            return PQBLOCKS_ERR_INVALID_ARGUMENT;
        }
        if (strcmp(command, "keygen") == 0) {
            ret = cmd_sig_keygen(argc - 2, &argv[2]);
        } else if (strcmp(command, "sign") == 0) {
            ret = cmd_sig_sign(argc - 2, &argv[2]);
        } else if (strcmp(command, "verify") == 0) {
            ret = cmd_sig_verify(argc - 2, &argv[2]);
        } else {
            fprintf(stderr, "Unknown SIG command: %s\n", command);
            ret = PQBLOCKS_ERR_UNKNOWN_COMMAND;
        }
    } else {
        fprintf(stderr, "Unknown category: %s\n", category);
        ret = PQBLOCKS_ERR_UNKNOWN_COMMAND;
    }

    /* Cleanup */
    if (kem_lib_handle != NULL)
        dlclose(kem_lib_handle);
    if (sig_lib_handle != NULL)
        dlclose(sig_lib_handle);

    /* Return 0 for success, non-zero for error. */
    return (ret == PQBLOCKS_SUCCESS) ? 0 : 1;
}
