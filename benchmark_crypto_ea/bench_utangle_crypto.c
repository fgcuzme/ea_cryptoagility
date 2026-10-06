
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

/*
 * bench_utangle_crypto.c
 *
 * U-Tangle / EA-CryptoAgility operation-level microbenchmark.
 *
 * Target: Raspberry Pi 3 B+
 *
 * Measures:
 *   - Ed25519 key generation
 *   - Ed25519 sign / verify (32, 64, 128, 256 B messages)
 *   - X25519 key generation
 *   - X25519 shared-secret derivation
 *   - HKDF-SHA256 (IKM=32 B, salt=32 B, info=16 B, OKM=32 B)
 *   - Ascon-128 v1.2 AEAD encryption/decryption
 *       message sizes: 16, 32, 48, 64, 96, 128, 160, 192, 224, 256 B
 *       associated data: 0, 16, 32 B
 *
 * Ascon parameters match the Python U-Tangle base implementation:
 *   variant = "Ascon-128"
 *   key     = 16 B
 *   nonce   = 16 B
 *   tag     = 16 B
 *   rate    = 8 B
 *   a       = 12 rounds
 *   b       = 6 rounds
 *
 * Timing:
 *   CLOCK_MONOTONIC_RAW
 *
 * Outputs:
 *   utangle_crypto_samples.csv
 *   utangle_crypto_summary.csv
 *
 * Environment:
 *   UT_BENCH_SAMPLES=<int>       default 5000
 *   UT_BENCH_FAST_BATCH=<int>    default 100
 *   UT_BENCH_MEDIUM_BATCH=<int>  default 20
 *   UT_BENCH_SLOW_BATCH=<int>    default 5
 *   UT_P_PROC_W=<float>          default 0.10
 *   UT_WARMUP=<int>              default 1000
 *
 * Build:
 *   gcc -O3 -std=c11 -Wall -Wextra \
 *       -D_POSIX_C_SOURCE=200809L \
 *       bench_utangle_crypto.c -o bench_utangle_crypto \
 *       -lcrypto -lm
 *
 * IMPORTANT:
 *   This benchmark intentionally excludes RNG/nonce generation from the
 *   timed sign, derive, HKDF, and Ascon operations. Key generation includes
 *   the key-generation work itself.
 */

#define ASCON_KEYBYTES 16
#define ASCON_NONCEBYTES 16
#define ASCON_TAGBYTES 16
#define ASCON_RATE 8
#define ASCON_A_ROUNDS 12
#define ASCON_B_ROUNDS 6

#define MAX_MSG 256
#define MAX_AD 32
#define MAX_CT (MAX_MSG + ASCON_TAGBYTES)

#define DEFAULT_SAMPLES 5000
#define DEFAULT_FAST_BATCH 100
#define DEFAULT_MEDIUM_BATCH 20
#define DEFAULT_SLOW_BATCH 5
#define DEFAULT_WARMUP 1000
#define DEFAULT_P_PROC_W 0.10

static volatile uint64_t g_sink64 = 0;
static volatile unsigned char g_sink8 = 0;

/* -------------------------------------------------------------------------- */
/* Timing                                                                      */
/* -------------------------------------------------------------------------- */

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

/* -------------------------------------------------------------------------- */
/* Utilities                                                                   */
/* -------------------------------------------------------------------------- */

static uint64_t load64_be(const unsigned char *p) {
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] <<  8) |
           ((uint64_t)p[7]);
}

static void store64_be(unsigned char *p, uint64_t x) {
    p[0] = (unsigned char)(x >> 56);
    p[1] = (unsigned char)(x >> 48);
    p[2] = (unsigned char)(x >> 40);
    p[3] = (unsigned char)(x >> 32);
    p[4] = (unsigned char)(x >> 24);
    p[5] = (unsigned char)(x >> 16);
    p[6] = (unsigned char)(x >>  8);
    p[7] = (unsigned char)x;
}

static uint64_t rotr64(uint64_t x, unsigned n) {
    return (x >> n) | (x << (64U - n));
}

static void hexprint(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) printf("%02x", buf[i]);
}

/* -------------------------------------------------------------------------- */
/* Ascon-128 v1.2 — exact parameters used by the U-Tangle Python implementation*/
/* -------------------------------------------------------------------------- */

static void ascon_permutation(uint64_t s[5], int rounds) {
    for (int r = 12 - rounds; r < 12; ++r) {
        /* add round constant: identical to Python:
         * S[2] ^= (0xf0 - r*0x10 + r*0x1)
         */
        s[2] ^= (uint64_t)(0xF0 - r * 0x10 + r * 0x01);

        /* substitution layer */
        s[0] ^= s[4];
        s[4] ^= s[3];
        s[2] ^= s[1];

        uint64_t t0 = (~s[0]) & s[1];
        uint64_t t1 = (~s[1]) & s[2];
        uint64_t t2 = (~s[2]) & s[3];
        uint64_t t3 = (~s[3]) & s[4];
        uint64_t t4 = (~s[4]) & s[0];

        s[0] ^= t1;
        s[1] ^= t2;
        s[2] ^= t3;
        s[3] ^= t4;
        s[4] ^= t0;

        s[1] ^= s[0];
        s[0] ^= s[4];
        s[3] ^= s[2];
        s[2] = ~s[2];

        /* linear diffusion */
        s[0] ^= rotr64(s[0], 19) ^ rotr64(s[0], 28);
        s[1] ^= rotr64(s[1], 61) ^ rotr64(s[1], 39);
        s[2] ^= rotr64(s[2],  1) ^ rotr64(s[2],  6);
        s[3] ^= rotr64(s[3], 10) ^ rotr64(s[3], 17);
        s[4] ^= rotr64(s[4],  7) ^ rotr64(s[4], 41);
    }
}

static void ascon128_initialize(
    uint64_t s[5],
    const unsigned char key[ASCON_KEYBYTES],
    const unsigned char nonce[ASCON_NONCEBYTES]
) {
    const uint64_t k0 = load64_be(key);
    const uint64_t k1 = load64_be(key + 8);
    const uint64_t n0 = load64_be(nonce);
    const uint64_t n1 = load64_be(nonce + 8);

    /* Python iv_zero_key_nonce for Ascon-128:
     * [128, 64, 12, 6, 0,0,0,0] || key || nonce
     */
    s[0] = 0x80400c0600000000ULL;
    s[1] = k0;
    s[2] = k1;
    s[3] = n0;
    s[4] = n1;

    ascon_permutation(s, ASCON_A_ROUNDS);

    /* Python zero_key = bytes_to_state(zero_bytes(24) + key) */
    s[3] ^= k0;
    s[4] ^= k1;
}

static void ascon128_process_ad(
    uint64_t s[5],
    const unsigned char *ad,
    size_t adlen
) {
    if (adlen > 0) {
        size_t full = adlen / ASCON_RATE;
        size_t rem  = adlen % ASCON_RATE;

        /* If rem==0, Python still adds one full padding block. */
        for (size_t i = 0; i < full; ++i) {
            s[0] ^= load64_be(ad + i * ASCON_RATE);
            ascon_permutation(s, ASCON_B_ROUNDS);
        }

        unsigned char last[ASCON_RATE] = {0};
        if (rem > 0) memcpy(last, ad + full * ASCON_RATE, rem);
        last[rem] = 0x80;
        s[0] ^= load64_be(last);
        ascon_permutation(s, ASCON_B_ROUNDS);
    }

    s[4] ^= 1ULL;
}

static void ascon128_finalize(
    uint64_t s[5],
    const unsigned char key[ASCON_KEYBYTES],
    unsigned char tag[ASCON_TAGBYTES]
) {
    const uint64_t k0 = load64_be(key);
    const uint64_t k1 = load64_be(key + 8);

    /* Python ascon_finalize for rate=8:
     * S[1] ^= key[0:8]
     * S[2] ^= key[8:16]
     * S[3] ^= 0
     */
    s[1] ^= k0;
    s[2] ^= k1;

    ascon_permutation(s, ASCON_A_ROUNDS);

    s[3] ^= k0;
    s[4] ^= k1;

    store64_be(tag, s[3]);
    store64_be(tag + 8, s[4]);
}

static int ascon128_encrypt(
    unsigned char *out,
    size_t *outlen,
    const unsigned char *plaintext,
    size_t mlen,
    const unsigned char *ad,
    size_t adlen,
    const unsigned char key[ASCON_KEYBYTES],
    const unsigned char nonce[ASCON_NONCEBYTES]
) {
    uint64_t s[5];
    ascon128_initialize(s, key, nonce);
    ascon128_process_ad(s, ad, adlen);

    size_t full = mlen / ASCON_RATE;
    size_t rem  = mlen % ASCON_RATE;
    size_t off = 0;

    /* Python padding always creates a last padded block. If rem==0,
     * all full plaintext blocks are processed with p6, then an empty
     * 0x80 padding block is absorbed without output.
     */
    for (size_t i = 0; i < full; ++i) {
        s[0] ^= load64_be(plaintext + i * ASCON_RATE);
        store64_be(out + off, s[0]);
        off += ASCON_RATE;
        ascon_permutation(s, ASCON_B_ROUNDS);
    }

    unsigned char last[ASCON_RATE] = {0};
    if (rem > 0) memcpy(last, plaintext + full * ASCON_RATE, rem);
    last[rem] = 0x80;
    s[0] ^= load64_be(last);

    if (rem > 0) {
        unsigned char word[ASCON_RATE];
        store64_be(word, s[0]);
        memcpy(out + off, word, rem);
        off += rem;
    }

    unsigned char tag[ASCON_TAGBYTES];
    ascon128_finalize(s, key, tag);
    memcpy(out + off, tag, ASCON_TAGBYTES);
    off += ASCON_TAGBYTES;

    *outlen = off;
    return 1;
}

static int ascon128_decrypt(
    unsigned char *out,
    size_t *outlen,
    const unsigned char *ciphertext,
    size_t clen_with_tag,
    const unsigned char *ad,
    size_t adlen,
    const unsigned char key[ASCON_KEYBYTES],
    const unsigned char nonce[ASCON_NONCEBYTES]
) {
    if (clen_with_tag < ASCON_TAGBYTES) return 0;

    const size_t clen = clen_with_tag - ASCON_TAGBYTES;
    const unsigned char *tag_in = ciphertext + clen;

    uint64_t s[5];
    ascon128_initialize(s, key, nonce);
    ascon128_process_ad(s, ad, adlen);

    size_t full = clen / ASCON_RATE;
    size_t rem  = clen % ASCON_RATE;
    size_t off = 0;

    for (size_t i = 0; i < full; ++i) {
        uint64_t ci = load64_be(ciphertext + i * ASCON_RATE);
        uint64_t pi = s[0] ^ ci;
        store64_be(out + off, pi);
        off += ASCON_RATE;
        s[0] = ci;
        ascon_permutation(s, ASCON_B_ROUNDS);
    }

    /* Last (possibly empty) partial block: mirrors Python code. */
    unsigned char cpad[ASCON_RATE] = {0};
    if (rem > 0) memcpy(cpad, ciphertext + full * ASCON_RATE, rem);
    uint64_t ci = load64_be(cpad);

    unsigned char state_word[ASCON_RATE];
    unsigned char ci_word[ASCON_RATE];
    store64_be(state_word, s[0]);
    store64_be(ci_word, ci);

    for (size_t i = 0; i < rem; ++i) {
        out[off + i] = (unsigned char)(state_word[i] ^ ci_word[i]);
    }
    off += rem;

    /* Python:
     * c_padding1 = 0x80 << ((8-rem-1)*8)
     * c_mask     = 0xffff... >> (rem*8)
     * S[0] = Ci ^ (S[0] & c_mask) ^ c_padding1
     */
    uint64_t padding = 0x80ULL << ((ASCON_RATE - rem - 1) * 8);
    uint64_t mask = UINT64_MAX >> (rem * 8);
    s[0] = ci ^ (s[0] & mask) ^ padding;

    unsigned char tag_calc[ASCON_TAGBYTES];
    ascon128_finalize(s, key, tag_calc);

    if (CRYPTO_memcmp(tag_calc, tag_in, ASCON_TAGBYTES) != 0) {
        memset(out, 0, clen);
        *outlen = 0;
        return 0;
    }

    *outlen = off;
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Benchmark statistics                                                        */
/* -------------------------------------------------------------------------- */

typedef struct {
    double mean_us;
    double median_us;
    double p95_us;
    double stddev_us;
} stats_t;

static int cmp_double(const void *a, const void *b) {
    const double da = *(const double *)a;
    const double db = *(const double *)b;
    return (da > db) - (da < db);
}

static stats_t calc_stats(double *samples, size_t n) {
    stats_t s = {0};
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) sum += samples[i];
    s.mean_us = sum / (double)n;

    qsort(samples, n, sizeof(double), cmp_double);
    if ((n & 1U) == 0)
        s.median_us = (samples[n/2 - 1] + samples[n/2]) / 2.0;
    else
        s.median_us = samples[n/2];

    size_t p95i = (size_t)ceil(0.95 * (double)n) - 1;
    if (p95i >= n) p95i = n - 1;
    s.p95_us = samples[p95i];

    double var = 0.0;
    for (size_t i = 0; i < n; ++i) {
        double d = samples[i] - s.mean_us;
        var += d * d;
    }
    s.stddev_us = sqrt(var / (double)n);
    return s;
}

typedef int (*bench_fn)(void *);

static void run_benchmark(
    const char *name,
    bench_fn fn,
    void *ctx,
    int samples_n,
    int batch,
    int warmup,
    double p_proc_w,
    FILE *raw,
    FILE *summary
) {
    if (samples_n <= 0 || batch <= 0) {
        fprintf(stderr, "Invalid benchmark parameters for %s\n", name);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < warmup; ++i) {
        if (!fn(ctx)) {
            fprintf(stderr, "Warmup failed for %s\n", name);
            exit(EXIT_FAILURE);
        }
    }

    double *samples = (double *)malloc(sizeof(double) * (size_t)samples_n);
    if (!samples) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    for (int s = 0; s < samples_n; ++s) {
        uint64_t t0 = now_ns();
        for (int j = 0; j < batch; ++j) {
            if (!fn(ctx)) {
                fprintf(stderr, "Operation failed: %s\n", name);
                free(samples);
                exit(EXIT_FAILURE);
            }
        }
        uint64_t t1 = now_ns();

        double us_per_op = ((double)(t1 - t0) / (double)batch) / 1000.0;
        samples[s] = us_per_op;
        fprintf(raw, "%s,%d,%d,%.9f\n", name, s, batch, us_per_op);
    }

    stats_t st = calc_stats(samples, (size_t)samples_n);
    double median_energy_mj = p_proc_w * st.median_us / 1000.0;

    printf("%-32s median=%10.6f us  mean=%10.6f us  p95=%10.6f us  Emed=%0.9f mJ\n",
           name, st.median_us, st.mean_us, st.p95_us, median_energy_mj);

    fprintf(summary,
            "%s,%d,%d,%.9f,%.9f,%.9f,%.9f,%.6f,%.12f\n",
            name, samples_n, batch,
            st.mean_us, st.median_us, st.p95_us, st.stddev_us,
            p_proc_w, median_energy_mj);

    free(samples);
}

/* -------------------------------------------------------------------------- */
/* OpenSSL operation contexts                                                  */
/* -------------------------------------------------------------------------- */

typedef struct {
    unsigned char msg[256];
    size_t msg_len;
    EVP_PKEY *ed_key;
    unsigned char sig[128];
    size_t sig_len;
} ed_ctx_t;

static EVP_PKEY *gen_key(int type) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(type, NULL);
    if (!ctx) return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) pkey = NULL;
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int op_ed25519_keygen(void *arg) {
    (void)arg;
    EVP_PKEY *k = gen_key(EVP_PKEY_ED25519);
    if (!k) return 0;
    g_sink64 ^= (uint64_t)EVP_PKEY_id(k);
    EVP_PKEY_free(k);
    return 1;
}

static int op_ed25519_sign(void *arg) {
    ed_ctx_t *c = (ed_ctx_t *)arg;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return 0;

    size_t slen = sizeof(c->sig);
    int ok = EVP_DigestSignInit(mctx, NULL, NULL, NULL, c->ed_key) > 0 &&
             EVP_DigestSign(mctx, c->sig, &slen, c->msg, c->msg_len) > 0;
    EVP_MD_CTX_free(mctx);
    if (!ok) return 0;
    c->sig_len = slen;
    g_sink8 ^= c->sig[0];
    return 1;
}

static int op_ed25519_verify(void *arg) {
    ed_ctx_t *c = (ed_ctx_t *)arg;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return 0;

    int ok = EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, c->ed_key) > 0 &&
             EVP_DigestVerify(mctx, c->sig, c->sig_len, c->msg, c->msg_len) == 1;
    EVP_MD_CTX_free(mctx);
    g_sink8 ^= (unsigned char)(ok ? 0x5a : 0xa5);
    return ok;
}

typedef struct {
    EVP_PKEY *x_priv;
    EVP_PKEY *x_peer;
    unsigned char secret[64];
    size_t secret_len;
} x_ctx_t;

static int op_x25519_keygen(void *arg) {
    (void)arg;
    EVP_PKEY *k = gen_key(EVP_PKEY_X25519);
    if (!k) return 0;
    g_sink64 ^= (uint64_t)EVP_PKEY_id(k);
    EVP_PKEY_free(k);
    return 1;
}

static int op_x25519_derive(void *arg) {
    x_ctx_t *c = (x_ctx_t *)arg;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(c->x_priv, NULL);
    if (!ctx) return 0;

    size_t outlen = sizeof(c->secret);
    int ok = EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_derive_set_peer(ctx, c->x_peer) > 0 &&
             EVP_PKEY_derive(ctx, c->secret, &outlen) > 0;

    EVP_PKEY_CTX_free(ctx);
    if (!ok) return 0;
    c->secret_len = outlen;
    g_sink8 ^= c->secret[0];
    return 1;
}

typedef struct {
    unsigned char ikm[32];
    unsigned char salt[32];
    unsigned char info[16];
    unsigned char out[32];
} hkdf_ctx_t;

static int op_hkdf_sha256(void *arg) {
    hkdf_ctx_t *c = (hkdf_ctx_t *)arg;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return 0;

    size_t outlen = sizeof(c->out);
    int ok = EVP_PKEY_derive_init(pctx) > 0 &&
             EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
             EVP_PKEY_CTX_set1_hkdf_salt(pctx, c->salt, sizeof(c->salt)) > 0 &&
             EVP_PKEY_CTX_set1_hkdf_key(pctx, c->ikm, sizeof(c->ikm)) > 0 &&
             EVP_PKEY_CTX_add1_hkdf_info(pctx, c->info, sizeof(c->info)) > 0 &&
             EVP_PKEY_derive(pctx, c->out, &outlen) > 0;

    EVP_PKEY_CTX_free(pctx);
    if (!ok) return 0;
    g_sink8 ^= c->out[0];
    return 1;
}

typedef struct {
    unsigned char key[ASCON_KEYBYTES];
    unsigned char nonce[ASCON_NONCEBYTES];
    unsigned char msg[MAX_MSG];
    unsigned char ad[MAX_AD];
    size_t msg_len;
    size_t ad_len;
    unsigned char ct[MAX_CT];
    size_t ct_len;
    unsigned char pt[MAX_MSG];
    size_t pt_len;
} ascon_ctx_t;

static int op_ascon_enc(void *arg) {
    ascon_ctx_t *c = (ascon_ctx_t *)arg;
    int ok = ascon128_encrypt(
        c->ct, &c->ct_len,
        c->msg, c->msg_len,
        c->ad, c->ad_len,
        c->key, c->nonce
    );
    if (ok) g_sink8 ^= c->ct[0];
    return ok;
}

static int op_ascon_dec(void *arg) {
    ascon_ctx_t *c = (ascon_ctx_t *)arg;
    int ok = ascon128_decrypt(
        c->pt, &c->pt_len,
        c->ct, c->ct_len,
        c->ad, c->ad_len,
        c->key, c->nonce
    );
    if (!ok) return 0;
    if (c->pt_len != c->msg_len || CRYPTO_memcmp(c->pt, c->msg, c->msg_len) != 0)
        return 0;
    g_sink8 ^= c->pt[0];
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Ascon vector output for cross-checking against the Python U-Tangle code     */
/* -------------------------------------------------------------------------- */

static void print_ascon_vector(void) {
    unsigned char key[16], nonce[16], ad[16], msg[32], ct[48], pt[32];
    for (int i = 0; i < 16; ++i) {
        key[i] = (unsigned char)i;
        nonce[i] = (unsigned char)(0x10 + i);
        ad[i] = (unsigned char)(0x20 + i);
    }
    for (int i = 0; i < 32; ++i) msg[i] = (unsigned char)(0x40 + i);

    size_t ctlen = 0, ptlen = 0;
    if (!ascon128_encrypt(ct, &ctlen, msg, sizeof(msg), ad, sizeof(ad), key, nonce)) {
        fprintf(stderr, "Ascon vector encryption failed\n");
        exit(EXIT_FAILURE);
    }
    if (!ascon128_decrypt(pt, &ptlen, ct, ctlen, ad, sizeof(ad), key, nonce) ||
        ptlen != sizeof(msg) || CRYPTO_memcmp(pt, msg, sizeof(msg)) != 0) {
        fprintf(stderr, "Ascon vector round-trip failed\n");
        exit(EXIT_FAILURE);
    }

    printf("\nASCON-128 v1.2 cross-check vector (compare with Python U-Tangle):\n");
    printf("key   = "); hexprint(key, sizeof(key)); printf("\n");
    printf("nonce = "); hexprint(nonce, sizeof(nonce)); printf("\n");
    printf("ad    = "); hexprint(ad, sizeof(ad)); printf("\n");
    printf("msg   = "); hexprint(msg, sizeof(msg)); printf("\n");
    printf("cttag = "); hexprint(ct, ctlen); printf("\n\n");
}

/* -------------------------------------------------------------------------- */
/* Main                                                                        */
/* -------------------------------------------------------------------------- */

static int env_int(const char *name, int defv) {
    const char *s = getenv(name);
    if (!s || !*s) return defv;
    int v = atoi(s);
    return v > 0 ? v : defv;
}

static double env_double(const char *name, double defv) {
    const char *s = getenv(name);
    if (!s || !*s) return defv;
    char *end = NULL;
    double v = strtod(s, &end);
    return (end && *end == '\0' && v > 0.0) ? v : defv;
}

int main(void) {
    const int samples = env_int("UT_BENCH_SAMPLES", DEFAULT_SAMPLES);
    const int fast_batch = env_int("UT_BENCH_FAST_BATCH", DEFAULT_FAST_BATCH);
    const int medium_batch = env_int("UT_BENCH_MEDIUM_BATCH", DEFAULT_MEDIUM_BATCH);
    const int slow_batch = env_int("UT_BENCH_SLOW_BATCH", DEFAULT_SLOW_BATCH);
    const int warmup = env_int("UT_WARMUP", DEFAULT_WARMUP);
    const double p_proc_w = env_double("UT_P_PROC_W", DEFAULT_P_PROC_W);

    printf("U-Tangle cryptographic microbenchmark\n");
    printf("OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("samples=%d fast_batch=%d medium_batch=%d slow_batch=%d warmup=%d P_PROC=%.6f W\n",
           samples, fast_batch, medium_batch, slow_batch, warmup, p_proc_w);

    print_ascon_vector();

    FILE *raw = fopen("utangle_crypto_samples.csv", "w");
    FILE *summary = fopen("utangle_crypto_summary.csv", "w");
    if (!raw || !summary) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    fprintf(raw, "operation,sample,batch,time_us\n");
    fprintf(summary,
            "operation,n_samples,batch,mean_us,median_us,p95_us,stddev_us,p_proc_w,median_energy_mj\n");

    /* deterministic message material */
    unsigned char base_msg[256];
    for (size_t i = 0; i < sizeof(base_msg); ++i)
        base_msg[i] = (unsigned char)(i ^ 0xA5);

    /* Ed25519 setup */
    ed_ctx_t ed = {0};
    ed.ed_key = gen_key(EVP_PKEY_ED25519);
    if (!ed.ed_key) {
        fprintf(stderr, "Ed25519 setup failed\n");
        return EXIT_FAILURE;
    }
    memcpy(ed.msg, base_msg, sizeof(ed.msg));

    const size_t ed_sizes[] = {32, 64, 128, 256};

    run_benchmark("ED25519_KEYGEN", op_ed25519_keygen, NULL,
                  samples, slow_batch, warmup, p_proc_w, raw, summary);

    for (size_t i = 0; i < sizeof(ed_sizes)/sizeof(ed_sizes[0]); ++i) {
        char name[64];
        ed.msg_len = ed_sizes[i];

        /* Ensure a valid signature exists before verification benchmark. */
        if (!op_ed25519_sign(&ed)) {
            fprintf(stderr, "Ed25519 pre-sign failed\n");
            return EXIT_FAILURE;
        }

        snprintf(name, sizeof(name), "ED25519_SIGN_%zu", ed.msg_len);
        run_benchmark(name, op_ed25519_sign, &ed,
                      samples, medium_batch, warmup, p_proc_w, raw, summary);

        /* Refresh valid signature once after sign benchmark. */
        if (!op_ed25519_sign(&ed)) {
            fprintf(stderr, "Ed25519 pre-verify sign failed\n");
            return EXIT_FAILURE;
        }

        snprintf(name, sizeof(name), "ED25519_VERIFY_%zu", ed.msg_len);
        run_benchmark(name, op_ed25519_verify, &ed,
                      samples, medium_batch, warmup, p_proc_w, raw, summary);
    }

    /* X25519 setup */
    x_ctx_t xc = {0};
    xc.x_priv = gen_key(EVP_PKEY_X25519);
    xc.x_peer = gen_key(EVP_PKEY_X25519);
    if (!xc.x_priv || !xc.x_peer) {
        fprintf(stderr, "X25519 setup failed\n");
        return EXIT_FAILURE;
    }

    run_benchmark("X25519_KEYGEN", op_x25519_keygen, NULL,
                  samples, slow_batch, warmup, p_proc_w, raw, summary);

    run_benchmark("X25519_DERIVE", op_x25519_derive, &xc,
                  samples, medium_batch, warmup, p_proc_w, raw, summary);

    /* HKDF setup */
    hkdf_ctx_t hk = {0};
    for (size_t i = 0; i < sizeof(hk.ikm); ++i) hk.ikm[i] = (unsigned char)(0x11 + i);
    for (size_t i = 0; i < sizeof(hk.salt); ++i) hk.salt[i] = (unsigned char)(0x22 + i);
    for (size_t i = 0; i < sizeof(hk.info); ++i) hk.info[i] = (unsigned char)(0x33 + i);

    run_benchmark("HKDF_SHA256_IKM32_OKM32", op_hkdf_sha256, &hk,
                  samples, fast_batch, warmup, p_proc_w, raw, summary);

    /* Ascon setup and matrix */
    ascon_ctx_t ac = {0};
    for (size_t i = 0; i < ASCON_KEYBYTES; ++i) ac.key[i] = (unsigned char)(0x01 + i);
    for (size_t i = 0; i < ASCON_NONCEBYTES; ++i) ac.nonce[i] = (unsigned char)(0x21 + i);
    for (size_t i = 0; i < MAX_MSG; ++i) ac.msg[i] = (unsigned char)(0x41 + (i & 0x3f));
    for (size_t i = 0; i < MAX_AD; ++i) ac.ad[i] = (unsigned char)(0x81 + i);

    const size_t msg_sizes[] = {16, 32, 48, 64, 96, 128, 160, 192, 224, 256};
    const size_t ad_sizes[]  = {0, 16, 32};

    for (size_t ai = 0; ai < sizeof(ad_sizes)/sizeof(ad_sizes[0]); ++ai) {
        for (size_t mi = 0; mi < sizeof(msg_sizes)/sizeof(msg_sizes[0]); ++mi) {
            char name[96];
            ac.ad_len = ad_sizes[ai];
            ac.msg_len = msg_sizes[mi];

            if (!op_ascon_enc(&ac)) {
                fprintf(stderr, "Ascon pre-encryption failed\n");
                return EXIT_FAILURE;
            }
            if (!op_ascon_dec(&ac)) {
                fprintf(stderr, "Ascon pre-decryption self-test failed for M=%zu AD=%zu\n",
                        ac.msg_len, ac.ad_len);
                return EXIT_FAILURE;
            }

            snprintf(name, sizeof(name), "ASCON128_ENC_M%zu_AD%zu", ac.msg_len, ac.ad_len);
            run_benchmark(name, op_ascon_enc, &ac,
                          samples, fast_batch, warmup, p_proc_w, raw, summary);

            /* ensure ct corresponds to current fixed input before DEC timing */
            if (!op_ascon_enc(&ac)) {
                fprintf(stderr, "Ascon ciphertext preparation failed\n");
                return EXIT_FAILURE;
            }

            snprintf(name, sizeof(name), "ASCON128_DEC_M%zu_AD%zu", ac.msg_len, ac.ad_len);
            run_benchmark(name, op_ascon_dec, &ac,
                          samples, fast_batch, warmup, p_proc_w, raw, summary);
        }
    }

    fclose(raw);
    fclose(summary);

    EVP_PKEY_free(ed.ed_key);
    EVP_PKEY_free(xc.x_priv);
    EVP_PKEY_free(xc.x_peer);

    printf("\nResults written to:\n");
    printf("  utangle_crypto_samples.csv\n");
    printf("  utangle_crypto_summary.csv\n");
    printf("sink=%llu/%u\n",
           (unsigned long long)g_sink64, (unsigned)g_sink8);

    return EXIT_SUCCESS;
}
