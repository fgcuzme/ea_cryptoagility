/*
 * bench_ea_extra_ops.c
 *
 * EA-CryptoAgility additional-operation benchmark
 *
 * Measures:
 *   1. POLICY_MAC_CRYPTO
 *      HMAC-SHA256 over pre-serialized policy context, truncated to 16 B.
 *
 *   2. POLICY_MAC_FULL
 *      Canonical policy serialization + HMAC-SHA256.
 *
 *   3. POLICY_MAC_VERIFY
 *      Canonical serialization + HMAC-SHA256 + constant-time comparison.
 *
 *   4. CHECKPOINT_HASH_128
 *   5. CHECKPOINT_HASH_256
 *   6. CHECKPOINT_HASH_512
 *
 * Outputs:
 *   ea_bench_samples.csv
 *   ea_bench_summary.csv
 *
 * Energy is derived using the same processing-power model as U-Tangle:
 *
 *      E = P_PROC * t
 *
 * Default:
 *      P_PROC = 0.10 W
 *
 * Compile:
 * gcc -O3 -std=c11 -Wall -Wextra \
 *     -D_POSIX_C_SOURCE=200809L \
 *     bench_ea_extra_ops.c \
 *     -o bench_ea_extra_ops \
 *     -lcrypto -lm
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#define DEFAULT_SAMPLES 5000
#define DEFAULT_BATCH   100
#define WARMUP_OPS      2000

#define POLICY_TAG_LEN  16
#define HMAC_KEY_LEN    32

#define POLICY_BUFFER_LEN 512

/* Same processing-power assumption used by the U-Tangle energy model */
#define DEFAULT_P_PROC_W 0.10


static volatile unsigned char g_sink = 0;


/* --------------------------------------------------------- */
/* Timing                                                    */
/* --------------------------------------------------------- */

static uint64_t now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }

    return ((uint64_t) ts.tv_sec * 1000000000ULL)
           + (uint64_t) ts.tv_nsec;
}


/* --------------------------------------------------------- */
/* Benchmark context                                         */
/* --------------------------------------------------------- */

typedef struct {

    unsigned char key[HMAC_KEY_LEN];

    char policy_json[POLICY_BUFFER_LEN];

    unsigned char expected_tag[POLICY_TAG_LEN];

    unsigned char checkpoint_128[128];
    unsigned char checkpoint_256[256];
    unsigned char checkpoint_512[512];

    int epoch;
    int node_id;

} bench_ctx_t;


/* --------------------------------------------------------- */
/* Canonical policy serialization                            */
/* --------------------------------------------------------- */

/*
 * Field order follows Python json.dumps(..., sort_keys=True,
 * separators=(",", ":")) used in ea_policy_metadata.py.
 *
 * Representative S3 policy context.
 */

static size_t build_policy_json(
    bench_ctx_t *ctx,
    char *buffer,
    size_t buffer_size)
{
    int n = snprintf(
        buffer,
        buffer_size,

        "{"
        "\"checkpoint_rule\":\"STRICT\","
        "\"energy_bucket\":\"E_50_75\","
        "\"epoch\":%d,"
        "\"message_type\":\"TELEMETRY\","
        "\"node_id\":%d,"
        "\"payload_mode\":\"FULL_AUTHENTICATED\","
        "\"policy_id\":\"EA_POLICY_V1\","
        "\"profile_id\":\"S3\","
        "\"rekey_rule\":\"ADAPTIVE_REKEY\","
        "\"risk_level\":\"R_HIGH\","
        "\"suite_id\":\"ASCON_ED25519_X25519\""
        "}",

        ctx->epoch,
        ctx->node_id
    );

    if (n < 0 || (size_t)n >= buffer_size) {
        fprintf(stderr, "Policy buffer too small\n");
        exit(EXIT_FAILURE);
    }

    return (size_t)n;
}


/* --------------------------------------------------------- */
/* HMAC-SHA256                                               */
/* --------------------------------------------------------- */

static void compute_hmac16(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *data,
    size_t data_len,
    unsigned char tag[POLICY_TAG_LEN])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (HMAC(
            EVP_sha256(),
            key,
            (int)key_len,
            data,
            data_len,
            digest,
            &digest_len) == NULL)
    {
        fprintf(stderr, "HMAC failed\n");
        exit(EXIT_FAILURE);
    }

    if (digest_len < POLICY_TAG_LEN) {
        fprintf(stderr, "Unexpected HMAC length\n");
        exit(EXIT_FAILURE);
    }

    memcpy(tag, digest, POLICY_TAG_LEN);

    /* prevent optimization */
    g_sink ^= tag[0];
}


/* --------------------------------------------------------- */
/* Operations under test                                     */
/* --------------------------------------------------------- */

/*
 * HMAC only.
 * The policy payload is already serialized.
 */
static void op_policy_mac_crypto(void *arg)
{
    bench_ctx_t *ctx = (bench_ctx_t *)arg;

    unsigned char tag[POLICY_TAG_LEN];

    size_t len = strlen(ctx->policy_json);

    compute_hmac16(
        ctx->key,
        HMAC_KEY_LEN,
        (unsigned char *)ctx->policy_json,
        len,
        tag
    );
}


/*
 * Serialization + HMAC.
 *
 * This is the preferred value for EA POLICY_MAC cost because
 * it represents the complete operation performed by a node.
 */
static void op_policy_mac_full(void *arg)
{
    bench_ctx_t *ctx = (bench_ctx_t *)arg;

    char buffer[POLICY_BUFFER_LEN];
    unsigned char tag[POLICY_TAG_LEN];

    size_t len = build_policy_json(
        ctx,
        buffer,
        sizeof(buffer)
    );

    compute_hmac16(
        ctx->key,
        HMAC_KEY_LEN,
        (unsigned char *)buffer,
        len,
        tag
    );
}


/*
 * Serialization + HMAC + constant-time verification.
 */
static void op_policy_mac_verify(void *arg)
{
    bench_ctx_t *ctx = (bench_ctx_t *)arg;

    char buffer[POLICY_BUFFER_LEN];
    unsigned char tag[POLICY_TAG_LEN];

    size_t len = build_policy_json(
        ctx,
        buffer,
        sizeof(buffer)
    );

    compute_hmac16(
        ctx->key,
        HMAC_KEY_LEN,
        (unsigned char *)buffer,
        len,
        tag
    );

    int result = CRYPTO_memcmp(
        tag,
        ctx->expected_tag,
        POLICY_TAG_LEN
    );

    g_sink ^= (unsigned char)result;
}


/* --------------------------------------------------------- */
/* Checkpoint SHA-256                                        */
/* --------------------------------------------------------- */

static void op_checkpoint_hash_128(void *arg)
{
    bench_ctx_t *ctx = (bench_ctx_t *)arg;

    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256(
        ctx->checkpoint_128,
        sizeof(ctx->checkpoint_128),
        digest
    );

    g_sink ^= digest[0];
}


static void op_checkpoint_hash_256(void *arg)
{
    bench_ctx_t *ctx = (bench_ctx_t *)arg;

    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256(
        ctx->checkpoint_256,
        sizeof(ctx->checkpoint_256),
        digest
    );

    g_sink ^= digest[0];
}


static void op_checkpoint_hash_512(void *arg)
{
    bench_ctx_t *ctx = (bench_ctx_t *)arg;

    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256(
        ctx->checkpoint_512,
        sizeof(ctx->checkpoint_512),
        digest
    );

    g_sink ^= digest[0];
}


/* --------------------------------------------------------- */
/* Statistics                                                */
/* --------------------------------------------------------- */

static int compare_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;

    if (da < db) return -1;
    if (da > db) return 1;

    return 0;
}


typedef struct {

    double mean_us;
    double median_us;
    double p95_us;
    double stddev_us;

} stats_t;


static stats_t calculate_stats(
    double *samples,
    size_t n)
{
    stats_t s = {0};

    double sum = 0.0;

    for (size_t i = 0; i < n; i++)
        sum += samples[i];

    s.mean_us = sum / (double)n;

    qsort(
        samples,
        n,
        sizeof(double),
        compare_double
    );

    if ((n % 2) == 0) {
        s.median_us =
            (samples[n / 2 - 1] +
             samples[n / 2]) / 2.0;
    }
    else {
        s.median_us = samples[n / 2];
    }

    size_t p95_index =
        (size_t)ceil(0.95 * (double)n) - 1;

    if (p95_index >= n)
        p95_index = n - 1;

    s.p95_us = samples[p95_index];

    double variance = 0.0;

    for (size_t i = 0; i < n; i++) {

        double d =
            samples[i] - s.mean_us;

        variance += d * d;
    }

    variance /= (double)n;

    s.stddev_us = sqrt(variance);

    return s;
}


/* --------------------------------------------------------- */
/* Generic benchmark                                         */
/* --------------------------------------------------------- */

typedef void (*operation_fn)(void *);


static void benchmark_operation(
    const char *name,
    operation_fn operation,
    void *ctx,
    int n_samples,
    int batch,
    double p_proc_w,
    FILE *raw_file,
    FILE *summary_file)
{
    double *samples =
        malloc(sizeof(double) * n_samples);

    if (!samples) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }


    /* Warm-up */
    for (int i = 0; i < WARMUP_OPS; i++)
        operation(ctx);


    for (int s = 0; s < n_samples; s++) {

        uint64_t start = now_ns();

        for (int j = 0; j < batch; j++)
            operation(ctx);

        uint64_t end = now_ns();


        double elapsed_ns =
            (double)(end - start);

        /*
         * Convert batch measurement into
         * average microseconds per operation.
         */
        double us_per_operation =
            elapsed_ns /
            (double)batch /
            1000.0;

        samples[s] = us_per_operation;

        fprintf(
            raw_file,
            "%s,%d,%.9f\n",
            name,
            s,
            us_per_operation
        );
    }


    stats_t stats =
        calculate_stats(samples, n_samples);


    /*
     * 1 W * 1 us = 1 uJ
     *
     * E_uJ = P_W * time_us
     *
     * E_mJ = P_W * time_us / 1000
     */

    double median_energy_uj =
        p_proc_w * stats.median_us;

    double median_energy_mj =
        median_energy_uj / 1000.0;


    printf("\n%-28s\n", name);

    printf(
        "  mean       : %.6f us\n",
        stats.mean_us
    );

    printf(
        "  median     : %.6f us\n",
        stats.median_us
    );

    printf(
        "  p95        : %.6f us\n",
        stats.p95_us
    );

    printf(
        "  stddev     : %.6f us\n",
        stats.stddev_us
    );

    printf(
        "  energy med.: %.9f mJ\n",
        median_energy_mj
    );


    fprintf(
        summary_file,

        "%s,%d,%d,"
        "%.9f,%.9f,%.9f,%.9f,"
        "%.6f,%.12f\n",

        name,
        n_samples,
        batch,

        stats.mean_us,
        stats.median_us,
        stats.p95_us,
        stats.stddev_us,

        p_proc_w,
        median_energy_mj
    );


    free(samples);
}


/* --------------------------------------------------------- */
/* Main                                                      */
/* --------------------------------------------------------- */

int main(void)
{
    int n_samples = DEFAULT_SAMPLES;
    int batch = DEFAULT_BATCH;
    double p_proc_w = DEFAULT_P_PROC_W;


    char *env_samples =
        getenv("EA_BENCH_SAMPLES");

    char *env_batch =
        getenv("EA_BENCH_BATCH");

    char *env_power =
        getenv("EA_P_PROC_W");


    if (env_samples)
        n_samples = atoi(env_samples);

    if (env_batch)
        batch = atoi(env_batch);

    if (env_power)
        p_proc_w = atof(env_power);


    if (n_samples <= 0 || batch <= 0) {
        fprintf(stderr, "Invalid benchmark parameters\n");
        return EXIT_FAILURE;
    }


    bench_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));


    /*
     * Deterministic benchmark key.
     *
     * This is NOT a real session key.
     * Key contents do not affect HMAC timing.
     */
    for (int i = 0; i < HMAC_KEY_LEN; i++)
        ctx.key[i] =
            (unsigned char)(0x20 + i);


    ctx.epoch = 100;
    ctx.node_id = 10;


    /* Representative checkpoint data */

    for (size_t i = 0;
         i < sizeof(ctx.checkpoint_128);
         i++)
    {
        ctx.checkpoint_128[i] =
            (unsigned char)(i & 0xff);
    }

    for (size_t i = 0;
         i < sizeof(ctx.checkpoint_256);
         i++)
    {
        ctx.checkpoint_256[i] =
            (unsigned char)(i & 0xff);
    }

    for (size_t i = 0;
         i < sizeof(ctx.checkpoint_512);
         i++)
    {
        ctx.checkpoint_512[i] =
            (unsigned char)(i & 0xff);
    }


    /* Build canonical policy payload */

    build_policy_json(
        &ctx,
        ctx.policy_json,
        sizeof(ctx.policy_json)
    );


    /* Expected MAC used by verification benchmark */

    compute_hmac16(
        ctx.key,
        HMAC_KEY_LEN,

        (unsigned char *)ctx.policy_json,
        strlen(ctx.policy_json),

        ctx.expected_tag
    );


    FILE *raw =
        fopen(
            "ea_bench_samples.csv",
            "w"
        );

    FILE *summary =
        fopen(
            "ea_bench_summary.csv",
            "w"
        );


    if (!raw || !summary) {
        perror("fopen");
        return EXIT_FAILURE;
    }


    fprintf(
        raw,
        "operation,sample,time_us\n"
    );


    fprintf(
        summary,
        "operation,n_samples,batch,"
        "mean_us,median_us,p95_us,stddev_us,"
        "p_proc_w,median_energy_mj\n"
    );


    printf(
        "EA-CryptoAgility Raspberry Pi benchmark\n"
    );

    printf(
        "Samples       : %d\n",
        n_samples
    );

    printf(
        "Batch         : %d operations/sample\n",
        batch
    );

    printf(
        "P_PROC        : %.6f W\n",
        p_proc_w
    );

    printf(
        "Policy bytes  : %zu\n",
        strlen(ctx.policy_json)
    );


    benchmark_operation(
        "POLICY_MAC_CRYPTO",
        op_policy_mac_crypto,
        &ctx,
        n_samples,
        batch,
        p_proc_w,
        raw,
        summary
    );


    benchmark_operation(
        "POLICY_MAC_FULL",
        op_policy_mac_full,
        &ctx,
        n_samples,
        batch,
        p_proc_w,
        raw,
        summary
    );


    benchmark_operation(
        "POLICY_MAC_VERIFY",
        op_policy_mac_verify,
        &ctx,
        n_samples,
        batch,
        p_proc_w,
        raw,
        summary
    );


    benchmark_operation(
        "CHECKPOINT_HASH_128",
        op_checkpoint_hash_128,
        &ctx,
        n_samples,
        batch,
        p_proc_w,
        raw,
        summary
    );


    benchmark_operation(
        "CHECKPOINT_HASH_256",
        op_checkpoint_hash_256,
        &ctx,
        n_samples,
        batch,
        p_proc_w,
        raw,
        summary
    );


    benchmark_operation(
        "CHECKPOINT_HASH_512",
        op_checkpoint_hash_512,
        &ctx,
        n_samples,
        batch,
        p_proc_w,
        raw,
        summary
    );


    fclose(raw);
    fclose(summary);


    printf(
        "\nResults written to:\n"
        "  ea_bench_samples.csv\n"
        "  ea_bench_summary.csv\n"
    );


    /*
     * Prevent optimizer from considering
     * cryptographic results unused.
     */
    printf(
        "Benchmark sink: %u\n",
        (unsigned int)g_sink
    );


    return EXIT_SUCCESS;
}