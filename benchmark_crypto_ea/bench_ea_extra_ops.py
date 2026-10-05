# bench_ea_extra_ops.py

import hashlib
import statistics
import time

from ea_cryptoagility.ea_policy_metadata import compute_policy_mac


N = 10000
WARMUP = 1000

KEY = b"EA-benchmark-key-32-bytes-value"

POLICY_PAYLOAD = {
    "suite_id": "ASCON_ED25519_X25519",
    "policy_id": "EA_POLICY_V1",
    "profile_id": "S3",
    "checkpoint_rule": "STRICT",
    "rekey_rule": "ADAPTIVE_REKEY",
    "payload_mode": "FULL_AUTHENTICATED",
    "risk_level": "R_HIGH",
    "energy_bucket": "E_50_75",
    "epoch": 100,
    "node_id": 10,
    "message_type": "TELEMETRY",
}

CHECKPOINT_DATA = bytes(256)


def benchmark(fn, n=N, warmup=WARMUP):
    for _ in range(warmup):
        fn()

    samples = []

    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        t1 = time.perf_counter_ns()
        samples.append((t1 - t0) / 1e9)

    samples.sort()

    return {
        "mean_s": statistics.mean(samples),
        "median_s": statistics.median(samples),
        "p95_s": samples[int(0.95 * len(samples))],
        "n": len(samples),
    }


policy_mac_stats = benchmark(
    lambda: compute_policy_mac(
        POLICY_PAYLOAD,
        KEY,
        mac_len_bytes=16,
    )
)

checkpoint_stats = benchmark(
    lambda: hashlib.sha256(CHECKPOINT_DATA).digest()
)


print("POLICY_MAC:", policy_mac_stats)
print("CHECKPOINT_HASH:", checkpoint_stats)

print()
print(
    "EA_POLICY_MAC_TIME_S="
    f"{policy_mac_stats['median_s']:.12f}"
)

print(
    "EA_CHECKPOINT_HASH_TIME_S="
    f"{checkpoint_stats['median_s']:.12f}"
)