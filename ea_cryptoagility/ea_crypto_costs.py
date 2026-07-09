from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any

from .ea_profiles import (
    CRYPTO_PROOF_SIZE_BYTES,
    PAYLOAD_MODE_SIZE_BYTES,
    POLICY_META_SIZE_BYTES,
    PROFILE_CONFIG,
)
from .ea_types import PayloadMode, PolicyTuple, ProfileID


@dataclass(frozen=True)
class OperationCost:
    time_ms: float
    energy_mj: float
    bytes_out: int = 0


# # Calibrate these values using Raspberry Pi microbenchmarks.
# # They are placeholders for simulation structure, not final claims.
# DEFAULT_OPERATION_COSTS: Dict[str, OperationCost] = {
#     "ASCON_AEAD_ENC": OperationCost(time_ms=0.05, energy_mj=0.01, bytes_out=16),
#     "ASCON_AEAD_DEC": OperationCost(time_ms=0.05, energy_mj=0.01, bytes_out=0),
#     "ED25519_SIGN": OperationCost(time_ms=1.00, energy_mj=0.80, bytes_out=64),
#     "ED25519_VERIFY": OperationCost(time_ms=2.00, energy_mj=1.20, bytes_out=0),
#     "X25519": OperationCost(time_ms=1.50, energy_mj=0.90, bytes_out=32),
#     "POLICY_MAC": OperationCost(time_ms=0.03, energy_mj=0.005, bytes_out=16),
#     "CHECKPOINT_HASH": OperationCost(time_ms=0.02, energy_mj=0.003, bytes_out=32),
# }

import os

CPU_ACTIVE_POWER_W = float(os.environ.get("EA_CPU_ACTIVE_POWER_W", "0.8"))


def energy_from_time_ms(time_ms: float, cpu_power_w: float = CPU_ACTIVE_POWER_W) -> float:
    """
    1 W * 1 ms = 1 mJ.
    Therefore, energy_mj = cpu_power_w * time_ms.
    """
    return cpu_power_w * time_ms

# Calibrated from U-Tangle simulation timing statistics.
# These values represent CPU-side cryptographic/processing cost only.
# Acoustic TX/RX energy is computed separately by UWSNsecure.
DEFAULT_OPERATION_COSTS: Dict[str, OperationCost] = {
    # ASCON values are approximated from DATA processing latency.
    # They include Python-level encryption/decryption processing overhead.
    "ASCON_AEAD_ENC": OperationCost(
        time_ms=3.0092,
        energy_mj=energy_from_time_ms(3.0092),
        bytes_out=16,
    ),
    "ASCON_AEAD_DEC": OperationCost(
        time_ms=2.7784,
        energy_mj=energy_from_time_ms(2.7784),
        bytes_out=0,
    ),

    # Ed25519 measured from tangle create/verify events.
    "ED25519_SIGN": OperationCost(
        time_ms=1.1709,
        energy_mj=energy_from_time_ms(1.1709),
        bytes_out=64,
    ),
    "ED25519_VERIFY": OperationCost(
        time_ms=1.3694,
        energy_mj=energy_from_time_ms(1.3694),
        bytes_out=0,
    ),

    # X25519 was not isolated in the provided timing logs.
    # Keep as configurable placeholder until a direct microbenchmark is added.
    "X25519": OperationCost(
        time_ms=1.5000,
        energy_mj=energy_from_time_ms(1.5000),
        bytes_out=32,
    ),

    # POLICY_MAC was not isolated in the current U-Tangle logs.
    # Keep lightweight placeholder or replace after HMAC/ASCON-MAC benchmark.
    "POLICY_MAC": OperationCost(
        time_ms=0.0300,
        energy_mj=energy_from_time_ms(0.0300),
        bytes_out=16,
    ),

    # Mapped to transaction hash/checkpoint hash.
    # Important: amortize this cost for PERIODIC/BATCHED checkpoints.
    "CHECKPOINT_HASH": OperationCost(
        time_ms=6.6656,
        energy_mj=energy_from_time_ms(6.6656),
        bytes_out=32,
    ),
}

def operation_counts_for_policy(policy: PolicyTuple) -> Dict[str, int]:
    """
    Return approximate cryptographic operation counts per generated transaction.

    Tune according to your exact U-Tangle transaction semantics.
    """
    profile = policy.profile_id
    counts = {
        "ASCON_AEAD_ENC": 1,
        "ASCON_AEAD_DEC": 0,
        "ED25519_SIGN": 0,
        "ED25519_VERIFY": 0,
        "X25519": 0,
        "POLICY_MAC": 1,
        "CHECKPOINT_HASH": 0,
    }

    if profile == ProfileID.S0:
        counts["ED25519_SIGN"] = 1
        counts["ED25519_VERIFY"] = 1
        counts["X25519"] = 1
        counts["CHECKPOINT_HASH"] = 1
    elif profile == ProfileID.S1:
        # Periodic/batched checkpointing should be amortized by the caller.
        counts["CHECKPOINT_HASH"] = 1 if policy.checkpoint_rule.value in {"PERIODIC", "BATCHED"} else 0
    elif profile == ProfileID.S2:
        # No per-packet asymmetric operation; checkpoint cost can be batched.
        counts["CHECKPOINT_HASH"] = 0
    elif profile == ProfileID.S3:
        counts["ED25519_SIGN"] = 1
        counts["ED25519_VERIFY"] = 1
        counts["X25519"] = 1
        counts["CHECKPOINT_HASH"] = 1
    elif profile == ProfileID.S4:
        counts["ED25519_SIGN"] = 1
        counts["ED25519_VERIFY"] = 1
        counts["CHECKPOINT_HASH"] = 1

    return counts


def estimate_crypto_cost(
    policy: PolicyTuple,
    op_costs: Dict[str, OperationCost] = DEFAULT_OPERATION_COSTS,
    checkpoint_amortization: float = 1.0,
) -> Dict[str, Any]:
    """
    Estimate crypto time, energy, and proof bytes for the selected policy.

    checkpoint_amortization:
        1.0 = full checkpoint cost per transaction.
        0.1 = one checkpoint amortized over 10 transactions.
    """
    counts = operation_counts_for_policy(policy)

    if policy.checkpoint_rule.value in {"BATCHED", "DELAYED_OR_BATCHED"}:
        counts["CHECKPOINT_HASH"] = counts.get("CHECKPOINT_HASH", 0) * checkpoint_amortization

    total_time_ms = 0.0
    total_energy_mj = 0.0
    total_bytes = 0.0

    for op, n in counts.items():
        cost = op_costs[op]
        total_time_ms += n * cost.time_ms
        total_energy_mj += n * cost.energy_mj
        total_bytes += n * cost.bytes_out

    return {
        "operation_counts": counts,
        "crypto_time_ms": total_time_ms,
        "crypto_energy_mj": total_energy_mj,
        "crypto_proof_bytes": int(round(total_bytes)),
    }


def payload_size_for_policy(policy: PolicyTuple) -> int:
    return PAYLOAD_MODE_SIZE_BYTES[policy.payload_mode]


def estimate_transaction_size_bytes(
    policy: PolicyTuple,
    base_payload_bytes: int = 96,
    parent_refs_bytes: int = 32,
    timestamp_bytes: int = 8,
    nonce_bytes: int = 8,
    include_policy_meta: bool = True,
) -> Dict[str, int]:
    crypto = estimate_crypto_cost(policy)
    payload = min(base_payload_bytes, payload_size_for_policy(policy))
    policy_meta = POLICY_META_SIZE_BYTES if include_policy_meta else 0
    total = payload + parent_refs_bytes + timestamp_bytes + nonce_bytes + crypto["crypto_proof_bytes"] + policy_meta
    return {
        "payload_bytes": payload,
        "parents_bytes": parent_refs_bytes,
        "timestamp_bytes": timestamp_bytes,
        "nonce_bytes": nonce_bytes,
        "crypto_proof_bytes": crypto["crypto_proof_bytes"],
        "policy_meta_bytes": policy_meta,
        "tx_size_bytes": int(total),
    }


def estimate_modem_energy_mj(
    tx_size_bytes: int,
    bitrate_bps: float = 9200.0,
    p_tx_w: float = 2.0,
    p_rx_w: float = 0.75,
    rx_count: int = 1,
    retransmissions: int = 0,
) -> Dict[str, float]:
    """
    Simple acoustic airtime energy model.

    E_tx = P_tx * T_air
    E_rx = P_rx * T_air * rx_count
    E_retx = retransmissions * (E_tx + E_rx)
    """
    t_air_s = (8.0 * tx_size_bytes) / bitrate_bps
    e_tx_mj = p_tx_w * t_air_s * 1000.0
    e_rx_mj = p_rx_w * t_air_s * rx_count * 1000.0
    e_retx_mj = retransmissions * (e_tx_mj + e_rx_mj)
    return {
        "t_air_s": t_air_s,
        "tx_energy_mj": e_tx_mj,
        "rx_energy_mj": e_rx_mj,
        "retransmission_energy_mj": e_retx_mj,
        "modem_energy_mj": e_tx_mj + e_rx_mj + e_retx_mj,
    }


def estimate_total_transaction_cost(
    policy: PolicyTuple,
    retransmissions: int = 0,
    bitrate_bps: float = 9200.0,
    p_tx_w: float = 2.0,
    p_rx_w: float = 0.75,
    rx_count: int = 1,
) -> Dict[str, Any]:
    size = estimate_transaction_size_bytes(policy)
    crypto = estimate_crypto_cost(policy)
    modem = estimate_modem_energy_mj(
        tx_size_bytes=size["tx_size_bytes"],
        bitrate_bps=bitrate_bps,
        p_tx_w=p_tx_w,
        p_rx_w=p_rx_w,
        rx_count=rx_count,
        retransmissions=retransmissions,
    )
    return {
        **size,
        **crypto,
        **modem,
        "total_energy_mj": crypto["crypto_energy_mj"] + modem["modem_energy_mj"],
    }
