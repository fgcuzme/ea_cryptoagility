# ea_cryptoagility/ea_crypto_costs.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal
import warnings, sys, os

# ---------------------------------------------------------------------
# Canonical U-Tangle processing-energy model
# ---------------------------------------------------------------------
#
# IMPORTANT:
# EA-CryptoAgility MUST use the same processing model as Static U-Tangle.
#
# OPS_TIME:
#   operation execution times obtained from the original U-Tangle
#   calibration.
#
# P_PROC:
#   processing power used by the U-Tangle energy model.
#
# energy_proc_j(t):
#   E_proc = P_PROC * t
#

from energia_dinamica import (
    OPS_TIME,
    P_PROC,
    PROC_BASE,
    energy_proc_j,
)

from .ea_profiles import (
    CRYPTO_PROOF_SIZE_BYTES,
    PAYLOAD_MODE_SIZE_BYTES,
    POLICY_META_SIZE_BYTES,
    PROFILE_CONFIG,
)

from .ea_types import (
    CheckpointRule,
    PolicyTuple,
)


# =====================================================================
# Types
# =====================================================================

ProcessingSide = Literal["sender", "receiver", "pair"]


@dataclass(frozen=True)
class OperationCost:
    """
    Processing cost of one cryptographic/policy operation.

    time_ms:
        execution time in milliseconds.

    energy_mj:
        processing energy derived using the canonical U-Tangle model:

            E = P_PROC * t

    source:
        identifies the calibration source.
    """
    time_ms: float
    energy_mj: float
    source: str = ""


# =====================================================================
# Calibration identifiers
# =====================================================================

BASE_CALIBRATION_ID = "UTANGLE_ENERGIA_DINAMICA"

EA_CALIBRATION_ID = "EA_RPI3B_C_MICROBENCH_R1"


# =====================================================================
# EA-CryptoAgility Raspberry Pi 3 B+ microbenchmarks
# =====================================================================
#
# Experimental methodology:
#
# - compiled C implementation
# - executed directly on Raspberry Pi 3 B+
# - 10,000 batched samples per run
# - 100 operations per sample
# - five independent runs
# - canonical value = median of the five run-level medians
#
# Time values below are expressed in seconds.
#
# POLICY_MAC_FULL includes:
#   canonical policy serialization + HMAC-SHA256 + truncation to 16 B.
#
# POLICY_MAC_VERIFY includes:
#   canonical serialization + HMAC-SHA256 + constant-time comparison.
#
# POLICY_MAC_CRYPTO is retained only for diagnostic decomposition and
# MUST NOT be added together with POLICY_MAC_GEN.
#

EA_POLICY_MAC_CRYPTO_TIME_S = 25.34688e-6

EA_POLICY_MAC_GEN_TIME_S = 27.13282e-6

EA_POLICY_MAC_VERIFY_TIME_S = 27.14218e-6


# ---------------------------------------------------------------------
# SHA-256 checkpoint benchmark
# ---------------------------------------------------------------------
#
# Three input sizes were measured. The checkpoint path must explicitly
# select the size corresponding to the actual serialized object being
# hashed.
#
# IMPORTANT:
# The 32-byte SHA-256 digest size must NOT be confused with the number
# of input bytes processed by SHA-256.
#

CHECKPOINT_HASH_TIME_S: Dict[int, float] = {
    128: 7.77969e-6,
    256: 9.39115e-6,
    512: 12.62552e-6,
}

# Temporary R1 default.
#
# After auditing the real checkpoint input in the simulator, callers
# should pass checkpoint_input_bytes explicitly.
DEFAULT_CHECKPOINT_INPUT_BYTES = 256


# =====================================================================
# Helpers
# =====================================================================

def _operation_cost(
    time_s: float,
    source: str,
) -> OperationCost:
    """
    Convert an execution time into the canonical U-Tangle energy model.
    """

    time_s = max(0.0, float(time_s))

    return OperationCost(
        time_ms=time_s * 1000.0,
        energy_mj=energy_proc_j(time_s) * 1000.0,
        source=source,
    )


def checkpoint_hash_cost(
    input_bytes: int,
) -> OperationCost:
    """
    Return the measured SHA-256 checkpoint cost for a supported
    input size.

    No interpolation is performed because only directly measured
    values should be used in the revision campaign.
    """

    input_bytes = int(input_bytes)

    if input_bytes not in CHECKPOINT_HASH_TIME_S:
        raise ValueError(
            "Unsupported checkpoint hash input size "
            f"{input_bytes} B. Measured sizes are "
            f"{sorted(CHECKPOINT_HASH_TIME_S.keys())}."
        )

    return _operation_cost(
        CHECKPOINT_HASH_TIME_S[input_bytes],
        EA_CALIBRATION_ID,
    )


# =====================================================================
# Operation-cost table
# =====================================================================
#
# Base cryptographic operations inherit their timing and processing
# power directly from energia_dinamica.py.
#
# EA-specific operations use the new compiled-C Raspberry Pi 3
# microbenchmarks, but their energy is still calculated using exactly
# the same U-Tangle P_PROC model.
#

DEFAULT_OPERATION_COSTS: Dict[str, OperationCost] = {

    # --------------------------------------------------------------
    # U-Tangle baseline operations
    # --------------------------------------------------------------

    "ASCON_AEAD_ENC": _operation_cost(
        OPS_TIME["encrypt_s"],
        BASE_CALIBRATION_ID,
    ),

    "ASCON_AEAD_DEC": _operation_cost(
        OPS_TIME["descrypt_s"],
        BASE_CALIBRATION_ID,
    ),

    "ED25519_SIGN": _operation_cost(
        OPS_TIME["sign_s"],
        BASE_CALIBRATION_ID,
    ),

    "ED25519_VERIFY": _operation_cost(
        OPS_TIME["verify_s"],
        BASE_CALIBRATION_ID,
    ),

    "X25519": _operation_cost(
        OPS_TIME["ecdh_x25519_s"],
        BASE_CALIBRATION_ID,
    ),

    "HKDF": _operation_cost(
        OPS_TIME["hkdf_s"],
        BASE_CALIBRATION_ID,
    ),

    # --------------------------------------------------------------
    # EA-CryptoAgility additional operations
    # --------------------------------------------------------------

    "POLICY_MAC_GEN": _operation_cost(
        EA_POLICY_MAC_GEN_TIME_S,
        EA_CALIBRATION_ID,
    ),

    "POLICY_MAC_VERIFY": _operation_cost(
        EA_POLICY_MAC_VERIFY_TIME_S,
        EA_CALIBRATION_ID,
    ),

    # Diagnostic only.
    # Do NOT add this together with POLICY_MAC_GEN.
    "POLICY_MAC_CRYPTO": _operation_cost(
        EA_POLICY_MAC_CRYPTO_TIME_S,
        EA_CALIBRATION_ID,
    ),

    # Default checkpoint entry.
    # estimate_crypto_cost() replaces this with the selected measured
    # input size.
    "CHECKPOINT_HASH": checkpoint_hash_cost(
        DEFAULT_CHECKPOINT_INPUT_BYTES
    ),
}


# =====================================================================
# Check calibration consistency
# =====================================================================

if str(PROC_BASE).lower() != "median":
    warnings.warn(
        "EA-CryptoAgility R1 microbenchmarks use median execution "
        "times, whereas energia_dinamica.py is currently configured "
        f"with PROC_BASE={PROC_BASE!r}. "
        "For the revision campaign use UWSN_PROC_BASE=median.",
        RuntimeWarning,
    )


# =====================================================================
# Profile operation counts
# =====================================================================

def _checkpoint_factor(
    policy: PolicyTuple,
    checkpoint_amortization: float,
) -> float:
    """
    Effective checkpoint executions per transaction.

    IMMEDIATE / STRICT:
        one checkpoint per transaction.

    PERIODIC / BATCHED / DELAYED_OR_BATCHED:
        amortized over several transactions.

        Example:
            one checkpoint every 10 transactions -> 0.1
    """

    rule = policy.checkpoint_rule

    if rule in {
        CheckpointRule.IMMEDIATE,
        CheckpointRule.STRICT,
    }:
        return 1.0

    return max(
        0.0,
        min(1.0, float(checkpoint_amortization)),
    )


def operation_counts_for_policy(
    policy: PolicyTuple,
    *,
    side: ProcessingSide = "sender",
    rekey_triggered: bool = False,
    checkpoint_amortization: float = 0.0,
) -> Dict[str, float]:
    """
    Return operation counts for one transaction.

    side="sender":
        processing performed by the transmitting node.

    side="receiver":
        processing performed by one receiving/validating node.

    side="pair":
        sender + one receiver.

    IMPORTANT:
    X25519 is counted only when a rekey is actually triggered.
    The profile itself does not imply that X25519 is executed for
    every packet.
    """

    if side not in {"sender", "receiver", "pair"}:
        raise ValueError(
            "side must be 'sender', 'receiver', or 'pair'"
        )

    if side == "pair":

        tx_counts = operation_counts_for_policy(
            policy,
            side="sender",
            rekey_triggered=rekey_triggered,
            checkpoint_amortization=checkpoint_amortization,
        )

        rx_counts = operation_counts_for_policy(
            policy,
            side="receiver",
            rekey_triggered=rekey_triggered,
            checkpoint_amortization=checkpoint_amortization,
        )

        keys = set(tx_counts) | set(rx_counts)

        return {
            key: tx_counts.get(key, 0.0)
                 + rx_counts.get(key, 0.0)
            for key in keys
        }

    counts: Dict[str, float] = {
        "ASCON_AEAD_ENC": 0.0,
        "ASCON_AEAD_DEC": 0.0,
        "ED25519_SIGN": 0.0,
        "ED25519_VERIFY": 0.0,
        "X25519": 0.0,
        "HKDF": 0.0,
        "POLICY_MAC_GEN": 0.0,
        "POLICY_MAC_VERIFY": 0.0,
        "CHECKPOINT_HASH": 0.0,
    }

    cfg = PROFILE_CONFIG[policy.profile_id]

    checkpoint_factor = _checkpoint_factor(
        policy,
        checkpoint_amortization,
    )

    # --------------------------------------------------------------
    # Sender
    # --------------------------------------------------------------

    if side == "sender":

        counts["ASCON_AEAD_ENC"] = 1.0

        counts["POLICY_MAC_GEN"] = 1.0

        if cfg.get("requires_signature", False):
            counts["ED25519_SIGN"] = 1.0

        if (
            cfg.get("requires_rekey", False)
            and rekey_triggered
        ):
            counts["X25519"] = 1.0

            # If the actual rekey path performs HKDF after X25519,
            # retain this count. Otherwise set it to 0 in the
            # integration layer.
            counts["HKDF"] = 1.0

        counts["CHECKPOINT_HASH"] = checkpoint_factor

    # --------------------------------------------------------------
    # Receiver / validator
    # --------------------------------------------------------------

    elif side == "receiver":

        counts["ASCON_AEAD_DEC"] = 1.0

        counts["POLICY_MAC_VERIFY"] = 1.0

        if cfg.get(
            "requires_signature_verification",
            False,
        ):
            counts["ED25519_VERIFY"] = 1.0

        if (
            cfg.get("requires_rekey", False)
            and rekey_triggered
        ):
            counts["X25519"] = 1.0
            counts["HKDF"] = 1.0

        counts["CHECKPOINT_HASH"] = checkpoint_factor

    return counts


# =====================================================================
# Processing cost
# =====================================================================

def estimate_crypto_cost(
    policy: PolicyTuple,
    *,
    side: ProcessingSide = "sender",
    rekey_triggered: bool = False,
    checkpoint_amortization: float = 0.0,
    checkpoint_input_bytes: int = DEFAULT_CHECKPOINT_INPUT_BYTES,
    op_costs: Dict[str, OperationCost] | None = None,
) -> Dict[str, Any]:
    """
    Estimate processing time and processing energy only.

    Acoustic TX/RX/retransmission energy is NOT computed here.

    Communication energy must come from energia_dinamica.py and the
    real simulator event.
    """

    costs = dict(
        DEFAULT_OPERATION_COSTS
        if op_costs is None
        else op_costs
    )

    # Use the measured SHA-256 value corresponding to the selected
    # input size.
    costs["CHECKPOINT_HASH"] = checkpoint_hash_cost(
        checkpoint_input_bytes
    )

    counts = operation_counts_for_policy(
        policy,
        side=side,
        rekey_triggered=rekey_triggered,
        checkpoint_amortization=checkpoint_amortization,
    )

    total_time_ms = 0.0
    total_energy_mj = 0.0

    breakdown: Dict[str, Dict[str, float | str]] = {}

    for op, count in counts.items():

        if count <= 0:
            continue

        if op not in costs:
            raise KeyError(
                f"No operation cost configured for {op}"
            )

        cost = costs[op]

        op_time_ms = count * cost.time_ms
        op_energy_mj = count * cost.energy_mj

        total_time_ms += op_time_ms
        total_energy_mj += op_energy_mj

        breakdown[op] = {
            "count": float(count),
            "time_ms": float(op_time_ms),
            "energy_mj": float(op_energy_mj),
            "source": cost.source,
        }

    return {
        "side": side,
        "operation_counts": counts,
        "operation_breakdown": breakdown,

        # Existing names retained for logger compatibility.
        "crypto_time_ms": total_time_ms,
        "crypto_energy_mj": total_energy_mj,

        # More precise names for the revised analysis.
        "processing_time_ms": total_time_ms,
        "processing_energy_mj": total_energy_mj,

        "checkpoint_input_bytes": int(
            checkpoint_input_bytes
        ),

        "p_proc_w": float(P_PROC),
        "proc_base": str(PROC_BASE),
    }


# =====================================================================
# Proof-size model
# =====================================================================

def crypto_proof_size_bytes(
    policy: PolicyTuple,
    *,
    rekey_triggered: bool = False,
    checkpoint_amortization: float = 0.0,
) -> int:
    """
    Estimate bytes added by cryptographic proofs at the sender.

    POLICY_MAC is NOT added here because it is already included in
    POLICY_META_SIZE_BYTES.
    """

    cfg = PROFILE_CONFIG[policy.profile_id]

    total = 0.0

    # AEAD authentication tag
    total += CRYPTO_PROOF_SIZE_BYTES["ASCON_TAG"]

    # Ed25519 signature
    if cfg.get("requires_signature", False):
        total += CRYPTO_PROOF_SIZE_BYTES[
            "ED25519_SIGNATURE"
        ]

    # Rekey material only when a rekey actually occurs
    if (
        cfg.get("requires_rekey", False)
        and rekey_triggered
    ):
        total += CRYPTO_PROOF_SIZE_BYTES[
            "X25519_PUBLIC_KEY"
        ]

    # Checkpoint proof
    checkpoint_factor = _checkpoint_factor(
        policy,
        checkpoint_amortization,
    )

    total += (
        checkpoint_factor
        * CRYPTO_PROOF_SIZE_BYTES["CHECKPOINT_HASH"]
    )

    return int(round(total))


# =====================================================================
# Packet-size model
# =====================================================================

def payload_size_for_policy(
    policy: PolicyTuple,
) -> int:
    return PAYLOAD_MODE_SIZE_BYTES[
        policy.payload_mode
    ]


def estimate_transaction_size_bytes(
    policy: PolicyTuple,
    *,
    base_payload_bytes: int = 96,
    parent_refs_bytes: int = 32,
    timestamp_bytes: int = 8,
    nonce_bytes: int = 8,
    include_policy_meta: bool = True,
    rekey_triggered: bool = False,
    checkpoint_amortization: float = 0.0,
) -> Dict[str, int]:
    """
    Logical transaction-size estimator.

    This function does NOT model acoustic fragmentation.
    """

    payload = min(
        int(base_payload_bytes),
        payload_size_for_policy(policy),
    )

    proof_bytes = crypto_proof_size_bytes(
        policy,
        rekey_triggered=rekey_triggered,
        checkpoint_amortization=checkpoint_amortization,
    )

    policy_meta_bytes = (
        POLICY_META_SIZE_BYTES
        if include_policy_meta
        else 0
    )

    total = (
        payload
        + int(parent_refs_bytes)
        + int(timestamp_bytes)
        + int(nonce_bytes)
        + proof_bytes
        + policy_meta_bytes
    )

    return {
        "payload_bytes": payload,
        "parents_bytes": int(parent_refs_bytes),
        "timestamp_bytes": int(timestamp_bytes),
        "nonce_bytes": int(nonce_bytes),
        "crypto_proof_bytes": int(proof_bytes),
        "policy_meta_bytes": int(policy_meta_bytes),
        "tx_size_bytes": int(total),
    }


# =====================================================================
# Processing-only transaction estimator
# =====================================================================

def estimate_total_transaction_cost(
    policy: PolicyTuple,
    retransmissions: int = 0,
    *,
    side: ProcessingSide = "sender",
    rekey_triggered: bool = False,
    checkpoint_amortization: float = 0.0,
    checkpoint_input_bytes: int = DEFAULT_CHECKPOINT_INPUT_BYTES,
    **legacy_kwargs,
) -> Dict[str, Any]:
    """
    Compatibility wrapper used by the current integration hooks.

    IMPORTANT R1 CHANGE:
    This function does NOT estimate acoustic modem energy.

    TX/RX/retransmission energy must be taken from the actual
    U-Tangle energy model in energia_dinamica.py.

    Until that measured communication energy is supplied, the
    network-wide total_energy_mj is intentionally left as None.
    """

    if legacy_kwargs:
        warnings.warn(
            "Legacy acoustic parameters supplied to "
            "estimate_total_transaction_cost() are ignored. "
            "Communication energy must come from "
            "energia_dinamica.py.",
            RuntimeWarning,
        )

    size = estimate_transaction_size_bytes(
        policy,
        rekey_triggered=rekey_triggered,
        checkpoint_amortization=checkpoint_amortization,
    )

    processing = estimate_crypto_cost(
        policy,
        side=side,
        rekey_triggered=rekey_triggered,
        checkpoint_amortization=checkpoint_amortization,
        checkpoint_input_bytes=checkpoint_input_bytes,
    )

    return {
        **size,
        **processing,

        # Acoustic energy is deliberately not estimated here.
        "tx_energy_mj": None,
        "rx_energy_mj": None,
        "retransmission_energy_mj": None,
        "communication_energy_mj": None,

        # Do not silently call processing energy "total energy".
        "total_energy_mj": None,

        "retransmissions": int(retransmissions),

        "energy_scope": "PROCESSING_ONLY",
        "communication_energy_source":
            "energia_dinamica.py",
    }


# =====================================================================
# Combine processing cost with REAL acoustic-energy measurements
# =====================================================================

def combine_with_measured_communication_energy(
    processing_cost: Dict[str, Any],
    *,
    tx_energy_mj: float,
    rx_energy_mj: float,
    retransmission_energy_mj: float = 0.0,
) -> Dict[str, Any]:
    """
    Combine EA processing cost with acoustic-energy values measured by
    the actual U-Tangle energy model.

    This must be called only with energy obtained from the real
    simulator event / residual-energy accounting.
    """

    result = dict(processing_cost)

    tx_energy_mj = max(
        0.0,
        float(tx_energy_mj),
    )

    rx_energy_mj = max(
        0.0,
        float(rx_energy_mj),
    )

    retransmission_energy_mj = max(
        0.0,
        float(retransmission_energy_mj),
    )

    communication_energy_mj = (
        tx_energy_mj
        + rx_energy_mj
        + retransmission_energy_mj
    )

    processing_energy_mj = float(
        result.get(
            "processing_energy_mj",
            result.get("crypto_energy_mj", 0.0),
        )
    )

    result.update({
        "tx_energy_mj": tx_energy_mj,
        "rx_energy_mj": rx_energy_mj,
        "retransmission_energy_mj":
            retransmission_energy_mj,

        "communication_energy_mj":
            communication_energy_mj,

        "total_energy_mj":
            communication_energy_mj
            + processing_energy_mj,

        "energy_scope":
            "PROCESSING_PLUS_MEASURED_COMMUNICATION",

        "communication_energy_source":
            "energia_dinamica.py",
    })

    return result


# =====================================================================
# Deprecated acoustic estimator
# =====================================================================

def estimate_modem_energy_mj(*args, **kwargs):
    """
    Removed in R1.

    The previous implementation used a second simplified acoustic
    model (fixed P_tx/P_rx), which is inconsistent with the U-Tangle
    distance-dependent energy model.
    """

    raise RuntimeError(
        "estimate_modem_energy_mj() is disabled in Major Revision R1. "
        "Use acoustic TX/RX/retransmission energy obtained from "
        "energia_dinamica.py and "
        "combine_with_measured_communication_energy()."
    )


# =====================================================================
# Calibration report
# =====================================================================

def calibration_summary() -> Dict[str, Any]:
    """
    Return the parameters required for reproducibility.
    """

    return {
        "base_calibration":
            BASE_CALIBRATION_ID,

        "ea_calibration":
            EA_CALIBRATION_ID,

        "proc_base":
            str(PROC_BASE),

        "p_proc_w":
            float(P_PROC),

        "utangle_operation_times_s":
            dict(OPS_TIME),

        "ea_policy_mac_crypto_time_s":
            EA_POLICY_MAC_CRYPTO_TIME_S,

        "ea_policy_mac_gen_time_s":
            EA_POLICY_MAC_GEN_TIME_S,

        "ea_policy_mac_verify_time_s":
            EA_POLICY_MAC_VERIFY_TIME_S,

        "checkpoint_hash_time_s":
            dict(CHECKPOINT_HASH_TIME_S),

        "default_checkpoint_input_bytes":
            DEFAULT_CHECKPOINT_INPUT_BYTES,
    }