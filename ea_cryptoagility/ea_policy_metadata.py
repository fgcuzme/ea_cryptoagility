from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, Optional

from .ea_policy_engine import compute_energy_pressure
from .ea_types import CrossLayerState, PolicyMetadata, PolicyTuple


DEFAULT_SUITE_ID = "ASCON_ED25519_X25519"
DEFAULT_POLICY_ID = "EA_POLICY_V1"


def energy_bucket(residual_energy_j: float, initial_energy_j: float) -> str:
    """
    Quantized residual-energy bucket for policy metadata.
    """
    if initial_energy_j <= 0:
        return "E_UNKNOWN"
    ratio = residual_energy_j / initial_energy_j
    if ratio <= 0.25:
        return "E_0_25"
    if ratio <= 0.50:
        return "E_25_50"
    if ratio <= 0.75:
        return "E_50_75"
    return "E_75_100"


def risk_level(security_risk: float) -> str:
    if security_risk >= 0.70:
        return "R_HIGH"
    if security_risk >= 0.25:
        return "R_MED"
    return "R_LOW"

### add
def _q6(value: float) -> float:
    """
    Canonical numeric quantization used by the policy-state
    cryptographic binding.
    Six decimal digits are sufficient for the normalized
    cross-layer variables while avoiding representation noise.
    """
    return round(float(value), 6)


def canonical_state_binding(
    state: CrossLayerState,
) -> Dict[str, Any]:
    """
    Policy-relevant cross-layer state authenticated by policy_mac.
    Only variables that can affect policy selection or its
    hysteresis/cooldown memory are included.
    """
    return {
        # ----------------------------------------------------
        # Energy state
        # ----------------------------------------------------
        "residual_energy_j": _q6(state.residual_energy_j),

        "initial_energy_j": _q6(state.initial_energy_j),

        "energy_pressure":
            _q6(
                compute_energy_pressure(
                    state.residual_energy_j,
                    state.initial_energy_j,
                )
            ),

        # ----------------------------------------------------
        # Observed cross-layer metrics
        # ----------------------------------------------------
        "per": _q6(state.per),
        "retransmission_rate": _q6( state.retransmission_rate),
        "dag_load": _q6(state.dag_load),
        "invalid_signature_rate": _q6(state.invalid_signature_rate),

        # ----------------------------------------------------
        # Explicit security evidence
        # ----------------------------------------------------
        "downgrade_detected": bool(state.downgrade_detected),
        "replay_detected":bool(state.replay_detected),
        "suspicious_identity":bool(state.suspicious_identity),

        # ----------------------------------------------------
        # Stateful hysteresis/cooldown
        # ----------------------------------------------------
        "previous_profile":str(state.previous_profile),
        "s3_clean_streak":int(state.s3_clean_streak),

        # ----------------------------------------------------
        # Link context
        # ----------------------------------------------------
        "neighbor_id": (
            None
            if state.neighbor_id is None
            else int(state.neighbor_id)
        ),
    }
###


def canonical_policy_payload(
    policy: PolicyTuple,
    state: CrossLayerState,
    epoch: int,
    suite_id: str = DEFAULT_SUITE_ID,
    policy_id: str = DEFAULT_POLICY_ID,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build a canonical JSON-serializable payload for MAC/signature.
    Keep field names stable for reproducibility.
    """
    payload = {
        "suite_id": suite_id,
        "policy_id": policy_id,
        "profile_id": policy.profile_id.value,
        "checkpoint_rule": policy.checkpoint_rule.value,
        "rekey_rule": policy.rekey_rule.value,
        "payload_mode": policy.payload_mode.value,
        "risk_level": risk_level(state.security_risk),
        "energy_bucket": energy_bucket(state.residual_energy_j, state.initial_energy_j),
        "epoch": int(epoch),
        "node_id": int(state.node_id),
        "message_type": state.message_type.value,
        ### new
        "state_binding_version": "CLSTATE_V1",
        "state_binding": canonical_state_binding(state),
        }
    if extra:
        payload.update(extra)
    return payload


def compute_policy_mac(
    payload: Dict[str, Any],
    key: bytes,
    mac_len_bytes: int = 16,
) -> str:
    """
    HMAC-SHA256 truncated MAC used for simulation of policy_meta authentication.

    In the final system, this field may be implemented through Ascon-MAC/AEAD
    associated data. HMAC here is deterministic, simple, and sufficient for
    simulation-level policy tamper detection.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tag = hmac.new(key, msg, hashlib.sha256).digest()[:mac_len_bytes]
    return tag.hex()


def build_policy_metadata(
    policy: PolicyTuple,
    state: CrossLayerState,
    epoch: int,
    key: bytes,
    suite_id: str = DEFAULT_SUITE_ID,
    policy_id: str = DEFAULT_POLICY_ID,
    extra_mac_fields: Optional[Dict[str, Any]] = None,
) -> PolicyMetadata:
    payload = canonical_policy_payload(
        policy=policy,
        state=state,
        epoch=epoch,
        suite_id=suite_id,
        policy_id=policy_id,
        extra=extra_mac_fields,
    )
    mac = compute_policy_mac(payload, key)
    return PolicyMetadata(
        suite_id=suite_id,
        policy_id=policy_id,
        profile_id=policy.profile_id.value,
        risk_level=payload["risk_level"],
        energy_bucket=payload["energy_bucket"],
        epoch=int(epoch),
        checkpoint_rule=policy.checkpoint_rule.value,
        rekey_rule=policy.rekey_rule.value,
        payload_mode=policy.payload_mode.value,
        policy_mac=mac,
    )


def verify_policy_metadata(
    meta: Dict[str, Any],
    policy: PolicyTuple,
    state: CrossLayerState,
    epoch: int,
    key: bytes,
    suite_id: str = DEFAULT_SUITE_ID,
    policy_id: str = DEFAULT_POLICY_ID,
    extra_mac_fields: Optional[Dict[str, Any]] = None,
) -> bool:
    expected_payload = canonical_policy_payload(
        policy=policy,
        state=state,
        epoch=epoch,
        suite_id=suite_id,
        policy_id=policy_id,
        extra=extra_mac_fields,
    )
    expected_mac = compute_policy_mac(expected_payload, key)

    # Check MAC and visible fields. This catches both metadata tampering and
    # policy/profile mismatch.
    return (
        str(meta.get("suite_id")) == suite_id
        and str(meta.get("policy_id")) == policy_id
        and str(meta.get("profile_id")) == policy.profile_id.value
        and str(meta.get("checkpoint_rule")) == policy.checkpoint_rule.value
        and str(meta.get("rekey_rule")) == policy.rekey_rule.value
        and str(meta.get("payload_mode")) == policy.payload_mode.value
        and str(meta.get("risk_level")) == expected_payload["risk_level"]
        and str(meta.get("energy_bucket")) == expected_payload["energy_bucket"]
        and int(meta.get("epoch", -1)) == int(epoch)
        and hmac.compare_digest(str(meta.get("policy_mac")), expected_mac)
    )
