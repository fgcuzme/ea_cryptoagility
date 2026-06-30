from __future__ import annotations

from typing import Dict, Any

from .ea_types import ProfileID, CheckpointRule, RekeyRule, PayloadMode


PROFILE_CONFIG: Dict[ProfileID, Dict[str, Any]] = {
    ProfileID.S0: {
        "name": "Critical Security Profile",
        "checkpoint_rule": CheckpointRule.IMMEDIATE,
        "rekey_rule": RekeyRule.REQUIRED_IF_APPLICABLE,
        "payload_mode": PayloadMode.FULL_AUTHENTICATED,
        "requires_signature": True,
        "requires_signature_verification": True,
        "requires_rekey": True,
        "priority_dag": True,
        "description": "Join, key update, CH election, and critical control under non-degraded conditions.",
    },
    ProfileID.S1: {
        "name": "Normal Secure Telemetry Profile",
        "checkpoint_rule": CheckpointRule.PERIODIC,
        "rekey_rule": RekeyRule.KEEP_CURRENT,
        "payload_mode": PayloadMode.NORMAL_AEAD,
        "requires_signature": False,
        "requires_signature_verification": False,
        "requires_rekey": False,
        "priority_dag": False,
        "description": "Regular telemetry under normal energy, channel, DAG, and risk conditions.",
    },
    ProfileID.S2: {
        "name": "Energy-Saving Secure Profile",
        "checkpoint_rule": CheckpointRule.DELAYED_OR_BATCHED,
        "rekey_rule": RekeyRule.KEEP_CURRENT,
        "payload_mode": PayloadMode.COMPACT_AEAD,
        "requires_signature": False,
        "requires_signature_verification": False,
        "requires_rekey": False,
        "priority_dag": False,
        "description": "Low-risk telemetry under energy pressure or benign channel degradation.",
    },
    ProfileID.S3: {
        "name": "High-Risk Security Profile",
        "checkpoint_rule": CheckpointRule.STRICT,
        "rekey_rule": RekeyRule.ADAPTIVE_REKEY,
        "payload_mode": PayloadMode.FULL_AUTHENTICATED,
        "requires_signature": True,
        "requires_signature_verification": True,
        "requires_rekey": True,
        "priority_dag": True,
        "description": "Adversarial conditions: downgrade, replay, invalid signatures, Sybil/spoofing indicators.",
    },
    ProfileID.S4: {
        "name": "Emergency Minimal-Payload Profile",
        "checkpoint_rule": CheckpointRule.IMMEDIATE,
        "rekey_rule": RekeyRule.KEEP_CURRENT_IF_VALID,
        "payload_mode": PayloadMode.MINIMAL_AUTHENTICATED,
        "requires_signature": True,
        "requires_signature_verification": True,
        "requires_rekey": False,
        "priority_dag": True,
        "description": "Emergency alarm under degraded acoustic channel or critical energy pressure.",
    },
}


# Default payload sizes are deltas relative to the baseline application payload.
# Adjust these values to match the exact UWSNsecure transaction format.
PAYLOAD_MODE_SIZE_BYTES: Dict[PayloadMode, int] = {
    PayloadMode.FULL_AUTHENTICATED: 128,
    PayloadMode.NORMAL_AEAD: 96,
    PayloadMode.COMPACT_AEAD: 64,
    PayloadMode.MINIMAL_AUTHENTICATED: 32,
}

# Compact policy metadata fields:
# suite_id(1), policy_id(1), profile_id(1), risk_level(1), energy_bucket(1),
# epoch(4), policy_mac(8-16). Default: 16 bytes MAC -> 25 bytes total.
POLICY_META_SIZE_BYTES: int = 25

# Approximate cryptographic proof sizes.
CRYPTO_PROOF_SIZE_BYTES: Dict[str, int] = {
    "ASCON_TAG": 16,
    "ED25519_SIGNATURE": 64,
    "X25519_PUBLIC_KEY": 32,
    "CHECKPOINT_HASH": 32,
    "POLICY_MAC": 16,
}
