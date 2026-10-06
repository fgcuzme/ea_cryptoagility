from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Dict, Optional


class MessageType(str, Enum):
    """Application/control message classes used by the policy engine."""
    TELEMETRY = "TELEMETRY"
    JOIN = "JOIN"
    KEY_UPDATE = "KEY_UPDATE"
    CH_ELECTION = "CH_ELECTION"
    EMERGENCY_ALARM = "EMERGENCY_ALARM"
    CHECKPOINT = "CHECKPOINT"
    CONTROL = "CONTROL"


class ProfileID(str, Enum):
    """Cryptographic profiles S0-S4."""
    S0 = "S0"  # Critical Security
    S1 = "S1"  # Normal Secure Telemetry
    S2 = "S2"  # Energy-Saving Secure Mode
    S3 = "S3"  # High-Risk Security Mode
    S4 = "S4"  # Emergency Minimal-Payload Mode


class CheckpointRule(str, Enum):
    IMMEDIATE = "IMMEDIATE"
    PERIODIC = "PERIODIC"
    BATCHED = "BATCHED"
    DELAYED_OR_BATCHED = "DELAYED_OR_BATCHED"
    STRICT = "STRICT"


class RekeyRule(str, Enum):
    KEEP_CURRENT = "KEEP_CURRENT"
    KEEP_CURRENT_IF_VALID = "KEEP_CURRENT_IF_VALID"
    REQUIRED_IF_APPLICABLE = "REQUIRED_IF_APPLICABLE"
    ADAPTIVE_REKEY = "ADAPTIVE_REKEY"


class PayloadMode(str, Enum):
    FULL_AUTHENTICATED = "FULL_AUTHENTICATED"
    NORMAL_AEAD = "NORMAL_AEAD"
    COMPACT_AEAD = "COMPACT_AEAD"
    MINIMAL_AUTHENTICATED = "MINIMAL_AUTHENTICATED"


# @dataclass(frozen=True)
# class Thresholds:
#     """Thresholds used by Algorithm 1."""
#     PER_HIGH: float = 0.20
#     RET_HIGH: float = 2.0
#     EP_HIGH: float = 0.75
#     EP_CRITICAL: float = 0.90
#     SR_LOW: float = 0.25
#     SR_HIGH: float = 0.70
#     INV_HIGH: float = 0.10
#     D_HIGH: float = 0.75

@dataclass(frozen=True)
class Thresholds:
    """
    Thresholds used by the EA-CryptoAgility policy engine.
    All cross-layer rates are normalized in [0,1].
    Hysteresis:
        HIGH -> threshold to enter a condition.
        LOW/EXIT -> lower threshold required to leave it.
    """

    # --------------------------------------------------------
    # Acoustic channel
    # --------------------------------------------------------
    PER_HIGH: float = 0.20
    PER_LOW: float = 0.10

    # Ret_i(t) =
    # logical packets requiring >=1 retry /
    # logical packets observed
    RET_HIGH: float = 0.50
    RET_LOW: float = 0.25

    # --------------------------------------------------------
    # Energy pressure
    #
    # EP_i(t) = 1 - E_i(t)/E_i,0
    # --------------------------------------------------------
    EP_HIGH: float = 0.75
    EP_HIGH_EXIT: float = 0.70
    EP_CRITICAL: float = 0.90

    # --------------------------------------------------------
    # Security risk
    # --------------------------------------------------------
    SR_LOW: float = 0.25
    SR_HIGH: float = 0.70

    # Hysteresis threshold for leaving S3.
    SR_EXIT: float = 0.40

    # --------------------------------------------------------
    # Invalid verification rate
    # --------------------------------------------------------
    INV_HIGH: float = 0.10
    INV_LOW: float = 0.05

    # --------------------------------------------------------
    # DAG
    # --------------------------------------------------------
    D_HIGH: float = 0.75

    # --------------------------------------------------------
    # S3 cooldown
    # Number of consecutive clean decisions required
    # before leaving S3.
    # --------------------------------------------------------
    S3_COOLDOWN_DECISIONS: int = 3

    # --------------------------------------------------------
    # SR_i(t) weights
    # --------------------------------------------------------
    W_PER: float = 0.20
    W_RET: float = 0.15
    W_INV: float = 0.25
    W_CRIT: float = 0.20
    W_DOW: float = 0.20

@dataclass
class CrossLayerState:
    """
    Compact cross-layer observation vector Ω_i(t).
    PER, retransmission_rate, dag_load, security_risk and
    invalid_signature_rate are normalized in [0,1].
    """
    node_id: int
    time_s: float = 0.0
    message_type: MessageType = MessageType.TELEMETRY

    residual_energy_j: float = 100.0
    initial_energy_j: float = 100.0

    per: float = 0.0
    snr_db: Optional[float] = None
    retransmission_rate: float = 0.0

    dag_load: float = 0.0
    tip_age_s: float = 0.0
    confirmation_delay_s: float = 0.0

    security_risk: float = 0.0
    invalid_signature_rate: float = 0.0
    downgrade_detected: bool = False
    replay_detected: bool = False
    suspicious_identity: bool = False

    # Optional contextual fields
    role: str = "SN"
    neighbor_id: Optional[int] = None
    attack_label: str = "NONE"

    ###
    # --------------------------------------------------------
    # Policy hysteresis/cooldown state
    # --------------------------------------------------------
    # Profile selected for the previous transaction.
    previous_profile: str = "S1"
    # Consecutive clean policy decisions accumulated while
    # recovering from S3.
    s3_clean_streak: int = 0
    ###

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["message_type"] = self.message_type.value if isinstance(self.message_type, Enum) else str(self.message_type)
        return d


@dataclass(frozen=True)
class PolicyTuple:
    """
    π_i(t) = <S*, checkpoint_rule, rekey_rule, payload_mode>
    """
    profile_id: ProfileID
    checkpoint_rule: CheckpointRule
    rekey_rule: RekeyRule
    payload_mode: PayloadMode

    def as_tuple(self):
        return (
            self.profile_id.value,
            self.checkpoint_rule.value,
            self.rekey_rule.value,
            self.payload_mode.value,
        )

    def as_dict(self) -> Dict[str, str]:
        return {
            "profile_id": self.profile_id.value,
            "checkpoint_rule": self.checkpoint_rule.value,
            "rekey_rule": self.rekey_rule.value,
            "payload_mode": self.payload_mode.value,
        }


@dataclass
class PolicyMetadata:
    """
    policy_meta_i(t) = <suite_id, policy_id, profile_id, risk_level,
                       energy_bucket, epoch, policy_mac>
    """
    suite_id: str
    policy_id: str
    profile_id: str
    risk_level: str
    energy_bucket: str
    epoch: int
    checkpoint_rule: str
    rekey_rule: str
    payload_mode: str
    policy_mac: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)
