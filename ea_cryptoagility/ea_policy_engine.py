from __future__ import annotations

from typing import Optional

from .ea_types import (
    CheckpointRule,
    CrossLayerState,
    MessageType,
    PayloadMode,
    PolicyTuple,
    ProfileID,
    RekeyRule,
    Thresholds,
)


def compute_energy_pressure(residual_energy_j: float, initial_energy_j: float) -> float:
    """
    EP_i(t) = 1 - E_i(t) / E_i,0

    Returns a value clipped to [0,1].
    """
    if initial_energy_j <= 0:
        return 1.0
    ep = 1.0 - (residual_energy_j / initial_energy_j)
    return max(0.0, min(1.0, ep))


def compute_security_risk(
    per: float,
    retransmission_rate_norm: float,
    invalid_signature_rate: float,
    criticality: float,
    downgrade_indicator: float,
    weights: Optional[dict] = None,
) -> float:
    """
    SR_i(t) = α1 PER_i(t) + α2 Ret_i(t) + α3 Inv_i(t)
              + α4 Crit_i(t) + α5 Dow_i(t)

    All inputs should be normalized in [0,1].
    """
    w = weights or {
        "per": 0.20,
        "ret": 0.15,
        "invalid": 0.25,
        "criticality": 0.20,
        "downgrade": 0.20,
    }
    total = sum(w.values()) or 1.0
    risk = (
        w["per"] * per
        + w["ret"] * retransmission_rate_norm
        + w["invalid"] * invalid_signature_rate
        + w["criticality"] * criticality
        + w["downgrade"] * downgrade_indicator
    ) / total
    return max(0.0, min(1.0, risk))


def _criticality_from_message(message_type: MessageType) -> float:
    if message_type in {MessageType.JOIN, MessageType.KEY_UPDATE, MessageType.CH_ELECTION}:
        return 1.0
    if message_type == MessageType.EMERGENCY_ALARM:
        return 1.0
    if message_type in {MessageType.CHECKPOINT, MessageType.CONTROL}:
        return 0.7
    return 0.1


def select_policy(
    state: CrossLayerState,
    thresholds: Thresholds = Thresholds(),
) -> PolicyTuple:
    """
    Algorithm 1: Energy-Aware Cryptographic Policy Selection.

    Output:
        π_i(t) = <S*, checkpoint_rule, rekey_rule, payload_mode>
    """
    EP_i = compute_energy_pressure(state.residual_energy_j, state.initial_energy_j)

    # If the caller did not precompute SR_i(t), derive a conservative estimate.
    SR_i = state.security_risk
    if SR_i <= 0.0:
        ret_norm = min(1.0, state.retransmission_rate / max(1.0, thresholds.RET_HIGH))
        crit = _criticality_from_message(state.message_type)
        dow = 1.0 if state.downgrade_detected else 0.0
        SR_i = compute_security_risk(
            per=state.per,
            retransmission_rate_norm=ret_norm,
            invalid_signature_rate=state.invalid_signature_rate,
            criticality=crit,
            downgrade_indicator=dow,
        )

    channel_degraded = (state.per >= thresholds.PER_HIGH) or (
        state.retransmission_rate >= thresholds.RET_HIGH
    )

    high_risk = (
        state.downgrade_detected
        or state.replay_detected
        or state.suspicious_identity
        or state.invalid_signature_rate >= thresholds.INV_HIGH
        or SR_i >= thresholds.SR_HIGH
    )

    # S4: emergency with degraded acoustic channel or critical energy pressure.
    if state.message_type == MessageType.EMERGENCY_ALARM and (
        channel_degraded or EP_i >= thresholds.EP_CRITICAL
    ):
        return PolicyTuple(
            ProfileID.S4,
            CheckpointRule.IMMEDIATE,
            RekeyRule.KEEP_CURRENT_IF_VALID,
            PayloadMode.MINIMAL_AUTHENTICATED,
        )

    # S3: adversarial or suspicious context.
    if high_risk:
        return PolicyTuple(
            ProfileID.S3,
            CheckpointRule.STRICT,
            RekeyRule.ADAPTIVE_REKEY,
            PayloadMode.FULL_AUTHENTICATED,
        )

    # S0: critical control under non-adversarial conditions.
    if state.message_type in {
        MessageType.JOIN,
        MessageType.KEY_UPDATE,
        MessageType.CH_ELECTION,
    }:
        return PolicyTuple(
            ProfileID.S0,
            CheckpointRule.IMMEDIATE,
            RekeyRule.REQUIRED_IF_APPLICABLE,
            PayloadMode.FULL_AUTHENTICATED,
        )

    # S0: emergency under normal channel/energy conditions.
    if state.message_type == MessageType.EMERGENCY_ALARM:
        return PolicyTuple(
            ProfileID.S0,
            CheckpointRule.IMMEDIATE,
            RekeyRule.KEEP_CURRENT_IF_VALID,
            PayloadMode.FULL_AUTHENTICATED,
        )

    # S2: low-risk telemetry under energy pressure or benign channel degradation.
    if (
        state.message_type == MessageType.TELEMETRY
        and SR_i <= thresholds.SR_LOW
        and (EP_i >= thresholds.EP_HIGH or channel_degraded)
    ):
        return PolicyTuple(
            ProfileID.S2,
            CheckpointRule.DELAYED_OR_BATCHED,
            RekeyRule.KEEP_CURRENT,
            PayloadMode.COMPACT_AEAD,
        )

    # S1 with batching: normal telemetry but high DAG load.
    if state.dag_load >= thresholds.D_HIGH:
        return PolicyTuple(
            ProfileID.S1,
            CheckpointRule.BATCHED,
            RekeyRule.KEEP_CURRENT,
            PayloadMode.NORMAL_AEAD,
        )

    # S1 default.
    return PolicyTuple(
        ProfileID.S1,
        CheckpointRule.PERIODIC,
        RekeyRule.KEEP_CURRENT,
        PayloadMode.NORMAL_AEAD,
    )


def select_policy_from_values(
    message_type: str,
    residual_energy_j: float,
    initial_energy_j: float,
    per: float,
    retransmission_rate: float,
    dag_load: float,
    security_risk: float = 0.0,
    invalid_signature_rate: float = 0.0,
    downgrade_detected: bool = False,
    replay_detected: bool = False,
    suspicious_identity: bool = False,
    thresholds: Thresholds = Thresholds(),
) -> PolicyTuple:
    """
    Convenience wrapper for quick integration with UWSNsecure dict-based code.
    """
    state = CrossLayerState(
        node_id=-1,
        message_type=MessageType(message_type),
        residual_energy_j=residual_energy_j,
        initial_energy_j=initial_energy_j,
        per=per,
        retransmission_rate=retransmission_rate,
        dag_load=dag_load,
        security_risk=security_risk,
        invalid_signature_rate=invalid_signature_rate,
        downgrade_detected=downgrade_detected,
        replay_detected=replay_detected,
        suspicious_identity=suspicious_identity,
    )
    return select_policy(state, thresholds)
