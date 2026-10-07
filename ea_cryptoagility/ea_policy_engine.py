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


## new
def compute_security_risk(
    per: float,
    retransmission_rate: float,
    invalid_signature_rate: float,
    criticality: float,
    downgrade_indicator: float,
    weights: Optional[dict] = None,
) -> float:
    """
    Compute normalized security risk:
        SR_i(t) = α1 PER_i(t) + α2 Ret_i(t) + α3 Inv_i(t) + α4 Crit_i(t) + α5 Dow_i(t)

    All input indicators must be normalized in [0,1].
    """

    def clip01(x: float) -> float:
        return max(
            0.0,
            min(1.0, float(x)),
        )

    per = clip01(per)
    retransmission_rate = clip01(
        retransmission_rate
    )
    invalid_signature_rate = clip01(
        invalid_signature_rate
    )
    criticality = clip01(criticality)
    downgrade_indicator = clip01(
        downgrade_indicator
    )

    w = weights or {
        "per": 0.20,
        "ret": 0.15,
        "invalid": 0.25,
        "criticality": 0.20,
        "downgrade": 0.20,
    }

    total = float(sum(w.values()))

    if total <= 0.0:
        raise ValueError(
            "Security-risk weights must sum "
            "to a positive value."
        )

    risk = (
        float(w["per"]) * per
        + float(w["ret"])
        * retransmission_rate
        + float(w["invalid"])
        * invalid_signature_rate
        + float(w["criticality"])
        * criticality
        + float(w["downgrade"])
        * downgrade_indicator
    ) / total

    return clip01(risk)
##

def _criticality_from_message(message_type: MessageType) -> float:
    if message_type in {MessageType.JOIN, MessageType.KEY_UPDATE, MessageType.CH_ELECTION}:
        return 1.0
    if message_type == MessageType.EMERGENCY_ALARM:
        return 1.0
    if message_type in {MessageType.CHECKPOINT, MessageType.CONTROL}:
        return 0.7
    return 0.1


## función nueva para calcuar SR_i(t) desde el estado
def compute_state_security_risk(
    state: CrossLayerState,
    thresholds: Thresholds = Thresholds(),
) -> float:
    """
    Derive SR_i(t) exclusively from current cross-layer
    observations.
    scenario.security_risk must not participate here.
    """
    criticality = _criticality_from_message(
        state.message_type
    )

    downgrade_indicator = (
        1.0
        if state.downgrade_detected
        else 0.0
    )

    weights = {
        "per": thresholds.W_PER,
        "ret": thresholds.W_RET,
        "invalid": thresholds.W_INV,
        "criticality": thresholds.W_CRIT,
        "downgrade": thresholds.W_DOW,
    }

    return compute_security_risk(
        per=state.per,
        retransmission_rate=
            state.retransmission_rate,
        invalid_signature_rate=
            state.invalid_signature_rate,
        criticality=criticality,
        downgrade_indicator=
            downgrade_indicator,
        weights=weights,
    )
######

## función de condición para salir de S3
def is_s3_exit_clean(
    state: CrossLayerState,
    thresholds: Thresholds = Thresholds(),
    security_risk: Optional[float] = None,
) -> bool:
    """
    True only if the current observation is sufficiently clean
    to contribute one decision toward S3 cooldown exit.
    """
    sr = (
        compute_state_security_risk(
            state,
            thresholds,
        )
        if security_risk is None
        else float(security_risk)
    )

    explicit_attack = (
        state.downgrade_detected
        or state.replay_detected
        or state.suspicious_identity
    )

    return (
        not explicit_attack
        and
        state.invalid_signature_rate <= thresholds.INV_LOW
        and
        sr <= thresholds.SR_EXIT
    )
##

## add
def compute_next_s3_clean_streak(
    state: CrossLayerState,
    thresholds: Thresholds = Thresholds(),
    security_risk: Optional[float] = None,
) -> int:
    """
    Computes the S3 recovery memory for the NEXT decision.
    IMPORTANT:
    This function does not mutate state. Therefore the state
    serialized in ea_state continues representing the inputs
    used to select the current policy.
    """
    sr = (
        compute_state_security_risk(state, thresholds,)
        if security_risk is None
        else float(security_risk)
    )

    high_risk_now = (
        state.downgrade_detected
        or state.replay_detected
        or state.suspicious_identity
        or state.invalid_signature_rate >= thresholds.INV_HIGH
        or sr >= thresholds.SR_HIGH
    )

    current_streak = max(0,int(getattr(state,"s3_clean_streak",0,)),)

    previous_profile = str(getattr(state, "previous_profile", ProfileID.S1.value,))

    if previous_profile.startswith("ProfileID."):
        previous_profile = (previous_profile.split(".")[-1])

    if high_risk_now:
        return 0

    if (previous_profile== ProfileID.S3.value):
        clean = is_s3_exit_clean(
            state,
            thresholds,
            security_risk=sr,
        )

        if clean:
            return (current_streak + 1)
        return 0

    return 0
##

## function new 
def select_policy(
    state: CrossLayerState,
    thresholds: Thresholds = Thresholds(),
) -> PolicyTuple:
    """
    Energy-Aware Cryptographic Policy Selection.
    The function derives SR_i(t) from actual cross-layer
    observations and applies hysteresis/cooldown rules.
    Output:
        π_i(t) =
        <S*, checkpoint_rule, rekey_rule, payload_mode>
    """

    # ========================================================
    # 1. Energy pressure
    # ========================================================
    EP_i = compute_energy_pressure(
        state.residual_energy_j,
        state.initial_energy_j,
    )

    # ========================================================
    # 2. Security risk
    #
    # Always derived from observations.
    # Never use scenario.security_risk as policy input.
    # ========================================================
    SR_i = compute_state_security_risk(
        state,
        thresholds,
    )

    # IMPORTANT:
    # Keep the state and the policy metadata consistent.
    state.security_risk = SR_i
    # ========================================================
    # 3. Previous policy
    # ========================================================
    previous_profile = str(
        getattr(state,"previous_profile",ProfileID.S1.value,)
    )

    if previous_profile.startswith("ProfileID."):
        previous_profile = (previous_profile.split(".")[-1])

    # ========================================================
    # 4. Channel degradation with hysteresis
    # ========================================================
    channel_degraded_enter = (
        state.per >= thresholds.PER_HIGH
        or
        state.retransmission_rate >= thresholds.RET_HIGH
    )

    channel_degraded_hold = (
        previous_profile == ProfileID.S2.value
        and (
            state.per >= thresholds.PER_LOW
            or
            state.retransmission_rate >= thresholds.RET_LOW
        )
    )

    channel_degraded = (
        channel_degraded_enter
        or channel_degraded_hold
    )

    # ========================================================
    # 5. Energy-pressure hysteresis
    # ========================================================
    energy_pressure_high = (
        EP_i >= thresholds.EP_HIGH
    )

    if (
        previous_profile == ProfileID.S2.value
        and
        EP_i >= thresholds.EP_HIGH_EXIT
    ):
        energy_pressure_high = True

    # ========================================================
    # 6. Current high-risk evidence
    # ========================================================
    high_risk_now = (
        state.downgrade_detected
        or state.replay_detected
        or state.suspicious_identity
        or
        state.invalid_signature_rate >= thresholds.INV_HIGH
        or
        SR_i >= thresholds.SR_HIGH
    )

    # ========================================================
    # 7. S3 hysteresis / cooldown
    # ========================================================

    next_s3_clean_streak = (
        compute_next_s3_clean_streak(
            state,
            thresholds,
            security_risk=SR_i,
        )
    )

    s3_cooldown_active = (
        previous_profile
        == ProfileID.S3.value
        and
        next_s3_clean_streak
        < thresholds.S3_COOLDOWN_DECISIONS
    )

    # ========================================================
    # S4
    # Emergency with degraded channel or critical battery.
    # ========================================================
    if (
        state.message_type
        == MessageType.EMERGENCY_ALARM
        and (
            channel_degraded
            or
            EP_i >= thresholds.EP_CRITICAL
        )
    ):
        return PolicyTuple(
            ProfileID.S4,
            CheckpointRule.IMMEDIATE,
            RekeyRule.KEEP_CURRENT_IF_VALID,
            PayloadMode.MINIMAL_AUTHENTICATED,
        )

    # ========================================================
    # S3
    # Active adversarial evidence OR cooldown from previous S3.
    # ========================================================
    if (
        high_risk_now
        or s3_cooldown_active
    ):
        return PolicyTuple(
            ProfileID.S3,
            CheckpointRule.STRICT,
            RekeyRule.ADAPTIVE_REKEY,
            PayloadMode.FULL_AUTHENTICATED,
        )

    # ========================================================
    # S0
    # Critical security/control traffic.
    # ========================================================
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

    # Emergency under normal conditions.
    if (
        state.message_type == MessageType.EMERGENCY_ALARM
    ):
        return PolicyTuple(
            ProfileID.S0,
            CheckpointRule.IMMEDIATE,
            RekeyRule.KEEP_CURRENT_IF_VALID,
            PayloadMode.FULL_AUTHENTICATED,
        )

    # ========================================================
    # S2
    # Low-risk telemetry under energy/channel pressure.
    # ========================================================
    if (
        state.message_type == MessageType.TELEMETRY
        and
        SR_i <= thresholds.SR_LOW
        and (
            energy_pressure_high
            or channel_degraded
        )
    ):
        return PolicyTuple(
            ProfileID.S2,
            CheckpointRule.DELAYED_OR_BATCHED,
            RekeyRule.KEEP_CURRENT,
            PayloadMode.COMPACT_AEAD,
        )

    # ========================================================
    # S1 with checkpoint batching under DAG congestion.
    # ========================================================
    if (
        state.dag_load >= thresholds.D_HIGH
    ):
        return PolicyTuple(
            ProfileID.S1,
            CheckpointRule.BATCHED,
            RekeyRule.KEEP_CURRENT,
            PayloadMode.NORMAL_AEAD,
        )

    # ========================================================
    # S1 default
    # ========================================================
    return PolicyTuple(
        ProfileID.S1,
        CheckpointRule.PERIODIC,
        RekeyRule.KEEP_CURRENT,
        PayloadMode.NORMAL_AEAD,
    )
###

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
