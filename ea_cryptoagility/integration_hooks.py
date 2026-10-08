from __future__ import annotations

import os
import time
from collections import deque
from typing import Any, Dict, Optional

# from .ea_crypto_costs import estimate_total_transaction_cost, operation_counts_for_policy
from .ea_logger import EAEventLogger
from .ea_policy_engine import (compute_energy_pressure, compute_next_s3_clean_streak, select_policy,)
from .ea_policy_metadata import build_policy_metadata, verify_policy_metadata
# from .ea_types import CrossLayerState, MessageType, PolicyTuple, Thresholds

from .ea_crypto_costs import (estimate_crypto_cost, estimate_transaction_size_bytes,)
from .ea_types import (CrossLayerState, MessageType, PolicyTuple, Thresholds, 
                       ProfileID, CheckpointRule, RekeyRule, PayloadMode,)

DEFAULT_POLICY_KEY = b"EA-CryptoAgility-U-Tangle-policy-key-v1"

### Helper
# ============================================================
# Cross-layer observation tracking
# ============================================================
DEFAULT_OBSERVATION_WINDOW = int(
    os.environ.get("EA_OBSERVATION_WINDOW","20",)
)

def _clip01(value: float) -> float:
    return max(0.0, min(1.0, float(value)),)

def _get_observation_store(
    ea_ctx: Dict[str, Any],
) -> Dict[int, Dict[str, Any]]:
    """
    Estado de observación LOCAL al run.
    No se utilizan globals para evitar contaminación entre
    ejecuciones independientes.
    """
    return ea_ctx.setdefault("_observation_state", {},)

def _get_node_observation(
    ea_ctx: Dict[str, Any],
    node_id: int,
) -> Dict[str, Any]:
    store = _get_observation_store(ea_ctx)
    node_id = int(node_id)
    if node_id not in store:
        window = max(
            1,
            int(
                ea_ctx.get(
                    "observation_window",
                    DEFAULT_OBSERVATION_WINDOW,
                )
            ),
        )

        store[node_id] = {
            # Resultado de cada intento DATA:
            # 0 = recibido
            # 1 = perdido
            "data_losses": deque(maxlen=window),

            # Una entrada por paquete lógico:
            # 0 = no necesitó retry
            # 1 = necesitó >= 1 retry
            "logical_retries": deque(maxlen=window),

            # Resultado de verificaciones:
            # 0 = válida
            # 1 = inválida
            "invalid_verifications": deque(maxlen=window),

            # Evidencias de seguridad recientes
            "downgrade_detected": False,
            "replay_detected": False,
            "suspicious_identity": False,

            # Número total de observaciones.
            "data_attempts_total": 0,
            "logical_packets_total": 0,
            "verification_events_total": 0,
        }
    return store[node_id]
###

### funcion de observacion update
def update_cross_layer_observation(
    ea_ctx: Dict[str, Any],
    node_id: int,
    *,
    data_success: Optional[bool] = None,
    logical_packet_had_retry: Optional[bool] = None,
    verification_valid: Optional[bool] = None,
    downgrade_detected: Optional[bool] = None,
    replay_detected: Optional[bool] = None,
    suspicious_identity: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Actualiza únicamente observaciones que YA ocurrieron.
    Esta función no selecciona políticas y no utiliza valores
    sintéticos de SC1-SC5.
    """
    obs = _get_node_observation(ea_ctx, node_id,)

    if data_success is not None:
        obs["data_losses"].append(
            0.0 if bool(data_success) else 1.0
        )
        obs["data_attempts_total"] += 1

    if logical_packet_had_retry is not None:
        obs["logical_retries"].append(
            1.0
            if bool(logical_packet_had_retry)
            else 0.0
        )
        obs["logical_packets_total"] += 1

    if verification_valid is not None:
        obs["invalid_verifications"].append(
            0.0
            if bool(verification_valid)
            else 1.0
        )
        obs["verification_events_total"] += 1

    # agregado
    if downgrade_detected is not None:
        obs["downgrade_detected"] = bool(downgrade_detected)

    if replay_detected is not None:
        obs["replay_detected"] = bool(replay_detected)

    if suspicious_identity is not None:
        obs["suspicious_identity"] = bool(suspicious_identity)

    return obs
###

### new
# ============================================================
# Policy hysteresis / cooldown memory
# ============================================================

def _get_policy_memory_store(
    ea_ctx: Dict[str, Any],
) -> Dict[int, Dict[str, Any]]:
    """
    Memoria de política LOCAL al run.
    Mantiene, por nodo:
        - último perfil seleccionado;
        - racha de decisiones limpias para salida de S3.
    Se almacena dentro de ea_ctx para evitar contaminación
    entre ejecuciones independientes.
    """
    return ea_ctx.setdefault(
        "_policy_memory",
        {},
    )

def _get_node_policy_memory(
    ea_ctx: Dict[str, Any],
    node_id: int,
) -> Dict[str, Any]:
    """
    Obtiene/inicializa la memoria de política de un nodo.
    """
    store = _get_policy_memory_store(
        ea_ctx
    )

    node_id = int(node_id)

    if node_id not in store:
        store[node_id] = {
            "previous_profile": ProfileID.S1.value,
            "s3_clean_streak": 0,
        }

    return store[node_id]
###

### función de observación get
def get_cross_layer_observation(
    ea_ctx: Dict[str, Any],
    node_id: int,
    *,
    fallback_per: float = 0.0,
    fallback_dag_load: float = 0.0,
) -> Dict[str, Any]:
    """
    Devuelve Ω_i(t) observado ANTES de seleccionar la política
    de la siguiente transacción.
    Si todavía no existe historial DATA, se utiliza únicamente
    el PER físico instantáneo como condición inicial.
    """
    obs = _get_node_observation(ea_ctx, node_id,)

    losses = obs["data_losses"]

    if len(losses) > 0:
        per_i = sum(losses) / len(losses)
        per_source = "OBSERVED_WINDOW"
    else:
        per_i = _clip01(fallback_per)
        per_source = "PHY_INITIALIZATION"

    retries = obs["logical_retries"]

    if len(retries) > 0:
        ret_i = sum(retries) / len(retries)
    else:
        ret_i = 0.0

    invalid = obs["invalid_verifications"]

    if len(invalid) > 0:
        inv_i = sum(invalid) / len(invalid)
    else:
        inv_i = 0.0

    return {
        "per": _clip01(per_i),
        "per_source": per_source,
        "retransmission_rate": _clip01(ret_i),
        "invalid_signature_rate": _clip01(inv_i),
        "dag_load": _clip01(fallback_dag_load),
        "downgrade_detected":
            bool(obs["downgrade_detected"]),
        "replay_detected":
            bool(obs["replay_detected"]),
        "suspicious_identity":
            bool(obs["suspicious_identity"]),
        "observation_window":
            int(
                ea_ctx.get("observation_window", DEFAULT_OBSERVATION_WINDOW,)
            ),

        "data_window_samples": len(losses),
        "retry_window_samples": len(retries),
        "verification_window_samples": len(invalid),
    }
###

def infer_message_type(tx: Dict[str, Any]) -> MessageType:
    """
    Infer message type from a UWSNsecure transaction dictionary.
   You can customize this mapping according to your Tx fields.
    """
    raw = (
        tx.get("message_type")
        or tx.get("MessageType")
        or tx.get("Type")
        or tx.get("type")
        or "TELEMETRY"
    )
    try:
        return MessageType(str(raw))
    except ValueError:
        return MessageType.TELEMETRY


def node_energy(node: Dict[str, Any], default_initial: float = 100.0) -> tuple[float, float]:
    """
    Extract residual and initial energy from UWSNsecure node dictionaries.
    ResidualEnergy is prioritized because it is updated by the acoustic
    transmission model.
    """
    if not isinstance(node, dict):
        raise TypeError(
            f"EA-CryptoAgility expected node as dict, got {type(node)} with value {node}"
        )

    residual_keys = ["ResidualEnergy", "energy", "Energy", "E_res", "Battery"]
    initial_keys = ["E_init", "InitialEnergy", "E0"]

    residual = default_initial
    for k in residual_keys:
        if k in node and node[k] is not None:
            residual = node[k]
            break

    initial = default_initial
    for k in initial_keys:
        if k in node and node[k] is not None:
            initial = node[k]
            break

    return float(residual), float(initial)


# Helper para reconstruir PolicyTuple
def policy_tuple_from_dict(
    policy_dict: Dict[str, Any],
) -> PolicyTuple:
    """
    Reconstruye el PolicyTuple a partir del formato serializable
    almacenado en tx["Policy"].
    """

    return PolicyTuple(
        profile_id=ProfileID(
            policy_dict["profile_id"]
        ),
        checkpoint_rule=CheckpointRule(
            policy_dict["checkpoint_rule"]
        ),
        rekey_rule=RekeyRule(
            policy_dict["rekey_rule"]
        ),
        payload_mode=PayloadMode(
            policy_dict["payload_mode"]
        ),
    )

# Helper para coste incremental EA
def estimate_ea_incremental_processing(
    policy: PolicyTuple,
    *,
    side: str,
    checkpoint_amortization: float = 0.0,
    checkpoint_input_bytes: int = 256,
    rekey_triggered: bool = False,
    already_accounted_ops=None,
) -> Dict[str, Any]:
    """
    Calcula solamente el procesamiento ADICIONAL introducido por EA.

    already_accounted_ops contiene operaciones que el baseline U-Tangle
    ya descuenta mediante energia_dinamica.py.

    DATA sender:
        ASCON_AEAD_ENC ya contabilizado.

    DATA receiver:
        ASCON_AEAD_DEC ya contabilizado.
    """

    already_accounted_ops = set(
        already_accounted_ops or []
    )

    full = estimate_crypto_cost(
        policy,
        side=side,
        rekey_triggered=rekey_triggered,
        checkpoint_amortization=checkpoint_amortization,
        checkpoint_input_bytes=checkpoint_input_bytes,
    )

    incremental_time_ms = 0.0
    incremental_energy_mj = 0.0

    incremental_counts = {}
    incremental_breakdown = {}

    for op, data in full.get(
        "operation_breakdown", {}
    ).items():

        if op in already_accounted_ops:
            continue

        count = float(data.get("count", 0.0))
        time_ms = float(data.get("time_ms", 0.0))
        energy_mj = float(
            data.get("energy_mj", 0.0)
        )

        incremental_counts[op] = count

        incremental_breakdown[op] = dict(data)

        incremental_time_ms += time_ms
        incremental_energy_mj += energy_mj

    return {
        "incremental_operation_counts":
            incremental_counts,

        "incremental_operation_breakdown":
            incremental_breakdown,

        "incremental_processing_time_ms":
            incremental_time_ms,

        "incremental_processing_energy_mj":
            incremental_energy_mj,
    }

# Helper para descontar procesamiento EA del nodo
def apply_incremental_processing_energy(
    node: Dict[str, Any],
    energy_mj: float,
) -> float:
    """
    Descuenta del nodo la energía de procesamiento adicional EA.

    Returns
    -------
    consumed_j : float
        Energía realmente descontada en joules.
    """

    if node is None:
        return 0.0

    if "ResidualEnergy" not in node:
        return 0.0

    requested_j = max(
        0.0,
        float(energy_mj) / 1000.0,
    )

    before = float(node["ResidualEnergy"])

    node["ResidualEnergy"] = max(
        before - requested_j,
        0.0,
    )

    return before - float(
        node["ResidualEnergy"]
    )

###


###

def build_state_from_uwsnsecure(
    node: Dict[str, Any],
    tx: Optional[Dict[str, Any]] = None,
    run_time_s: Optional[float] = None,
    per: float = 0.0,
    retransmission_rate: float = 0.0,
    dag_load: float = 0.0,
    security_risk: float = 0.0,
    invalid_signature_rate: float = 0.0,
    downgrade_detected: bool = False,
    replay_detected: bool = False,
    suspicious_identity: bool = False,
    ea_ctx: Optional[Dict[str, Any]] = None,
    neighbor_id: Optional[int] = None,
) -> CrossLayerState:
    tx = tx or {}
    residual, initial = node_energy(node)
    node_id = int(node.get("NodeID", node.get("node_id", -1)))

    ###
    # --------------------------------------------------------
    # Policy memory defaults
    # --------------------------------------------------------
    previous_profile = (ProfileID.S1.value)
    s3_clean_streak = 0

    ###
    observed = None

    if ea_ctx is not None:
        observed = get_cross_layer_observation(
            ea_ctx,
            node_id,
            fallback_per=per,
            fallback_dag_load=dag_load,
        )
        
        per = observed["per"]
        retransmission_rate = (observed["retransmission_rate"])
        invalid_signature_rate = (observed["invalid_signature_rate"])
        ## agregado
        dag_load = observed["dag_load"]
        ##
        downgrade_detected = (observed["downgrade_detected"])
        replay_detected = (observed["replay_detected"])
        suspicious_identity = (observed["suspicious_identity"])

        ### add
        policy_memory = (
            _get_node_policy_memory(ea_ctx, node_id,)
        )
        previous_profile = str(
            policy_memory.get("previous_profile", ProfileID.S1.value,)
        )

        s3_clean_streak = max(
            0,
            int(
                policy_memory.get("s3_clean_streak",0,)
            ),
        )
        ###
    ###

    return CrossLayerState(
        node_id=node_id,
        time_s=time.time() if run_time_s is None else float(run_time_s),
        message_type=infer_message_type(tx),
        residual_energy_j=residual,
        initial_energy_j=initial,
        per=float(per),
        retransmission_rate=float(retransmission_rate),
        dag_load=float(dag_load),
        # security_risk=float(security_risk),
        security_risk=0.0,
        invalid_signature_rate=float(invalid_signature_rate),
        downgrade_detected=bool(downgrade_detected),
        replay_detected=bool(replay_detected),
        suspicious_identity=bool(suspicious_identity),
        role=str(node.get("Role", "SN")),
        neighbor_id=neighbor_id,
        ## add policy memory
        previous_profile=previous_profile,
        s3_clean_streak=s3_clean_streak,
    )


def attach_policy_to_transaction(
    tx: Dict[str, Any],
    node: Dict[str, Any],
    epoch: int,
    key: bytes = DEFAULT_POLICY_KEY,
    thresholds: Thresholds = Thresholds(),
    per: float = 0.0,
    retransmission_rate: float = 0.0,
    dag_load: float = 0.0,
    security_risk: float = 0.0,
    invalid_signature_rate: float = 0.0,
    downgrade_detected: bool = False,
    replay_detected: bool = False,
    suspicious_identity: bool = False,
    # agregado
    ea_ctx: Optional[Dict[str, Any]] = None,
    neighbor_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Select π_i(t), build policy_meta_i(t), and attach them to an existing transaction dict.

    This is the main integration point before ingest_tx(...).
    """
    state = build_state_from_uwsnsecure(
        node=node,
        tx=tx,
        per=per,
        retransmission_rate=retransmission_rate,
        dag_load=dag_load,
        security_risk=security_risk,
        invalid_signature_rate=invalid_signature_rate,
        downgrade_detected=downgrade_detected,
        replay_detected=replay_detected,
        suspicious_identity=suspicious_identity,
        # agregado
        ea_ctx=ea_ctx,
        neighbor_id=neighbor_id,
    )
    policy = select_policy(state, thresholds)

    ###
    next_s3_clean_streak = (
        compute_next_s3_clean_streak(
            state,
            thresholds,
            security_risk=state.security_risk,
        )
    )
    ###

    ## add
    # ========================================================
    # Persist policy hysteresis/cooldown state
    # ========================================================
    if ea_ctx is not None:
        policy_memory = (_get_node_policy_memory(ea_ctx, state.node_id,))
        policy_memory["previous_profile"] = policy.profile_id.value
        # El streak solo tiene significado mientras el nodo
        # permanece en S3. Al abandonar S3 se reinicia.
        policy_memory["s3_clean_streak"] = (
            int(next_s3_clean_streak)
            if policy.profile_id == ProfileID.S3
            else 0
        )
    ##

    meta = build_policy_metadata(policy, state, epoch=epoch, key=key)
    tx["Policy"] = policy.as_dict()
    tx["policy_meta"] = meta.as_dict()
    tx["ea_state"] = state.as_dict()

    ###
    # ========================================================
    # Consume one-shot adversarial evidence
    # ========================================================
    # Security-event flags remain latched until they have
    # participated in at least one policy decision.
    # Persistent evidence is still represented by windowed
    # metrics such as Inv_i(t).
    # ========================================================
    if ea_ctx is not None:
        obs = _get_node_observation(ea_ctx, state.node_id,)
        obs["downgrade_detected"] = False
        obs["replay_detected"] = False
        obs["suspicious_identity"] = False
    ###

    # # Update optional cost fields.
    # # cost = estimate_total_transaction_cost(policy, retransmissions=int(round(retransmission_rate)))
    # cost = estimate_total_transaction_cost(policy, retransmissions=0)
    # tx["ea_cost"] = cost

    # ---------------------------------------------------------
    # Initial EA accounting structure.
    #
    # No acoustic energy and no final processing cost are
    # computed here. Those values are only known at the actual
    # communication event.
    # ---------------------------------------------------------

    initial_size = estimate_transaction_size_bytes(
        policy,
        rekey_triggered=False,
        checkpoint_amortization=0.0,
    )

    tx["ea_cost"] = {
        **initial_size,

        "processing_time_ms": 0.0,
        "processing_energy_mj": 0.0,

        "ea_sender_incremental_time_ms": 0.0,
        "ea_sender_incremental_energy_mj": 0.0,

        "ea_receiver_incremental_time_ms": 0.0,
        "ea_receiver_incremental_energy_mj": 0.0,

        "base_processing_energy_mj": 0.0,

        "communication_energy_mj": 0.0,

        "sender_event_energy_mj": 0.0,
        "receiver_event_energy_mj": 0.0,

        "total_energy_mj": 0.0,

        "energy_scope": "NOT_FINALIZED",
    }

    return tx


def verify_transaction_policy(
    tx: Dict[str, Any],
    node: Dict[str, Any],
    epoch: int,
    key: bytes = DEFAULT_POLICY_KEY,
    thresholds: Thresholds = Thresholds(),
) -> bool:
    """
    Recompute expected policy from stored ea_state and verify metadata.
    Use this during transaction validation/ingestion.
    """
    meta = tx.get("policy_meta") or {}
    state_dict = tx.get("ea_state") or {}
    if not meta or not state_dict:
        return False

    # Rebuild CrossLayerState safely.
    state = CrossLayerState(
        node_id=int(state_dict.get("node_id", node.get("NodeID", -1))),
        time_s=float(state_dict.get("time_s", 0.0)),
        message_type=MessageType(state_dict.get("message_type", "TELEMETRY")),
        residual_energy_j=float(state_dict.get("residual_energy_j", 100.0)),
        initial_energy_j=float(state_dict.get("initial_energy_j", 100.0)),
        per=float(state_dict.get("per", 0.0)),
        snr_db=state_dict.get("snr_db"),
        retransmission_rate=float(state_dict.get("retransmission_rate", 0.0)),
        dag_load=float(state_dict.get("dag_load", 0.0)),
        security_risk=float(state_dict.get("security_risk", 0.0)),
        invalid_signature_rate=float(state_dict.get("invalid_signature_rate", 0.0)),
        downgrade_detected=bool(state_dict.get("downgrade_detected", False)),
        replay_detected=bool(state_dict.get("replay_detected", False)),
        suspicious_identity=bool(state_dict.get("suspicious_identity", False)),
        role=str(state_dict.get("role",node.get("Role", "SN"))),
        neighbor_id=state_dict.get("neighbor_id"),
        attack_label=str(state_dict.get("attack_label","NONE")),
        previous_profile=str(state_dict.get("previous_profile", ProfileID.S1.value,)),
        s3_clean_streak=max(0, int(state_dict.get("s3_clean_streak", 0,)),),
    )
    expected_policy = select_policy(state, thresholds)

    return verify_policy_metadata(meta, expected_policy, state, epoch=epoch, key=key)


def log_ea_transaction(
    logger: EAEventLogger,
    run_id: str,
    seed: int,
    scenario_id: str,
    tx: Dict[str, Any],
    latency_ms: float = 0.0,
    pdr: float = 1.0,
    downgrade_injected: bool = False,
    invalid_policy_meta: bool = False,
    invalid_tx_rejected: bool = False,
) -> None:
    
    # Baseline/static runs do not create an EA logger. Return safely.
    if logger is None:
        return
    
    policy = tx.get("Policy", {})
    meta = tx.get("policy_meta", {})
    state = tx.get("ea_state", {})
    cost = tx.get("ea_cost", {})
    ops = cost.get("operation_counts", {}) if isinstance(cost.get("operation_counts"), dict) else {}

    initial = float(state.get("initial_energy_j", 100.0))
    residual = float(state.get("residual_energy_j", 100.0))
    ep = compute_energy_pressure(residual, initial)

    logger.log({
        "run_id": run_id,
        "seed": seed,
        "scenario_id": scenario_id,
        "time_s": state.get("time_s", ""),
        "node_id": state.get("node_id", ""),
        "neighbor_id": state.get("neighbor_id", ""),
        "message_type": state.get("message_type", ""),
        "profile_id": policy.get("profile_id", ""),
        "checkpoint_rule": policy.get("checkpoint_rule", ""),
        "rekey_rule": policy.get("rekey_rule", ""),
        "payload_mode": policy.get("payload_mode", ""),
        "energy_pressure": ep,
        "security_risk": state.get("security_risk", ""),
        "per": state.get("per", ""),
        "snr_db": state.get("snr_db", ""),
        "retransmission_rate": state.get("retransmission_rate", ""),
        "dag_load": state.get("dag_load", ""),
        "risk_level": meta.get("risk_level", ""),
        "energy_bucket": meta.get("energy_bucket", ""),
        "tx_size_bytes": cost.get("tx_size_bytes", ""),
        "policy_meta_bytes": cost.get("policy_meta_bytes", ""),
        "crypto_proof_bytes": cost.get("crypto_proof_bytes", ""),
        "crypto_time_ms": cost.get("crypto_time_ms", ""),
        "crypto_energy_mj": cost.get("crypto_energy_mj", ""),
        "tx_energy_mj": cost.get("tx_energy_mj", ""),
        "rx_energy_mj": cost.get("rx_energy_mj", ""),
        "retransmission_energy_mj": cost.get("retransmission_energy_mj", ""),
        "total_energy_mj": cost.get("total_energy_mj", ""),
        "latency_ms": latency_ms,
        "pdr": pdr,
        "num_sign": ops.get("ED25519_SIGN", 0),
        "num_verify": ops.get("ED25519_VERIFY", 0),
        "num_rekey": ops.get("X25519", 0),
        "num_checkpoint": ops.get("CHECKPOINT_HASH", 0),
        "downgrade_injected": downgrade_injected,
        "downgrade_detected": state.get("downgrade_detected", False),
        "replay_detected": state.get("replay_detected", False),
        "invalid_policy_meta": invalid_policy_meta,
        "invalid_tx_rejected": invalid_tx_rejected,
        "attack_label": state.get("attack_label", "NONE"),
    })


# New function
def maybe_tamper_policy_metadata(
    tx: Dict[str, Any],
    ea_ctx: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Injects controlled policy_meta tampering for IRR evaluation.

    This function must be called after attach_policy_to_transaction()
    and before ingest_tx(). It modifies policy_meta after policy_mac has
    been computed, so verify_transaction_policy() should reject the tx.
    """
    import random
    import os

    if ea_ctx is None or not ea_ctx.get("enabled", False):
        return tx

    if not isinstance(tx, dict):
        return tx

    if not isinstance(tx.get("policy_meta"), dict):
        return tx

    # Global switch
    enabled = int(os.environ.get("EA_ENABLE_POLICY_TAMPERING", "0"))
    if enabled != 1:
        return tx

    # Optional scenario filter
    scenario_id = str(ea_ctx.get("scenario_id", ""))
    target_scenarios = os.environ.get("EA_TAMPER_SCENARIOS", "").strip()

    if target_scenarios:
        allowed = {s.strip() for s in target_scenarios.split(",") if s.strip()}
        if scenario_id not in allowed:
            return tx

    # Optional message-type filter.
    # Strong recommendation: do not tamper JOIN in the first validation,
    # because it may disrupt the whole authentication chain.
    msg_type = str(
        tx.get("message_type")
        or tx.get("MessageType")
        or tx.get("Type")
        or tx.get("ea_state", {}).get("message_type", "")
    )

    target_msg_types = os.environ.get(
        "EA_TAMPER_MESSAGE_TYPES",
        "KEY_UPDATE,CONTROL"
    ).strip()

    if target_msg_types:
        allowed_msg = {s.strip() for s in target_msg_types.split(",") if s.strip()}
        if msg_type not in allowed_msg:
            return tx

    prob = float(os.environ.get("EA_TAMPER_POLICY_PROB", "0.0"))

    if prob <= 0.0:
        return tx

    if random.random() > prob:
        return tx

    meta = tx["policy_meta"]

    tamper_field = os.environ.get("EA_TAMPER_FIELD", "policy_mac")

    tx.setdefault("ea_state", {})
    tx["ea_state"]["attack_label"] = "POLICY_TAMPERING"
    tx["ea_state"]["policy_tamper_injected"] = True

    tx["policy_tamper_injected"] = True
    tx["tampered_policy_field"] = tamper_field

    if tamper_field == "policy_mac":
        old_mac = str(meta.get("policy_mac", ""))
        if old_mac:
            # Flip first hex char deterministically enough for MAC mismatch.
            first = old_mac[0]
            new_first = "0" if first != "0" else "1"
            meta["policy_mac"] = new_first + old_mac[1:]
        else:
            meta["policy_mac"] = "00"

    elif tamper_field == "profile_id":
        old = str(meta.get("profile_id", "S1"))
        meta["profile_id"] = "S2" if old != "S2" else "S1"

    elif tamper_field == "risk_level":
        old = str(meta.get("risk_level", "R_LOW"))
        meta["risk_level"] = "R_HIGH" if old != "R_HIGH" else "R_LOW"

    elif tamper_field == "energy_bucket":
        old = str(meta.get("energy_bucket", "E_75_100"))
        meta["energy_bucket"] = "E_0_25" if old != "E_0_25" else "E_75_100"

    elif tamper_field == "epoch":
        meta["epoch"] = int(meta.get("epoch", 1)) + 999

    else:
        # Default safe tamper: corrupt MAC.
        old_mac = str(meta.get("policy_mac", ""))
        meta["policy_mac"] = "00" + old_mac[2:] if len(old_mac) >= 2 else "00"

    tx["policy_meta"] = meta

    return tx