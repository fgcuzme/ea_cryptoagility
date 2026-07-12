from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

from .ea_crypto_costs import estimate_total_transaction_cost, operation_counts_for_policy
from .ea_logger import EAEventLogger
from .ea_policy_engine import compute_energy_pressure, select_policy
from .ea_policy_metadata import build_policy_metadata, verify_policy_metadata
from .ea_types import CrossLayerState, MessageType, PolicyTuple, Thresholds


DEFAULT_POLICY_KEY = b"EA-CryptoAgility-U-Tangle-policy-key-v1"


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


# def node_energy(node: Dict[str, Any], default_initial: float = 100.0) -> tuple[float, float]:
#     """
#     Extract residual and initial energy from UWSNsecure node dicts.
#     Adjust keys if your node structure uses different names.
#     """
#     residual = (
#         node.get("ResidualEnergy")
#         or node.get("energy")
#         or node.get("Energy")
#         or node.get("E_res")
#         or node.get("Battery")
#         or default_initial
#     )
#     initial = (
#         node.get("InitialEnergy")
#         or node.get("E_init")
#         or node.get("E0")
#         or default_initial
#     )
#     return float(residual), float(initial)

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
) -> CrossLayerState:
    tx = tx or {}
    residual, initial = node_energy(node)
    node_id = int(node.get("NodeID", node.get("node_id", -1)))
    return CrossLayerState(
        node_id=node_id,
        time_s=time.time() if run_time_s is None else float(run_time_s),
        message_type=infer_message_type(tx),
        residual_energy_j=residual,
        initial_energy_j=initial,
        per=float(per),
        retransmission_rate=float(retransmission_rate),
        dag_load=float(dag_load),
        security_risk=float(security_risk),
        invalid_signature_rate=float(invalid_signature_rate),
        downgrade_detected=bool(downgrade_detected),
        replay_detected=bool(replay_detected),
        suspicious_identity=bool(suspicious_identity),
        role=str(node.get("Role", "SN")),
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
    )
    policy = select_policy(state, thresholds)
    meta = build_policy_metadata(policy, state, epoch=epoch, key=key)

    tx["Policy"] = policy.as_dict()
    tx["policy_meta"] = meta.as_dict()
    tx["ea_state"] = state.as_dict()

    # Update optional cost fields.
    # cost = estimate_total_transaction_cost(policy, retransmissions=int(round(retransmission_rate)))
    cost = estimate_total_transaction_cost(policy, retransmissions=0)
    tx["ea_cost"] = cost
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