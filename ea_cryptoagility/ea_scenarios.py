from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .ea_types import MessageType, Thresholds


@dataclass(frozen=True)
class ScenarioConfig:
    scenario_id: str
    description: str
    per: float
    retransmission_rate: float
    residual_energy_ratio: float
    dag_load: float
    security_risk: float
    message_mix: Dict[MessageType, float]
    downgrade_detected: bool = False
    replay_detected: bool = False
    invalid_signature_rate: float = 0.0
    suspicious_identity: bool = False


SCENARIOS: Dict[str, ScenarioConfig] = {
    "SC1_NORMAL": ScenarioConfig(
        scenario_id="SC1_NORMAL",
        description="Stable channel, sufficient energy, low risk, regular telemetry",
        per=0.03,
        retransmission_rate=0.1,
        residual_energy_ratio=0.85,
        dag_load=0.20,
        security_risk=0.05,
        message_mix={MessageType.TELEMETRY: 0.95, MessageType.CONTROL: 0.05},
    ),
    "SC2_LOW_ENERGY": ScenarioConfig(
        scenario_id="SC2_LOW_ENERGY",
        description="Low residual energy, low risk, non-critical telemetry",
        per=0.05,
        retransmission_rate=0.2,
        residual_energy_ratio=0.20,
        dag_load=0.25,
        security_risk=0.05,
        message_mix={MessageType.TELEMETRY: 1.0},
    ),
    "SC3_DEGRADED_CHANNEL": ScenarioConfig(
        scenario_id="SC3_DEGRADED_CHANNEL",
        description="High PER/retransmissions without adversarial evidence",
        per=0.25,
        retransmission_rate=2.5,
        residual_energy_ratio=0.70,
        dag_load=0.35,
        security_risk=0.10,
        message_mix={MessageType.TELEMETRY: 0.90, MessageType.EMERGENCY_ALARM: 0.10},
    ),
    "SC4_HIGH_RISK": ScenarioConfig(
        scenario_id="SC4_HIGH_RISK",
        description="Replay, invalid signatures, downgrade attempt or suspicious identity",
        per=0.10,
        retransmission_rate=1.0,
        residual_energy_ratio=0.70,
        dag_load=0.45,
        security_risk=0.85,
        message_mix={MessageType.TELEMETRY: 0.80, MessageType.CONTROL: 0.20},
        downgrade_detected=True,
        replay_detected=True,
        invalid_signature_rate=0.20,
    ),
    "SC5_DAG_CONGESTION": ScenarioConfig(
        scenario_id="SC5_DAG_CONGESTION",
        description="High transaction backlog or local DAG load",
        per=0.05,
        retransmission_rate=0.3,
        residual_energy_ratio=0.75,
        dag_load=0.90,
        security_risk=0.10,
        message_mix={MessageType.TELEMETRY: 1.0},
    ),
}


def scenario_to_env(s: ScenarioConfig) -> Dict[str, str]:
    """
    Optional: convert scenario into environment variables to run a_run_many.py.
    """
    return {
        "EA_SCENARIO_ID": s.scenario_id,
        "EA_PER": str(s.per),
        "EA_RET_RATE": str(s.retransmission_rate),
        "EA_RESIDUAL_ENERGY_RATIO": str(s.residual_energy_ratio),
        "EA_DAG_LOAD": str(s.dag_load),
        "EA_SECURITY_RISK": str(s.security_risk),
        "EA_DOWNGRADE": "1" if s.downgrade_detected else "0",
        "EA_REPLAY": "1" if s.replay_detected else "0",
        "EA_INVALID_SIG_RATE": str(s.invalid_signature_rate),
    }


def list_scenarios() -> List[str]:
    return list(SCENARIOS.keys())
