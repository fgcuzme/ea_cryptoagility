from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Dict, Iterable, Optional, Any


EA_LOG_FIELDS = [
    "run_id",
    "seed",
    "scenario_id",
    "time_s",
    "node_id",
    "neighbor_id",
    "message_type",
    "profile_id",
    "checkpoint_rule",
    "rekey_rule",
    "payload_mode",
    "energy_pressure",
    "security_risk",
    "per",
    "snr_db",
    "retransmission_rate",
    "dag_load",
    "risk_level",
    "energy_bucket",
    "tx_size_bytes",
    "policy_meta_bytes",
    "crypto_proof_bytes",
    "crypto_time_ms",
    "crypto_energy_mj",
    "tx_energy_mj",
    "rx_energy_mj",
    "retransmission_energy_mj",
    "total_energy_mj",
    "latency_ms",
    "pdr",
    "num_sign",
    "num_verify",
    "num_rekey",
    "num_checkpoint",
    "downgrade_injected",
    "downgrade_detected",
    "replay_detected",
    "invalid_policy_meta",
    "invalid_tx_rejected",
    "attack_label",
]


class EAEventLogger:
    """
    Append-only CSV logger for EA-CryptoAgility events.
    """

    def __init__(self, path: str | os.PathLike, extra_fields: Optional[Iterable[str]] = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fields = list(EA_LOG_FIELDS)
        if extra_fields:
            for f in extra_fields:
                if f not in self.fields:
                    self.fields.append(f)
        self._initialized = self.path.exists() and self.path.stat().st_size > 0

    def log(self, row: Dict[str, Any]) -> None:
        clean = {k: row.get(k, "") for k in self.fields}
        with self.path.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.fields)
            if not self._initialized:
                writer.writeheader()
                self._initialized = True
            writer.writerow(clean)
