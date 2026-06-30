from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Any, List


def _to_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default


def summarize_ea_log(csv_path: str | Path) -> Dict[str, Any]:
    """
    Summarize EA event log without requiring pandas.
    """
    path = Path(csv_path)
    rows: List[dict] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        return {"rows": 0}

    profile_counts = Counter(r.get("profile_id", "") for r in rows)
    scenario_counts = Counter(r.get("scenario_id", "") for r in rows)

    energy = [_to_float(r.get("total_energy_mj")) for r in rows]
    latency = [_to_float(r.get("latency_ms")) for r in rows]
    tx_size = [_to_float(r.get("tx_size_bytes")) for r in rows]

    dow_inj = sum(1 for r in rows if str(r.get("downgrade_injected")).lower() in {"1", "true", "yes"})
    dow_det = sum(1 for r in rows if str(r.get("downgrade_detected")).lower() in {"1", "true", "yes"})
    invalid_rej = sum(1 for r in rows if str(r.get("invalid_tx_rejected")).lower() in {"1", "true", "yes"})

    return {
        "rows": len(rows),
        "profiles": dict(profile_counts),
        "scenarios": dict(scenario_counts),
        "avg_total_energy_mj": sum(energy) / len(energy),
        "avg_latency_ms": sum(latency) / len(latency),
        "avg_tx_size_bytes": sum(tx_size) / len(tx_size),
        "downgrade_injected": dow_inj,
        "downgrade_detected": dow_det,
        "downgrade_detection_rate": (dow_det / dow_inj) if dow_inj else None,
        "invalid_tx_rejected": invalid_rej,
    }


def summarize_by_profile(csv_path: str | Path) -> Dict[str, Dict[str, float]]:
    path = Path(csv_path)
    groups = defaultdict(list)
    with path.open("r", newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            groups[r.get("profile_id", "")].append(r)

    out = {}
    for profile, rows in groups.items():
        if not rows:
            continue
        out[profile] = {
            "count": len(rows),
            "avg_total_energy_mj": sum(_to_float(r.get("total_energy_mj")) for r in rows) / len(rows),
            "avg_tx_size_bytes": sum(_to_float(r.get("tx_size_bytes")) for r in rows) / len(rows),
            "avg_crypto_energy_mj": sum(_to_float(r.get("crypto_energy_mj")) for r in rows) / len(rows),
        }
    return out
