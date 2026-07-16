from pathlib import Path
import json
import re
import pandas as pd
import numpy as np


# ROOT = Path("results")
# ROOT = Path("D:/Utangle_code/results_30runs_raspberry")
ROOT = Path("D:/Utangle_code/results_30runs_irr_raspbrry")
# OUT = Path("analysis_outputs")
# OUT = Path("D:/Utangle_code/analysis_outputs_without_irr")
OUT = Path("D:/Utangle_code/analysis_outputs_with_irr")
OUT.mkdir(exist_ok=True)

SCHEMES = {"EA_CryptoAgility", "Static_UTangle"}


def parse_result_path(path: Path):
    """
    Expected:
    results/<scheme>/<scenario>/nodes_<N>/run_<R>/<file>
    """
    parts = path.parts

    scheme = None
    scenario = None
    nodes = None
    run = None

    for i, p in enumerate(parts):
        if p in SCHEMES:
            scheme = p
            if i + 1 < len(parts):
                scenario = parts[i + 1]
            if i + 2 < len(parts):
                m = re.match(r"nodes_(\d+)", parts[i + 2])
                if m:
                    nodes = int(m.group(1))
            if i + 3 < len(parts):
                m = re.match(r"run_(\d+)", parts[i + 3])
                if m:
                    run = int(m.group(1))
            break

    return scheme, scenario, nodes, run


def read_csv_with_meta(path: Path):
    scheme, scenario, nodes, run = parse_result_path(path)
    try:
        df = pd.read_csv(path)
    except Exception as e:
        print(f"[WARN] could not read {path}: {e}")
        return None

    df.insert(0, "source_file", path.name)
    df.insert(0, "run", run)
    df.insert(0, "nodes", nodes)
    df.insert(0, "scenario", scenario)
    df.insert(0, "scheme", scheme)
    return df


def concat_pattern(pattern: str, out_name: str):
    files = sorted(ROOT.glob(pattern))
    frames = []

    for f in files:
        df = read_csv_with_meta(f)
        if df is not None and len(df) > 0:
            frames.append(df)

    if not frames:
        print(f"[INFO] no files for {pattern}")
        return pd.DataFrame()

    out = pd.concat(frames, ignore_index=True)
    out.to_csv(OUT / out_name, index=False)
    print(f"[OK] {out_name}: {len(out)} rows")
    return out


# 1) Raw unified files
ea_events = concat_pattern(
    "EA_CryptoAgility/*/nodes_*/run_*/ea_policy_events_*.csv",
    "all_ea_policy_events.csv"
)

transmissions = concat_pattern(
    "*/*/nodes_*/run_*/transmissions.csv",
    "all_transmissions.csv"
)

tangle_events = concat_pattern(
    "*/*/nodes_*/run_*/tangle_events_light.csv",
    "all_tangle_events.csv"
)

tangle_summary = concat_pattern(
    "*/*/nodes_*/run_*/tangle_summary_light*.csv",
    "all_tangle_summary.csv"
)

auth_global = concat_pattern(
    "*/*/nodes_*/run_*/*_auth_global.csv",
    "all_auth_global.csv"
)

data_global = concat_pattern(
    "*/*/nodes_*/run_*/*_data_global.csv",
    "all_data_global.csv"
)

syn_global = concat_pattern(
    "*/*/nodes_*/run_*/*_syn_global.csv",
    "all_syn_global.csv"
)


# 2) EA profile summary
if not ea_events.empty:
    numeric_cols = [
        c for c in [
            "tx_size_bytes",
            "policy_meta_bytes",
            "crypto_proof_bytes",
            "crypto_energy_mj",
            "tx_energy_mj",
            "rx_energy_mj",
            "retransmission_energy_mj",
            "total_energy_mj",
            "latency_ms",
            "pdr",
        ]
        if c in ea_events.columns
    ]

    profile_summary = (
        ea_events
        .groupby(["scenario", "nodes", "run", "message_type", "profile_id", "checkpoint_rule"], dropna=False)
        .agg(
            events=("profile_id", "size"),
            **{f"mean_{c}": (c, "mean") for c in numeric_cols},
            **{f"sum_{c}": (c, "sum") for c in numeric_cols if "energy" in c},
        )
        .reset_index()
    )

    profile_summary.to_csv(OUT / "ea_profile_summary_by_run.csv", index=False)
    print(f"[OK] ea_profile_summary_by_run.csv: {len(profile_summary)} rows")

    scenario_profile_summary = (
        ea_events
        .groupby(["scenario", "nodes", "message_type", "profile_id", "checkpoint_rule"], dropna=False)
        .agg(
            events=("profile_id", "size"),
            runs=("run", "nunique"),
            **{f"mean_{c}": (c, "mean") for c in numeric_cols},
            **{f"std_{c}": (c, "std") for c in numeric_cols},
        )
        .reset_index()
    )

    for c in numeric_cols:
        scenario_profile_summary[f"ci95_{c}"] = (
            1.96 * scenario_profile_summary[f"std_{c}"] /
            np.sqrt(scenario_profile_summary["runs"].clip(lower=1))
        )

    scenario_profile_summary.to_csv(OUT / "ea_profile_summary_mean_ci.csv", index=False)
    print(f"[OK] ea_profile_summary_mean_ci.csv: {len(scenario_profile_summary)} rows")


# 3) Packet-size feasibility summary
if not ea_events.empty and "tx_size_bytes" in ea_events.columns:
    def allowed_lmax(row):
        # Main paper assumption:
        # regular profiles <= 256 B; strict high-risk S3 <= 300 B
        if row.get("profile_id") == "S3":
            return 300
        return 256

    ea_events["allowed_lmax"] = ea_events.apply(allowed_lmax, axis=1)
    ea_events["above_lmax"] = ea_events["tx_size_bytes"] > ea_events["allowed_lmax"]

    packet_summary = (
        ea_events
        .groupby(["scenario", "nodes", "run", "profile_id"], dropna=False)
        .agg(
            events=("profile_id", "size"),
            max_tx_size_bytes=("tx_size_bytes", "max"),
            mean_tx_size_bytes=("tx_size_bytes", "mean"),
            above_lmax_count=("above_lmax", "sum"),
        )
        .reset_index()
    )

    packet_summary.to_csv(OUT / "ea_packet_size_summary_by_run.csv", index=False)
    print(f"[OK] ea_packet_size_summary_by_run.csv: {len(packet_summary)} rows")


# 4) Security summary
if not ea_events.empty:
    sec_cols = [
        c for c in [
            "downgrade_injected",
            "downgrade_detected",
            "invalid_policy_meta",
            "invalid_tx_rejected",
        ]
        if c in ea_events.columns
    ]

    if sec_cols:
        security = (
            ea_events
            .groupby(["scenario", "nodes", "run"], dropna=False)
            .agg(
                events=("profile_id", "size"),
                **{f"sum_{c}": (c, "sum") for c in sec_cols},
            )
            .reset_index()
        )

        if "sum_downgrade_detected" in security.columns and "sum_downgrade_injected" in security.columns:
            security["DDR"] = security["sum_downgrade_detected"] / security["sum_downgrade_injected"].replace(0, np.nan)

        if "sum_invalid_tx_rejected" in security.columns and "sum_invalid_policy_meta" in security.columns:
            security["IRR"] = security["sum_invalid_tx_rejected"] / security["sum_invalid_policy_meta"].replace(0, np.nan)

        security.to_csv(OUT / "ea_security_summary_by_run.csv", index=False)
        print(f"[OK] ea_security_summary_by_run.csv: {len(security)} rows")



if not ea_events.empty:
    ea_events["is_policy_tamper_injected"] = (
        ea_events.get("attack_label", "").astype(str) == "POLICY_TAMPERING"
    )

    ea_events["is_policy_tamper_rejected"] = (
        ea_events["is_policy_tamper_injected"]
        & ea_events.get("invalid_tx_rejected", False).astype(bool)
    )

    irr_summary = (
        ea_events
        .groupby(["scenario", "nodes", "run"], dropna=False)
        .agg(
            events=("profile_id", "size"),
            policy_tamper_injected=("is_policy_tamper_injected", "sum"),
            policy_tamper_rejected=("is_policy_tamper_rejected", "sum"),
            invalid_policy_meta=("invalid_policy_meta", "sum"),
            invalid_tx_rejected=("invalid_tx_rejected", "sum"),
        )
        .reset_index()
    )

    irr_summary["IRR"] = (
        irr_summary["policy_tamper_rejected"]
        / irr_summary["policy_tamper_injected"].replace(0, pd.NA)
    )

    irr_summary.to_csv(OUT / "ea_irr_summary_by_run.csv", index=False)

print("\nDone. Check analysis_outputs/")