from pathlib import Path
import pandas as pd
import numpy as np


MAIN_DIR = Path("D:/Utangle_code/analysis_outputs_without_irr")
IRR_DIR = Path("D:/Utangle_code/analysis_outputs_with_irr")
OUT = Path("D:/Utangle_code/paper_statistics_final")
OUT.mkdir(exist_ok=True)


def ci95(x):
    x = pd.to_numeric(x, errors="coerce").dropna()
    if len(x) <= 1:
        return 0.0
    return 1.96 * x.std(ddof=1) / np.sqrt(len(x))


def mean_ci_table(df, group_cols, metric_cols):
    rows = []
    for keys, g in df.groupby(group_cols, dropna=False):
        if not isinstance(keys, tuple):
            keys = (keys,)

        row = dict(zip(group_cols, keys))
        row["runs"] = g["run"].nunique() if "run" in g.columns else len(g)

        for m in metric_cols:
            if m in g.columns:
                vals = pd.to_numeric(g[m], errors="coerce")
                row[f"{m}_mean"] = vals.mean()
                row[f"{m}_std"] = vals.std(ddof=1)
                row[f"{m}_ci95"] = ci95(vals)

        rows.append(row)

    return pd.DataFrame(rows)


# ============================================================
# 1. Main campaign: EA profile metrics
# ============================================================

profile_by_run = pd.read_csv(MAIN_DIR / "ea_profile_summary_by_run.csv")

profile_metrics = mean_ci_table(
    profile_by_run,
    group_cols=["scenario", "nodes", "message_type", "profile_id", "checkpoint_rule"],
    metric_cols=[
        "events",
        "mean_tx_size_bytes",
        "mean_crypto_energy_mj",
        "mean_total_energy_mj",
        "mean_pdr",
        "mean_latency_ms",
    ],
)

profile_metrics.to_csv(OUT / "paper_table_ea_profile_metrics.csv", index=False)


# ============================================================
# 2. Main campaign: profile distribution
# ============================================================

dist = (
    profile_by_run
    .groupby(["scenario", "nodes", "run", "profile_id"], dropna=False)
    .agg(events=("events", "sum"))
    .reset_index()
)

dist_total = (
    dist
    .groupby(["scenario", "nodes", "run"], dropna=False)
    .agg(total_events=("events", "sum"))
    .reset_index()
)

dist = dist.merge(dist_total, on=["scenario", "nodes", "run"], how="left")
dist["profile_share"] = dist["events"] / dist["total_events"]

profile_distribution = mean_ci_table(
    dist,
    group_cols=["scenario", "nodes", "profile_id"],
    metric_cols=["events", "profile_share"],
)

profile_distribution.to_csv(OUT / "paper_table_profile_distribution.csv", index=False)


# ============================================================
# 3. Main campaign: packet-size feasibility
# ============================================================

packet = pd.read_csv(MAIN_DIR / "ea_packet_size_summary_by_run.csv")

packet_summary = mean_ci_table(
    packet,
    group_cols=["scenario", "nodes", "profile_id"],
    metric_cols=[
        "events",
        "max_tx_size_bytes",
        "mean_tx_size_bytes",
        "above_lmax_count",
    ],
)

packet_summary.to_csv(OUT / "paper_table_packet_size_feasibility.csv", index=False)


# ============================================================
# 4. Main campaign: phase-level EA vs Static
# ============================================================

phase_files = {
    "auth": "all_auth_global.csv",
    "data": "all_data_global.csv",
    "syn": "all_syn_global.csv",
}

phase_frames = []

for phase, fname in phase_files.items():
    f = MAIN_DIR / fname
    if not f.exists():
        continue

    df = pd.read_csv(f)
    df["phase"] = phase
    phase_frames.append(df)

phase_all = pd.concat(phase_frames, ignore_index=True)
phase_all.to_csv(OUT / "paper_phase_raw_small.csv", index=False)

# Detect useful numeric metrics automatically
ignore_cols = {"scheme", "scenario", "nodes", "run", "phase", "source_file"}
metric_cols = [
    c for c in phase_all.columns
    if c not in ignore_cols and pd.api.types.is_numeric_dtype(phase_all[c])
]

phase_summary = mean_ci_table(
    phase_all,
    group_cols=["scheme", "scenario", "nodes", "phase"],
    metric_cols=metric_cols,
)

phase_summary.to_csv(OUT / "paper_table_phase_summary.csv", index=False)


# ============================================================
# 5. Main campaign: paired EA vs Static by run
# ============================================================

# Use all numeric columns from global phase summaries.
# This creates EA - Static and percent difference per phase.
paired_rows = []

key_cols = ["scenario", "nodes", "run", "phase"]

for metric in metric_cols:
    temp = phase_all[key_cols + ["scheme", metric]].copy()

    pivot = temp.pivot_table(
        index=key_cols,
        columns="scheme",
        values=metric,
        aggfunc="mean",
    ).reset_index()

    if "EA_CryptoAgility" not in pivot.columns or "Static_UTangle" not in pivot.columns:
        continue

    pivot["metric"] = metric
    pivot["ea"] = pivot["EA_CryptoAgility"]
    pivot["static"] = pivot["Static_UTangle"]
    pivot["delta_abs"] = pivot["ea"] - pivot["static"]
    pivot["delta_pct"] = 100.0 * pivot["delta_abs"] / pivot["static"].replace(0, np.nan)

    paired_rows.append(
        pivot[key_cols + ["metric", "ea", "static", "delta_abs", "delta_pct"]]
    )

if paired_rows:
    paired = pd.concat(paired_rows, ignore_index=True)
    paired.to_csv(OUT / "paper_paired_ea_vs_static_by_run.csv", index=False)

    paired_summary = mean_ci_table(
        paired,
        group_cols=["scenario", "nodes", "phase", "metric"],
        metric_cols=["ea", "static", "delta_abs", "delta_pct"],
    )

    paired_summary.to_csv(OUT / "paper_table_paired_ea_vs_static.csv", index=False)


# ============================================================
# 6. Security campaign: DDR / IRR
# ============================================================

security_file = IRR_DIR / "ea_security_summary_by_run.csv"

if security_file.exists():
    sec = pd.read_csv(security_file)

    # ------------------------------------------------------------
    # Recompute DDR and IRR robustly at run level
    # ------------------------------------------------------------
    if {
        "sum_downgrade_injected",
        "sum_downgrade_detected",
    }.issubset(sec.columns):
        sec["DDR_final"] = (
            sec["sum_downgrade_detected"]
            / sec["sum_downgrade_injected"].replace(0, np.nan)
        )

    if {
        "sum_invalid_policy_meta",
        "sum_invalid_tx_rejected",
    }.issubset(sec.columns):
        sec["IRR_final"] = (
            sec["sum_invalid_tx_rejected"]
            / sec["sum_invalid_policy_meta"].replace(0, np.nan)
        )

    sec_metrics = [
        c for c in [
            "sum_downgrade_injected",
            "sum_downgrade_detected",
            "sum_invalid_policy_meta",
            "sum_invalid_tx_rejected",
            "DDR_final",
            "IRR_final",
        ]
        if c in sec.columns
    ]

    sec_summary = mean_ci_table(
        sec,
        group_cols=["scenario", "nodes"],
        metric_cols=sec_metrics,
    )

    sec_summary.to_csv(
        OUT / "paper_table_security_ddr_irr.csv",
        index=False,
    )

    # ------------------------------------------------------------
    # Also generate a clean IRR-only table for the paper
    # ------------------------------------------------------------
    irr_only_cols = [
        c for c in [
            "sum_invalid_policy_meta",
            "sum_invalid_tx_rejected",
            "IRR_final",
        ]
        if c in sec.columns
    ]

    irr_summary = mean_ci_table(
        sec,
        group_cols=["scenario", "nodes"],
        metric_cols=irr_only_cols,
    )

    irr_summary = irr_summary.rename(
        columns={
            "sum_invalid_policy_meta_mean": "policy_tamper_injected_mean",
            "sum_invalid_policy_meta_std": "policy_tamper_injected_std",
            "sum_invalid_policy_meta_ci95": "policy_tamper_injected_ci95",
            "sum_invalid_tx_rejected_mean": "policy_tamper_rejected_mean",
            "sum_invalid_tx_rejected_std": "policy_tamper_rejected_std",
            "sum_invalid_tx_rejected_ci95": "policy_tamper_rejected_ci95",
            "IRR_final_mean": "IRR_mean",
            "IRR_final_std": "IRR_std",
            "IRR_final_ci95": "IRR_ci95",
        }
    )

    irr_summary.to_csv(
        OUT / "paper_table_irr_summary.csv",
        index=False,
    )


print("Done.")
print(f"Final small paper tables saved in: {OUT.resolve()}")