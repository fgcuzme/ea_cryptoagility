from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


MAIN_DIR = Path("D:/Utangle_code/analysis_outputs_without_irr")
OUT_TABLES = Path("D:/Utangle_code/paper_statistics_final")
OUT_FIGS = Path("D:/Utangle_code/paper_figures")

OUT_TABLES.mkdir(exist_ok=True)
OUT_FIGS.mkdir(exist_ok=True)


def ci95(x):
    x = pd.to_numeric(x, errors="coerce").dropna()
    if len(x) <= 1:
        return 0.0
    return 1.96 * x.std(ddof=1) / np.sqrt(len(x))


def savefig(name):
    png = OUT_FIGS / f"{name}.png"
    pdf = OUT_FIGS / f"{name}.pdf"
    plt.tight_layout()
    plt.savefig(png, dpi=300, bbox_inches="tight")
    plt.savefig(pdf, bbox_inches="tight")
    print(f"[OK] {png}")
    print(f"[OK] {pdf}")
    plt.close()


# ============================================================
# 1. Load all_tangle_summary.csv
# ============================================================

f = MAIN_DIR / "all_tangle_summary.csv"

if not f.exists():
    raise FileNotFoundError(f"File not found: {f}")

dag = pd.read_csv(f)

required = {
    "scheme", "scenario", "nodes", "run",
    "op", "metric", "n",
    "mean_ms", "p50_ms", "p90_ms", "p95_ms", "p99_ms", "max_ms"
}

missing = required - set(dag.columns)
if missing:
    raise ValueError(f"Missing columns in all_tangle_summary.csv: {missing}")


# ============================================================
# 2. paper_table_dag_summary.csv
#    Summary by scheme/scenario/nodes/op/metric
# ============================================================

rows = []

group_cols = ["scheme", "scenario", "nodes", "op", "metric"]

for keys, g in dag.groupby(group_cols, dropna=False):
    row = dict(zip(group_cols, keys))
    row["runs"] = g["run"].nunique()
    row["events_mean"] = g["n"].mean()
    row["events_ci95"] = ci95(g["n"])

    for m in ["mean_ms", "p50_ms", "p90_ms", "p95_ms", "p99_ms", "max_ms"]:
        row[f"{m}_mean"] = g[m].mean()
        row[f"{m}_std"] = g[m].std(ddof=1)
        row[f"{m}_ci95"] = ci95(g[m])

    rows.append(row)

dag_summary = pd.DataFrame(rows)

dag_summary.to_csv(
    OUT_TABLES / "paper_table_dag_summary.csv",
    index=False
)

print(f"[OK] {OUT_TABLES / 'paper_table_dag_summary.csv'}")


# ============================================================
# 3. Paired EA vs Static DAG overhead by run
# ============================================================

paired_rows = []

key_cols = ["scenario", "nodes", "run", "op", "metric"]

for stat in ["mean_ms", "p50_ms", "p90_ms", "p95_ms", "p99_ms", "max_ms"]:

    temp = dag[key_cols + ["scheme", stat]].copy()

    pivot = temp.pivot_table(
        index=key_cols,
        columns="scheme",
        values=stat,
        aggfunc="mean"
    ).reset_index()

    if "EA_CryptoAgility" not in pivot.columns:
        continue
    if "Static_UTangle" not in pivot.columns:
        continue

    pivot["stat"] = stat
    pivot["ea"] = pivot["EA_CryptoAgility"]
    pivot["static"] = pivot["Static_UTangle"]
    pivot["delta_abs_ms"] = pivot["ea"] - pivot["static"]
    pivot["delta_pct"] = (
        100.0 * pivot["delta_abs_ms"] /
        pivot["static"].replace(0, np.nan)
    )

    paired_rows.append(
        pivot[
            key_cols + [
                "stat",
                "ea",
                "static",
                "delta_abs_ms",
                "delta_pct"
            ]
        ]
    )

if not paired_rows:
    raise RuntimeError("No paired EA vs Static DAG rows were generated.")

dag_paired_by_run = pd.concat(paired_rows, ignore_index=True)

dag_paired_by_run.to_csv(
    OUT_TABLES / "paper_dag_paired_by_run.csv",
    index=False
)

print(f"[OK] {OUT_TABLES / 'paper_dag_paired_by_run.csv'}")


# ============================================================
# 4. paper_table_dag_paired_overhead.csv
# ============================================================

rows = []

group_cols = ["scenario", "nodes", "op", "metric", "stat"]

for keys, g in dag_paired_by_run.groupby(group_cols, dropna=False):
    row = dict(zip(group_cols, keys))
    row["runs"] = g["run"].nunique()

    for m in ["ea", "static", "delta_abs_ms", "delta_pct"]:
        row[f"{m}_mean"] = g[m].mean()
        row[f"{m}_std"] = g[m].std(ddof=1)
        row[f"{m}_ci95"] = ci95(g[m])

    rows.append(row)

dag_paired_summary = pd.DataFrame(rows)

dag_paired_summary.to_csv(
    OUT_TABLES / "paper_table_dag_paired_overhead.csv",
    index=False
)

print(f"[OK] {OUT_TABLES / 'paper_table_dag_paired_overhead.csv'}")


# ============================================================
# 5. Figure: DAG confirmation-check overhead
# ============================================================

confirm = dag_paired_summary[
    (dag_paired_summary["op"] == "confirm_check") &
    (dag_paired_summary["metric"] == "t_confirm_ms") &
    (dag_paired_summary["stat"] == "p95_ms")
].copy()

if confirm.empty:
    print("[WARN] No confirm_check/t_confirm_ms rows found. Figure not generated.")
else:
    scenario_order = [
        "SC1_NORMAL",
        "SC2_LOW_ENERGY",
        "SC3_DEGRADED_CHANNEL",
        "SC4_HIGH_RISK",
        "SC5_DAG_CONGESTION",
    ]

    scenario_labels = {
        "SC1_NORMAL": "SC1 Normal",
        "SC2_LOW_ENERGY": "SC2 Low energy",
        "SC3_DEGRADED_CHANNEL": "SC3 Degraded",
        "SC4_HIGH_RISK": "SC4 High risk",
        "SC5_DAG_CONGESTION": "SC5 DAG congestion",
    }

    plt.figure(figsize=(8.2, 4.8))

    for sc in scenario_order:
        g = confirm[confirm["scenario"] == sc].sort_values("nodes")
        if g.empty:
            continue

        plt.errorbar(
            g["nodes"],
            g["delta_pct_mean"],
            yerr=g["delta_pct_ci95"],
            marker="o",
            linewidth=2,
            capsize=4,
            label=scenario_labels.get(sc, sc),
        )

    plt.axhline(0, linestyle="--", linewidth=1.2)
    plt.xlabel("Number of nodes")
    plt.ylabel("P95 confirmation-check difference [%]")
    plt.title("DAG confirmation-check overhead vs. network size")
    plt.grid(True, alpha=0.35)
    plt.legend(ncol=2, fontsize=8)
    savefig("fig9_dag_confirmation_overhead")


# ============================================================
# 6. Optional Figure: DAG processing cost at N = 200
# ============================================================

target_nodes = 200

processing = dag_summary[
    (dag_summary["nodes"] == target_nodes) &
    (
        (
            (dag_summary["op"] == "create_tx") &
            (dag_summary["metric"] == "t_total")
        ) |
        (
            (dag_summary["op"] == "verify_tx") &
            (dag_summary["metric"] == "t_total")
        ) |
        (
            (dag_summary["op"] == "confirm_check") &
            (dag_summary["metric"] == "t_confirm_ms")
        )
    )
].copy()

if processing.empty:
    print(f"[WARN] No DAG processing rows found for N={target_nodes}. Optional figure not generated.")
else:
    processing["operation_label"] = processing["op"] + "/" + processing["metric"]

    # Use scenario SC1, SC4, SC5 to avoid overcrowding.
    selected_scenarios = ["SC1_NORMAL", "SC4_HIGH_RISK", "SC5_DAG_CONGESTION"]

    processing = processing[
        processing["scenario"].isin(selected_scenarios)
    ].copy()

    if not processing.empty:
        labels = {
            "SC1_NORMAL": "SC1",
            "SC4_HIGH_RISK": "SC4",
            "SC5_DAG_CONGESTION": "SC5",
        }

        processing["x_label"] = (
            processing["scenario"].map(labels)
            + "\n"
            + processing["operation_label"]
        )

        # Keep fixed order
        order = []
        for sc in selected_scenarios:
            for opm in [
                "create_tx/t_total",
                "verify_tx/t_total",
                "confirm_check/t_confirm_ms",
            ]:
                order.append((sc, opm))

        processing["order"] = processing.apply(
            lambda r: order.index((r["scenario"], r["operation_label"]))
            if (r["scenario"], r["operation_label"]) in order else 999,
            axis=1
        )

        processing = processing.sort_values(["order", "scheme"])

        x_labels = []
        ea_vals = []
        ea_errs = []
        st_vals = []
        st_errs = []

        for sc, opm in order:
            g = processing[
                (processing["scenario"] == sc) &
                (processing["operation_label"] == opm)
            ]

            if g.empty:
                continue

            # x_labels.append(labels.get(sc, sc) + "\n" + opm)
            short_op = {
                "create_tx/t_total": "create",
                "verify_tx/t_total": "verify",
                "confirm_check/t_confirm_ms": "confirm",
            }

            x_labels.append(labels.get(sc, sc) + "-" + short_op.get(opm, opm))

            ea = g[g["scheme"] == "EA_CryptoAgility"]
            st = g[g["scheme"] == "Static_UTangle"]

            ea_vals.append(float(ea["p95_ms_mean"].iloc[0]) if not ea.empty else np.nan)
            ea_errs.append(float(ea["p95_ms_ci95"].iloc[0]) if not ea.empty else 0.0)

            st_vals.append(float(st["p95_ms_mean"].iloc[0]) if not st.empty else np.nan)
            st_errs.append(float(st["p95_ms_ci95"].iloc[0]) if not st.empty else 0.0)

        x = np.arange(len(x_labels))
        width = 0.38

        plt.figure(figsize=(10.5, 4.8))
        plt.bar(
            x - width / 2,
            st_vals,
            width,
            yerr=st_errs,
            capsize=3,
            label="Static U-Tangle"
        )
        plt.bar(
            x + width / 2,
            ea_vals,
            width,
            yerr=ea_errs,
            capsize=3,
            label="EA-CryptoAgility"
        )

        plt.ylabel("P95 processing time [ms]")
        plt.xlabel("Scenario / DAG operation")
        plt.title(f"DAG processing cost at N={target_nodes}")
        plt.xticks(x, x_labels, rotation=30, ha="right")
        plt.grid(True, axis="y", alpha=0.35)
        plt.legend()
        savefig("fig10_dag_processing_cost_N200")


print("\nDAG statistics and figures generated successfully.")