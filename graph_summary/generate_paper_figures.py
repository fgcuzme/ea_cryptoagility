
"""
generate_paper_figures.py

Genera las figuras principales del paper EA-CryptoAgility U-Tangle
a partir de las tablas pequeñas creadas por make_paper_statistics.py.

Entrada esperada:
    paper_statistics_final/
        paper_table_profile_distribution.csv
        paper_table_ea_profile_metrics.csv
        paper_table_packet_size_feasibility.csv
        paper_table_paired_ea_vs_static.csv
        paper_phase_raw_small.csv
        paper_table_security_ddr_irr.csv

Uso:
    python generate_paper_figures.py
    python generate_paper_figures.py --input paper_statistics_final --output paper_figures

Salidas:
    paper_figures/*.png
    paper_figures/*.pdf
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, Optional

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


SCENARIO_ORDER = [
    "SC1_NORMAL",
    "SC2_LOW_ENERGY",
    "SC3_DEGRADED_CHANNEL",
    "SC4_HIGH_RISK",
    "SC5_DAG_CONGESTION",
]

SCENARIO_LABELS = {
    "SC1_NORMAL": "SC1\nNormal",
    "SC2_LOW_ENERGY": "SC2\nLow energy",
    "SC3_DEGRADED_CHANNEL": "SC3\nDegraded",
    "SC4_HIGH_RISK": "SC4\nHigh risk",
    "SC5_DAG_CONGESTION": "SC5\nDAG congest.",
}

PROFILE_ORDER = ["S0", "S1", "S2", "S3", "S4"]
NODE_ORDER = [20, 50, 100, 200]


def read_csv(input_dir: Path, filename: str) -> pd.DataFrame:
    path = input_dir / filename
    if not path.exists():
        raise FileNotFoundError(f"No existe el archivo requerido: {path}")
    return pd.read_csv(path)


def save_figure(fig: plt.Figure, output_dir: Path, basename: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    png = output_dir / f"{basename}.png"
    pdf = output_dir / f"{basename}.pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    print(f"[OK] {png}")
    print(f"[OK] {pdf}")


def set_common_style() -> None:
    # No se fijan colores específicos para mantener compatibilidad con estilos IEEE/matplotlib.
    plt.rcParams.update({
        "figure.dpi": 120,
        "savefig.dpi": 300,
        "font.size": 10,
        "axes.titlesize": 11,
        "axes.labelsize": 10,
        "legend.fontsize": 8,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "axes.grid": True,
        "grid.alpha": 0.30,
    })


def scenario_sort_key(s: str) -> int:
    try:
        return SCENARIO_ORDER.index(s)
    except ValueError:
        return len(SCENARIO_ORDER)


def get_scenario_label(s: str) -> str:
    return SCENARIO_LABELS.get(s, s.replace("_", "\n"))


def ci_or_zero(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series, errors="coerce").fillna(0.0)


# ============================================================
# Fig. 2: Profile distribution per scenario and network size
# ============================================================

def plot_profile_distribution(input_dir: Path, output_dir: Path) -> None:
    df = read_csv(input_dir, "paper_table_profile_distribution.csv")

    df["profile_share_mean"] = pd.to_numeric(df["profile_share_mean"], errors="coerce").fillna(0.0)
    df["nodes"] = pd.to_numeric(df["nodes"], errors="coerce").astype(int)

    nodes = [n for n in NODE_ORDER if n in set(df["nodes"])]
    scenarios = [s for s in SCENARIO_ORDER if s in set(df["scenario"])]

    fig, axes = plt.subplots(
        nrows=len(nodes),
        ncols=1,
        figsize=(7.2, 2.1 * len(nodes)),
        sharex=True,
    )

    if len(nodes) == 1:
        axes = [axes]

    x = np.arange(len(scenarios))

    for ax, n in zip(axes, nodes):
        sub = df[df["nodes"] == n]
        bottom = np.zeros(len(scenarios))

        for profile in PROFILE_ORDER:
            vals = []
            for sc in scenarios:
                row = sub[(sub["scenario"] == sc) & (sub["profile_id"] == profile)]
                vals.append(float(row["profile_share_mean"].iloc[0]) if len(row) else 0.0)

            ax.bar(x, vals, bottom=bottom, label=profile)
            bottom += np.asarray(vals)

        ax.set_ylim(0, 1.05)
        ax.set_ylabel(f"N={n}\nShare")
        ax.set_yticks([0, 0.5, 1.0])

    axes[-1].set_xticks(x)
    axes[-1].set_xticklabels([get_scenario_label(s) for s in scenarios])
    axes[0].legend(
        title="Profile",
        ncol=len(PROFILE_ORDER),
        loc="upper center",
        bbox_to_anchor=(0.5, 1.35),
        frameon=True,
    )

    fig.suptitle("Cryptographic profile distribution per scenario and network size", y=0.995)
    fig.tight_layout()
    save_figure(fig, output_dir, "fig2_profile_distribution")
    plt.close(fig)


# ============================================================
# Fig. 3: Energy overhead/scalability EA vs Static
# ============================================================

def compute_total_energy_overhead_from_phase_raw(input_dir: Path) -> pd.DataFrame:
    raw = read_csv(input_dir, "paper_phase_raw_small.csv")

    required = {"scheme", "scenario", "nodes", "run", "phase", "total_energy_j"}
    missing = required - set(raw.columns)
    if missing:
        raise ValueError(f"paper_phase_raw_small.csv no tiene columnas requeridas: {missing}")

    raw["nodes"] = pd.to_numeric(raw["nodes"], errors="coerce").astype(int)
    raw["run"] = pd.to_numeric(raw["run"], errors="coerce").astype(int)
    raw["total_energy_j"] = pd.to_numeric(raw["total_energy_j"], errors="coerce")

    # Energía total por run = suma de fases auth + data + syn.
    total = (
        raw.groupby(["scheme", "scenario", "nodes", "run"], dropna=False)
        .agg(total_energy_j=("total_energy_j", "sum"))
        .reset_index()
    )

    pivot = total.pivot_table(
        index=["scenario", "nodes", "run"],
        columns="scheme",
        values="total_energy_j",
        aggfunc="mean",
    ).reset_index()

    if "EA_CryptoAgility" not in pivot.columns or "Static_UTangle" not in pivot.columns:
        raise ValueError("No se encontraron ambos esquemas: EA_CryptoAgility y Static_UTangle")

    pivot["delta_pct"] = (
        100.0
        * (pivot["EA_CryptoAgility"] - pivot["Static_UTangle"])
        / pivot["Static_UTangle"].replace(0, np.nan)
    )

    summary = (
        pivot.groupby(["scenario", "nodes"], dropna=False)
        .agg(
            delta_pct_mean=("delta_pct", "mean"),
            delta_pct_std=("delta_pct", "std"),
            runs=("run", "nunique"),
            ea_energy_j_mean=("EA_CryptoAgility", "mean"),
            static_energy_j_mean=("Static_UTangle", "mean"),
        )
        .reset_index()
    )

    summary["delta_pct_ci95"] = 1.96 * summary["delta_pct_std"] / np.sqrt(summary["runs"])
    return summary


def plot_energy_overhead(input_dir: Path, output_dir: Path) -> None:
    df = compute_total_energy_overhead_from_phase_raw(input_dir)

    fig, ax = plt.subplots(figsize=(7.2, 4.2))

    for scenario in SCENARIO_ORDER:
        sub = df[df["scenario"] == scenario].sort_values("nodes")
        if sub.empty:
            continue

        ax.errorbar(
            sub["nodes"],
            sub["delta_pct_mean"],
            yerr=ci_or_zero(sub["delta_pct_ci95"]),
            marker="o",
            capsize=3,
            linewidth=1.6,
            label=scenario.replace("SC", "SC ").replace("_", " "),
        )

    ax.axhline(0, linestyle="--", linewidth=1)
    ax.set_xlabel("Number of nodes")
    ax.set_ylabel("Energy difference w.r.t. Static U-Tangle [%]")
    ax.set_title("Energy overhead vs. network size")
    ax.set_xticks(NODE_ORDER)
    ax.legend(ncol=2, frameon=True)
    fig.tight_layout()
    save_figure(fig, output_dir, "fig3_energy_overhead_scalability")
    plt.close(fig)


# ============================================================
# Fig. 4: Latency overhead vs network size
# ============================================================

def compute_latency_overhead(input_dir: Path, phase: str = "data") -> pd.DataFrame:
    paired = read_csv(input_dir, "paper_table_paired_ea_vs_static.csv")

    required = {"scenario", "nodes", "phase", "metric", "delta_pct_mean", "delta_pct_ci95"}
    missing = required - set(paired.columns)
    if missing:
        raise ValueError(f"paper_table_paired_ea_vs_static.csv no tiene columnas requeridas: {missing}")

    sub = paired[
        (paired["phase"] == phase)
        & (paired["metric"] == "avg_latency_ms")
    ].copy()

    sub["nodes"] = pd.to_numeric(sub["nodes"], errors="coerce").astype(int)
    sub["delta_pct_mean"] = pd.to_numeric(sub["delta_pct_mean"], errors="coerce")
    sub["delta_pct_ci95"] = pd.to_numeric(sub["delta_pct_ci95"], errors="coerce").fillna(0.0)

    return sub


def plot_latency_overhead(input_dir: Path, output_dir: Path, phase: str = "data") -> None:
    df = compute_latency_overhead(input_dir, phase=phase)

    fig, ax = plt.subplots(figsize=(7.2, 4.2))

    for scenario in SCENARIO_ORDER:
        sub = df[df["scenario"] == scenario].sort_values("nodes")
        if sub.empty:
            continue

        ax.errorbar(
            sub["nodes"],
            sub["delta_pct_mean"],
            yerr=ci_or_zero(sub["delta_pct_ci95"]),
            marker="o",
            capsize=3,
            linewidth=1.6,
            label=scenario.replace("SC", "SC ").replace("_", " "),
        )

    ax.axhline(0, linestyle="--", linewidth=1)
    ax.set_xlabel("Number of nodes")
    ax.set_ylabel("Latency difference relative to Static U-Tangle [%]")
    ax.set_title(f"EA-CryptoAgility latency overhead ({phase} phase)")
    ax.set_xticks(NODE_ORDER)
    ax.legend(ncol=2, frameon=True)
    fig.tight_layout()
    save_figure(fig, output_dir, f"fig4_latency_overhead_{phase}")
    plt.close(fig)


# ============================================================
# Fig. 5: Packet-size feasibility by profile
# ============================================================

def plot_packet_size_feasibility(input_dir: Path, output_dir: Path) -> None:
    df = read_csv(input_dir, "paper_table_packet_size_feasibility.csv")

    df["max_tx_size_bytes_mean"] = pd.to_numeric(df["max_tx_size_bytes_mean"], errors="coerce")
    df["max_tx_size_bytes_ci95"] = pd.to_numeric(df["max_tx_size_bytes_ci95"], errors="coerce").fillna(0.0)

    # Usar el máximo observado por perfil en toda la campaña.
    rows = []
    for profile in PROFILE_ORDER:
        sub = df[df["profile_id"] == profile]
        if sub.empty:
            continue

        idx = sub["max_tx_size_bytes_mean"].idxmax()
        r = sub.loc[idx].copy()
        rows.append(r)

    summary = pd.DataFrame(rows)
    summary["profile_id"] = pd.Categorical(summary["profile_id"], categories=PROFILE_ORDER, ordered=True)
    summary = summary.sort_values("profile_id")

    x = np.arange(len(summary))

    fig, ax = plt.subplots(figsize=(6.8, 4.0))
    ax.bar(
        x,
        summary["max_tx_size_bytes_mean"],
        yerr=ci_or_zero(summary["max_tx_size_bytes_ci95"]),
        capsize=3,
    )

    ax.axhline(256, linestyle="--", linewidth=1, label="Regular Lmax = 256 B")
    ax.axhline(300, linestyle=":", linewidth=1.5, label="S3 high-risk Lmax = 300 B")

    ax.set_xticks(x)
    ax.set_xticklabels(summary["profile_id"])
    ax.set_ylabel("Maximum observed packet size [bytes]")
    ax.set_xlabel("EA-CryptoAgility profile")
    ax.set_title("Packet-size feasibility by cryptographic profile")
    ax.set_ylim(0, max(320, float(summary["max_tx_size_bytes_mean"].max()) * 1.15))
    ax.legend(frameon=True)

    fig.tight_layout()
    save_figure(fig, output_dir, "fig5_packet_size_feasibility")
    plt.close(fig)


# ============================================================
# Fig. 6: Profile-level crypto/total energy
# ============================================================

def plot_profile_energy_cost(input_dir: Path, output_dir: Path, nodes: int = 200) -> None:
    df = read_csv(input_dir, "paper_table_ea_profile_metrics.csv")
    df["nodes"] = pd.to_numeric(df["nodes"], errors="coerce").astype(int)

    required_cols = {
        "scenario",
        "nodes",
        "message_type",
        "profile_id",
        "checkpoint_rule",
        "mean_crypto_energy_mj_mean",
        "mean_total_energy_mj_mean",
    }
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"paper_table_ea_profile_metrics.csv no tiene columnas requeridas: {missing}")

    # Filas representativas para no saturar la figura.
    selectors = [
        ("SC1_NORMAL", "TELEMETRY", "S1"),
        ("SC2_LOW_ENERGY", "TELEMETRY", "S2"),
        ("SC3_DEGRADED_CHANNEL", "TELEMETRY", "S2"),
        ("SC3_DEGRADED_CHANNEL", "EMERGENCY_ALARM", "S4"),
        ("SC4_HIGH_RISK", "TELEMETRY", "S3"),
        ("SC5_DAG_CONGESTION", "TELEMETRY", "S1"),
    ]

    rows = []
    for scenario, msg, profile in selectors:
        sub = df[
            (df["nodes"] == nodes)
            & (df["scenario"] == scenario)
            & (df["message_type"] == msg)
            & (df["profile_id"] == profile)
        ]
        if not sub.empty:
            rows.append(sub.iloc[0])

    if not rows:
        raise ValueError(f"No hay filas representativas para nodes={nodes}")

    rep = pd.DataFrame(rows)
    labels = [
        f"{r['scenario'].replace('SC', 'SC ').replace('_', ' ')}\n{r['message_type']}/{r['profile_id']}"
        for _, r in rep.iterrows()
    ]

    x = np.arange(len(rep))
    width = 0.38

    fig, ax = plt.subplots(figsize=(8.0, 4.3))
    ax.bar(
        x - width / 2,
        rep["mean_crypto_energy_mj_mean"],
        width,
        yerr=ci_or_zero(rep.get("mean_crypto_energy_mj_ci95", pd.Series([0] * len(rep)))),
        capsize=3,
        label="Crypto energy",
    )
    ax.bar(
        x + width / 2,
        rep["mean_total_energy_mj_mean"],
        width,
        yerr=ci_or_zero(rep.get("mean_total_energy_mj_ci95", pd.Series([0] * len(rep)))),
        capsize=3,
        label="Total energy",
    )

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.set_ylabel("Energy per transaction [mJ]")
    ax.set_title(f"Profile-level cryptographic and total energy cost (N={nodes})")
    ax.legend(frameon=True)
    fig.tight_layout()
    save_figure(fig, output_dir, f"fig6_profile_energy_cost_N{nodes}")
    plt.close(fig)


# ============================================================
# Fig. 7: PDR / packet-loss behavior
# ============================================================

def plot_data_phase_pdr(input_dir: Path, output_dir: Path) -> None:
    phase = read_csv(input_dir, "paper_table_phase_summary.csv")

    required = {"scheme", "scenario", "nodes", "phase", "packet_loss_percent_mean", "packet_loss_percent_ci95"}
    missing = required - set(phase.columns)
    if missing:
        raise ValueError(f"paper_table_phase_summary.csv no tiene columnas requeridas: {missing}")

    data = phase[phase["phase"] == "data"].copy()
    data["nodes"] = pd.to_numeric(data["nodes"], errors="coerce").astype(int)
    data["pdr_mean"] = 1.0 - pd.to_numeric(data["packet_loss_percent_mean"], errors="coerce") / 100.0
    data["pdr_ci95"] = pd.to_numeric(data["packet_loss_percent_ci95"], errors="coerce").fillna(0.0) / 100.0

    # Para no saturar, mostrar el escenario degradado y el high-risk.
    scenarios_to_plot = ["SC3_DEGRADED_CHANNEL", "SC4_HIGH_RISK"]

    fig, axes = plt.subplots(1, len(scenarios_to_plot), figsize=(7.8, 3.6), sharey=True)
    if len(scenarios_to_plot) == 1:
        axes = [axes]

    width = 0.36

    for ax, scenario in zip(axes, scenarios_to_plot):
        sub = data[data["scenario"] == scenario]
        nodes = [n for n in NODE_ORDER if n in set(sub["nodes"])]
        x = np.arange(len(nodes))

        for j, scheme in enumerate(["Static_UTangle", "EA_CryptoAgility"]):
            vals = []
            errs = []
            for n in nodes:
                row = sub[(sub["nodes"] == n) & (sub["scheme"] == scheme)]
                vals.append(float(row["pdr_mean"].iloc[0]) if len(row) else np.nan)
                errs.append(float(row["pdr_ci95"].iloc[0]) if len(row) else 0.0)

            offset = -width / 2 if j == 0 else width / 2
            ax.bar(x + offset, vals, width, yerr=errs, capsize=3, label=scheme)

        ax.set_title(get_scenario_label(scenario).replace("\n", " "))
        ax.set_xticks(x)
        ax.set_xticklabels(nodes)
        ax.set_xlabel("Nodes")
        ax.set_ylim(0, 1.05)
        ax.grid(True, axis="y", alpha=0.3)

    axes[0].set_ylabel("Data-phase PDR")
    axes[0].legend(frameon=True)
    fig.suptitle("Packet delivery ratio under degraded and high-risk scenarios", y=1.02)
    fig.tight_layout()
    save_figure(fig, output_dir, "fig7_data_phase_pdr")
    plt.close(fig)


# ============================================================
# Fig. 8: DDR and IRR
# ============================================================

def plot_security_ddr_irr(input_dir: Path, output_dir: Path) -> None:
    df = read_csv(input_dir, "paper_table_security_ddr_irr.csv")

    required = {"nodes", "DDR_final_mean", "DDR_final_ci95", "IRR_final_mean", "IRR_final_ci95"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"paper_table_security_ddr_irr.csv no tiene columnas requeridas: {missing}")

    df["nodes"] = pd.to_numeric(df["nodes"], errors="coerce").astype(int)
    df = df.sort_values("nodes")

    x = np.arange(len(df))
    width = 0.36

    fig, ax = plt.subplots(figsize=(6.6, 3.8))

    ax.bar(
        x - width / 2,
        df["DDR_final_mean"],
        width,
        yerr=ci_or_zero(df["DDR_final_ci95"]),
        capsize=3,
        label="DDR",
    )
    ax.bar(
        x + width / 2,
        df["IRR_final_mean"],
        width,
        yerr=ci_or_zero(df["IRR_final_ci95"]),
        capsize=3,
        label="IRR",
    )

    ax.set_xticks(x)
    ax.set_xticklabels(df["nodes"])
    ax.set_xlabel("Number of nodes")
    ax.set_ylabel("Detection / rejection ratio")
    ax.set_ylim(0, 1.08)
    ax.set_title("Downgrade detection and invalid policy-metadata rejection")
    ax.legend(frameon=True)

    fig.tight_layout()
    save_figure(fig, output_dir, "fig8_security_ddr_irr")
    plt.close(fig)


# ============================================================
# Optional: DAG behavior if all_tangle_summary is available
# ============================================================

def plot_optional_dag_behavior(input_dir: Path, output_dir: Path) -> None:
    """
    Esta figura es opcional. Solo se ejecuta si existe paper_table_dag_summary.csv.
    Si después generas una tabla pequeña de DAG, debe contener al menos:
        scheme, scenario, nodes, metric_name, metric_mean, metric_ci95
    """
    path = input_dir / "paper_table_dag_summary.csv"
    if not path.exists():
        print("[INFO] No se generó figura DAG porque no existe paper_table_dag_summary.csv")
        return

    df = pd.read_csv(path)
    required = {"scheme", "scenario", "nodes", "metric_name", "metric_mean", "metric_ci95"}
    missing = required - set(df.columns)
    if missing:
        print(f"[WARN] paper_table_dag_summary.csv no tiene columnas requeridas: {missing}")
        return

    # Intenta graficar confirmation_delay_ms si existe.
    metric_candidates = ["confirmation_delay_ms", "t_confirm_ms", "avg_confirmation_delay_ms"]
    metric = None
    for m in metric_candidates:
        if m in set(df["metric_name"].astype(str)):
            metric = m
            break

    if metric is None:
        print("[INFO] No se encontró métrica DAG compatible para graficar.")
        return

    sub = df[
        (df["metric_name"] == metric)
        & (df["scenario"].isin(["SC1_NORMAL", "SC4_HIGH_RISK", "SC5_DAG_CONGESTION"]))
    ].copy()

    if sub.empty:
        print("[INFO] No hay filas DAG para SC1/SC4/SC5.")
        return

    scenarios = ["SC1_NORMAL", "SC4_HIGH_RISK", "SC5_DAG_CONGESTION"]
    fig, axes = plt.subplots(1, len(scenarios), figsize=(8.0, 3.6), sharey=True)
    width = 0.36

    for ax, scenario in zip(axes, scenarios):
        s = sub[sub["scenario"] == scenario]
        nodes = [n for n in NODE_ORDER if n in set(s["nodes"])]
        x = np.arange(len(nodes))

        for j, scheme in enumerate(["Static_UTangle", "EA_CryptoAgility"]):
            vals, errs = [], []
            for n in nodes:
                row = s[(s["nodes"] == n) & (s["scheme"] == scheme)]
                vals.append(float(row["metric_mean"].iloc[0]) if len(row) else np.nan)
                errs.append(float(row["metric_ci95"].iloc[0]) if len(row) else 0.0)
            offset = -width / 2 if j == 0 else width / 2
            ax.bar(x + offset, vals, width, yerr=errs, capsize=3, label=scheme)

        ax.set_title(get_scenario_label(scenario).replace("\n", " "))
        ax.set_xticks(x)
        ax.set_xticklabels(nodes)
        ax.set_xlabel("Nodes")

    axes[0].set_ylabel(metric.replace("_", " "))
    axes[0].legend(frameon=True)
    fig.suptitle("DAG confirmation behavior", y=1.02)
    fig.tight_layout()
    save_figure(fig, output_dir, "fig_optional_dag_behavior")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="paper_statistics_final",
        help="Carpeta con las tablas pequeñas del paper.",
    )
    parser.add_argument(
        "--output",
        default="paper_figures",
        help="Carpeta de salida para figuras PNG/PDF.",
    )
    parser.add_argument(
        "--profile-energy-nodes",
        type=int,
        default=200,
        help="Número de nodos usado en la figura de coste por perfil.",
    )

    args = parser.parse_args()
    input_dir = Path(args.input)
    output_dir = Path(args.output)

    if not input_dir.exists():
        raise FileNotFoundError(f"No existe la carpeta de entrada: {input_dir}")

    set_common_style()

    plot_profile_distribution(input_dir, output_dir)
    plot_energy_overhead(input_dir, output_dir)
    plot_latency_overhead(input_dir, output_dir, phase="data")
    plot_packet_size_feasibility(input_dir, output_dir)
    plot_profile_energy_cost(input_dir, output_dir, nodes=args.profile_energy_nodes)
    plot_data_phase_pdr(input_dir, output_dir)
    plot_security_ddr_irr(input_dir, output_dir)
    plot_optional_dag_behavior(input_dir, output_dir)

    print("\nFiguras generadas correctamente.")
    print(f"Carpeta de salida: {output_dir.resolve()}")


if __name__ == "__main__":
    main()