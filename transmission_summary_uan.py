# 📁 transmission_summary.py — resumen sobre CSV canónico
import os, csv
import pandas as pd
from collections import defaultdict

# # PHASE = "syn"
# PHASE = "auth"
# # PHASE = "data"

CANON_CSV = os.environ.get("UWSN_EVENTS_CSV", "stats/transmissions.csv")


PHASES = ["syn", "auth", "data"]

# helper
def _load_phase_energy(snapshot_csv, run_id, phase,):
    snap = pd.read_csv(
        snapshot_csv
    )

    snap["phase"] = (
        snap["phase"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    p = snap[
        (snap["run_id"].astype(str) == str(run_id))
        & (snap["phase"] == phase.lower())
    ].copy()

    start = (
        p[p["boundary"] == "start"][
            [
                "node_id",
                "role",
                "cluster_id",
                "cluster_head",
                "residual_energy_j",
            ]
        ]
        .rename(
            columns={
                "residual_energy_j":
                    "residual_start_j"
            }
        )
    )

    end = (
        p[p["boundary"] == "end"][
            [
                "node_id",
                "residual_energy_j",
            ]
        ]
        .rename(
            columns={
                "residual_energy_j":
                    "residual_end_j"
            }
        )
    )

    energy = start.merge(
        end,
        on="node_id",
        how="inner",
        validate="one_to_one",
    )

    energy["energy_total_j"] = (
        energy["residual_start_j"]
        - energy["residual_end_j"]
    ).clip(lower=0.0)

    return energy
###

# def summarize_per_node_by_run(input_csv=CANON_CSV, output_dir=None, phase=None):
def summarize_per_node_by_run(input_csv=CANON_CSV, output_dir=None, phase=None, snapshot_csv=None,):
    if not os.path.exists(input_csv):
        print(f"🚨 Archivo no encontrado: {input_csv}")
        return
    df = pd.read_csv(input_csv)
    # df = df[df["phase"].astype(str).str.contains(phase)]
    
    df["phase"] = (df["phase"].astype(str).str.strip().str.lower())

    df = df[df["phase"] == phase.lower()]

    # df = df[df["phase"].astype(str).str.strip().str.lower() == phase.lower()]

    E0 = float(os.environ.get("UWSN_ENERGY_INITIAL_J", "100.0"))

    output_dir = output_dir or os.environ.get("OUTPUT_DIR", "stats/")
    # os.makedirs(output_dir, exist_ok=True)

    for run_id, group in df.groupby("run_id"):
        tx = group[group["energy_event_type"] == "tx"]
        rx = group[group["energy_event_type"] == "rx"]

        # Energía residual como transmisor
        # res_tx = tx[["sender_id", "residual_energy_sender"]].dropna()
        # res_tx = res_tx.rename(columns={"sender_id": "node_id", 
        #                                 "residual_energy_sender": "residual_energy"})
        # res_tx = res_tx.groupby("node_id")["residual_energy"].min().reset_index()

        # Energía residual como receptor
        # res_rx = rx[["receiver_id", "residual_energy_receiver"]].dropna()
        # res_rx = res_rx.rename(columns={"receiver_id": "node_id", 
        #                                 "residual_energy_receiver": "residual_energy"})
        # res_rx = res_rx.groupby("node_id")["residual_energy"].min().reset_index()

        # Unir ambas fuentes
        # residual_min = pd.concat([res_tx, res_rx]).groupby("node_id")["residual_energy"].min().reset_index()

        phase_energy = _load_phase_energy(snapshot_csv, run_id, phase,)

        tx = group[group["energy_event_type"] == "tx"]

        rx = group[group["energy_event_type"] == "rx"]

        tx_summary = tx.groupby("sender_id").agg(
            transmissions=("success", "count"),
            successes=("success", "sum"),
            latency_avg_ms=("latency_ms", "mean"),
            energy_tx_j=("energy_j", "sum"),
            clusterId=("cluster_id", "first"),
            packet_lost=("packet_lost", "sum")
        ).reset_index().rename(columns={"sender_id": "node_id"})

        rx_summary = rx.groupby("receiver_id").agg(
            energy_rx_j=("energy_j", "sum")
        ).reset_index().rename(columns={"receiver_id": "node_id"})

        # summary = pd.merge(tx_summary, rx_summary, on="node_id", how="outer")
        # summary = pd.merge(summary, residual_min, on="node_id", how="outer")
        summary = phase_energy.merge(tx_summary, on="node_id", how="left",)
        summary = summary.merge(rx_summary, on="node_id", how="left",)

        summary["energy_tx_j"] = (summary["energy_tx_j"].fillna(0.0))
        summary["energy_rx_j"] = (summary["energy_rx_j"].fillna(0.0))
        summary["energy_active_logged_j"] = (summary["energy_tx_j"] + summary["energy_rx_j"])

        summary["energy_standby_j"] = (summary["energy_total_j"] - summary["energy_active_logged_j"]).clip(lower=0.0)

        # summary["energy_tx_j"] = summary["energy_tx_j"].fillna(0.0)
        # summary["energy_rx_j"] = summary["energy_rx_j"].fillna(0.0)

        # # summary["energy_total_j"] = summary["energy_tx_j"] + summary["energy_rx_j"]

        # summary["energy_active_j"] = (summary["energy_tx_j"] + summary["energy_rx_j"])

        summary["latency_avg_ms"] = summary["latency_avg_ms"].round(2)
        # summary["energy_tx_j"] = summary["energy_tx_j"].round(8)
        # summary["energy_rx_j"] = summary["energy_rx_j"].round(8)

        # corregir luego, se requiere guardar un snapshot de energía de todos los nodos al inicio y al final de cada fase.
        # summary["energy_standby_j"] = (E0 - summary["residual_energy"]) - (summary["energy_tx_j"] + summary["energy_rx_j"])
        # summary["energy_standby_j"] = summary["energy_standby_j"].clip(lower=0.0).round(18)
        
        # summary["energy_total_j"] = (summary["energy_total_j"]+ summary["energy_standby_j"]).round(8)
        summary["energy_total_j"] = (summary["energy_active_logged_j"] + summary["energy_standby_j"])

        summary["residual_energy"] = summary["residual_energy"].fillna(0.0).round(8)
        summary["packet_loss_percent"] = (summary["packet_lost"] / summary["transmissions"] * 100).round(2)

        summary = summary[[
            "node_id", "clusterId", "transmissions", "successes",
            "latency_avg_ms", "energy_tx_j", "energy_rx_j", "energy_standby_j", 
            "energy_total_j","residual_energy", "packet_loss_percent"
        ]]

        # agregado nuevo
        SINK_ID = int(os.environ.get("UWSN_SINK_ID","0"))
        summary = summary[summary["node_id"] != SINK_ID].copy()

        output_csv = os.path.join(output_dir, f"{run_id}_{phase}_per_node.csv")
        summary.to_csv(output_csv, index=False)
        print(f"📁 Resumen por nodo exportado: {output_csv}")


def summarize_global_by_run(input_csv=CANON_CSV, output_dir=None, phase=None, snapshot_csv=None,):
    if not os.path.exists(input_csv):
        print(f"🚨 Archivo no encontrado: {input_csv}")
        return
    df = pd.read_csv(input_csv)
    df = df[df["phase"].astype(str).str.contains(phase)]
    # df = df[df["phase"].astype(str).str.strip().str.lower() == phase.lower()]

    output_dir = output_dir or os.environ.get("OUTPUT_DIR", "stats/")
    # os.makedirs(input_csv, exist_ok=True)

    # E0 = float(os.environ.get("UWSN_ENERGY_INITIAL_J", "100.0"))
    
    for run_id, group in df.groupby("run_id"):
        d = group.copy()

        ##
        msg = d["msg_type"].astype(str)
        is_tx = (d["energy_event_type"] == "tx")
        is_rx = (d["energy_event_type"] == "rx")
        is_data = msg.str.startswith("DATA:")
        is_ack = msg.str.startswith("ACK:")
        is_retry = msg.str.contains(":RETRY",regex=False,)
        all_tx = d[is_tx]
        data_tx = d[is_tx & is_data]
        initial_data_tx = d[is_tx & is_data & ~is_retry]
        retry_tx = d[is_tx & is_data & is_retry]
        ack_tx = d[is_tx & is_ack]
        total_tx_events = len(all_tx)
        logical_data_packets = len(initial_data_tx)
        data_attempts = len(data_tx)
        retransmissions = len(retry_tx)
        ack_attempts = len(ack_tx)
        ack_failures = int((~ack_tx["success"].astype(bool)).sum())
        ##

        ###
        phase_energy = _load_phase_energy(
            snapshot_csv,
            run_id,
            phase,
        )

        network_phase_energy_j = float(
            phase_energy["energy_total_j"].sum()
        )

        active_event_energy_j = float(
            d["energy_j"].sum()
        )

        standby_energy_j = max(
            0.0,
            network_phase_energy_j
            - active_event_energy_j,
        )
        ###

        # if "payload_len" in d.columns:
        #     d["payload_bits"] = d["payload_len"].fillna(0).astype(int) * 8
        # else:
        #     d["payload_bits"] = 0

        if "payload_len" in d.columns:
            d["payload_bits"] = (
                pd.to_numeric(
                    d["payload_len"],
                    errors="coerce"
                )
                .fillna(0)
            )
        else:
            d["payload_bits"] = 0
        
        # - PDR desde el punto de vista del receptor: rx_success / tx_total - recepción exitosa (paquete válido, sin errores)
        # - Tasa de entrega efectiva desde el emisor: tx_success / tx_total -  transmisión que fue confirmada como entregada (por ACK o por log cruzado)
        # tx_events = df[df.energy_event_type == "tx"]
        # rx_events = df[df.energy_event_type == "rx"]

        # tx_success = tx_events["success"].sum()
        # rx_success = rx_events["success"].sum()

        tx_events = d[d["energy_event_type"] == "tx"]
        # total_tx = len(tx_events)

        rx_events = d[d.energy_event_type == "rx"]
        # successful = int(rx_events["success"].sum())

        # avg_latency = d["latency_ms"].mean()
        ##
        avg_tx_event_latency_ms = (
            all_tx["latency_ms"].mean()
            if len(all_tx)
            else 0.0
        )
        ##

        ##
        total_link_tx_bits = float(
            data_tx["bits_sent"].sum() + ack_tx["bits_sent"].sum()
        )

        initial_application_bits = float(
            initial_data_tx["payload_bits"].sum()
        )

        link_payload_efficiency_percent = (
            100.0 * initial_application_bits / total_link_tx_bits
            if total_link_tx_bits > 0.0
            else 0.0
        )
        ##

        total_energy = d["energy_j"].sum()
        avg_energy = d["energy_j"].mean()

        kbps_bruto = (d["bits_received"].sum()/1024.0) / (d["latency_ms"].sum()/1000.0) if d["latency_ms"].sum() > 0 else 0.0
        kbps_util = (d["payload_bits"].sum()/1024.0) / (d["latency_ms"].sum()/1000.0) if d["latency_ms"].sum() > 0 else 0.0
        # eff_pct = (d["payload_bits"].sum() / d["bits_received"].sum() * 100.0) if d["bits_received"].sum() > 0 else 0.0
        # loss_pct = 100.0 * (1.0 - (successful / total_tx)) if total_tx > 0 else 0.0

        output_csv = os.path.join(output_dir, f"{run_id}_{phase}_global.csv")
        with open(output_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "run_id", "total_transmissions", "successful_receptions", "avg_latency_ms",
                "avg_throughput_bruto_kbps", "avg_throughput_util_kbps",
                "efficiency_percent", "total_energy_j", "avg_energy_j", "packet_loss_percent"
            ])
            w.writerow([
                run_id, total_tx, successful, round(avg_latency or 0,2),
                round(kbps_bruto,2), round(kbps_util,2),
                round(eff_pct,2), round(total_energy or 0,8),
                round(avg_energy or 0,8), round(loss_pct,2)
            ])
        print(f"📊 Resumen global exportado: {output_csv}")


# print(f"📁 Guardando en: {os.environ.get('OUTPUT_DIR')}")

# output_dir = os.environ.get("OUTPUT_DIR", "stats/")
# for phase in PHASES:
#     print(f"\n📡 Procesando fase: {phase}")
#     summarize_per_node_by_run(phase=phase)
#     summarize_global_by_run(phase=phase)

def summarize_all_by_run(
    input_csv=CANON_CSV,
    output_dir=None,
    snapshot_csv=None,
    sim_duration_s=None,
):

    for phase in PHASES:

        print(
            f"\n📡 Procesando fase: {phase}"
        )

        summarize_per_node_by_run(
            input_csv=input_csv,
            output_dir=output_dir,
            phase=phase,
            snapshot_csv=snapshot_csv,
        )

        summarize_global_by_run(
            input_csv=input_csv,
            output_dir=output_dir,
            phase=phase,
            snapshot_csv=snapshot_csv,
            sim_duration_s=sim_duration_s,
        )