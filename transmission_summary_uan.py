# transmission_summary_uan.py
#
# Resumen estadístico sobre:
#
#   transmissions.csv
#       -> eventos TX/RX, ACK, retries, latencias y energía activa
#
#   energy_phase_snapshots.csv
#       -> energía residual start/end por nodo y fase
#
# La energía total de una fase SIEMPRE se deriva de snapshots:
#
#   E_phase = E_start - E_end
#
# El CSV de transmisiones se utiliza únicamente para descomponer:
#
#   E_active_logged = E_TX + E_RX
#
#   E_standby/unlogged = E_phase - E_active_logged

import os
import pandas as pd


CANON_CSV = os.environ.get(
    "UWSN_EVENTS_CSV",
    "stats/transmissions.csv",
)

PHASES = ["syn", "auth", "data"]

ENERGY_TOL_J = 1e-6


# ============================================================
# Helpers
# ============================================================

def _resolve_snapshot_csv(
    input_csv,
    snapshot_csv=None,
):
    """
    Si no se pasa explícitamente el archivo de snapshots,
    se busca junto al transmissions.csv del run.
    """

    if snapshot_csv is not None:
        return snapshot_csv

    return os.path.join(
        os.path.dirname(
            os.path.abspath(input_csv)
        ),
        "energy_phase_snapshots.csv",
    )


def _bool_series(series):
    """
    Conversión robusta de columnas booleanas leídas desde CSV.

    Evita usar:
        astype(bool)

    porque:
        bool("False") == True
    """

    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)

    if pd.api.types.is_numeric_dtype(series):
        return (
            pd.to_numeric(
                series,
                errors="coerce",
            )
            .fillna(0)
            .ne(0)
        )

    return (
        series
        .astype(str)
        .str.strip()
        .str.lower()
        .isin({
            "true",
            "1",
            "yes",
            "y",
            "t",
        })
    )


def _load_phase_energy(
    snapshot_csv,
    run_id,
    phase,
):
    """
    Reconstruye el consumo REAL de energía de cada nodo
    durante una fase a partir de snapshots start/end.

    El Sink no aparece en energy_phase_snapshots.csv.
    """

    if snapshot_csv is None:
        raise ValueError(
            "snapshot_csv es obligatorio para "
            "calcular energía por fase."
        )

    if not os.path.exists(snapshot_csv):
        raise FileNotFoundError(
            f"No existe snapshot CSV: "
            f"{snapshot_csv}"
        )

    snap = pd.read_csv(snapshot_csv)

    required = {
        "run_id",
        "phase",
        "boundary",
        "node_id",
        "role",
        "cluster_id",
        "cluster_head",
        "residual_energy_j",
    }

    missing = required - set(snap.columns)

    if missing:
        raise ValueError(
            "Faltan columnas en "
            "energy_phase_snapshots.csv: "
            f"{sorted(missing)}"
        )

    snap["phase"] = (
        snap["phase"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    snap["boundary"] = (
        snap["boundary"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    p = snap[
        (snap["run_id"].astype(str) == str(run_id))
        & (
            snap["phase"]
            == str(phase).lower()
        )
    ].copy()

    if p.empty:
        raise ValueError(
            "No existen snapshots para "
            f"run_id={run_id}, phase={phase}"
        )

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

    if start["node_id"].duplicated().any():
        raise ValueError(
            "Snapshots START duplicados para "
            f"run={run_id}, phase={phase}"
        )

    if end["node_id"].duplicated().any():
        raise ValueError(
            "Snapshots END duplicados para "
            f"run={run_id}, phase={phase}"
        )

    start_nodes = set(start["node_id"])
    end_nodes = set(end["node_id"])

    if start_nodes != end_nodes:
        raise ValueError(
            "Los nodos START/END no coinciden "
            f"en run={run_id}, phase={phase}. "
            f"Solo START={sorted(start_nodes-end_nodes)}, "
            f"solo END={sorted(end_nodes-start_nodes)}"
        )

    energy = start.merge(
        end,
        on="node_id",
        how="inner",
        validate="one_to_one",
    )

    delta = (
        pd.to_numeric(
            energy["residual_start_j"],
            errors="coerce",
        )
        -
        pd.to_numeric(
            energy["residual_end_j"],
            errors="coerce",
        )
    )

    # Una batería no debería ganar energía.
    # Permitimos solo error numérico muy pequeño.
    if (delta < -ENERGY_TOL_J).any():

        bad = energy.loc[
            delta < -ENERGY_TOL_J,
            [
                "node_id",
                "residual_start_j",
                "residual_end_j",
            ]
        ]

        raise ValueError(
            "Se detectó incremento inesperado de "
            "energía residual:\n"
            f"{bad}"
        )

    energy["energy_total_j"] = (
        delta.clip(lower=0.0)
    )

    return energy


# ============================================================
# Resumen PER NODE
# ============================================================

def summarize_per_node_by_run(
    input_csv=CANON_CSV,
    output_dir=None,
    phase=None,
    snapshot_csv=None,
):

    if phase is None:
        raise ValueError(
            "phase no puede ser None."
        )

    if not os.path.exists(input_csv):
        raise FileNotFoundError(
            f"Archivo no encontrado: {input_csv}"
        )

    snapshot_csv = _resolve_snapshot_csv(
        input_csv,
        snapshot_csv,
    )

    output_dir = (
        output_dir
        or os.environ.get("OUTPUT_DIR")
        or os.path.dirname(
            os.path.abspath(input_csv)
        )
    )

    os.makedirs(
        output_dir,
        exist_ok=True,
    )

    df = pd.read_csv(input_csv)

    df["phase"] = (
        df["phase"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    df = df[
        df["phase"]
        == str(phase).lower()
    ].copy()

    # Los run_id se toman de snapshots para que incluso
    # una fase sin eventos pueda conservar energía total.
    snap = pd.read_csv(snapshot_csv)

    snap["phase"] = (
        snap["phase"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    run_ids = (
        snap[
            snap["phase"]
            == str(phase).lower()
        ]["run_id"]
        .astype(str)
        .unique()
    )

    for run_id in run_ids:

        group = df[
            df["run_id"].astype(str)
            == str(run_id)
        ].copy()

        phase_energy = _load_phase_energy(
            snapshot_csv,
            run_id,
            phase,
        )

        if not group.empty:

            group["success_bool"] = (
                _bool_series(
                    group["success"]
                )
            )

            group["packet_lost_bool"] = (
                _bool_series(
                    group["packet_lost"]
                )
            )

            group["energy_j"] = (
                pd.to_numeric(
                    group["energy_j"],
                    errors="coerce",
                )
                .fillna(0.0)
            )

            group["latency_ms"] = (
                pd.to_numeric(
                    group["latency_ms"],
                    errors="coerce",
                )
            )

        tx = group[
            group["energy_event_type"]
            == "tx"
        ].copy()

        rx = group[
            group["energy_event_type"]
            == "rx"
        ].copy()

        # ----------------------------------------------------
        # TX
        # ----------------------------------------------------

        if not tx.empty:

            tx_summary = (
                tx
                .groupby("sender_id")
                .agg(
                    tx_events=(
                        "success_bool",
                        "size",
                    ),
                    tx_successes=(
                        "success_bool",
                        "sum",
                    ),
                    tx_packet_lost=(
                        "packet_lost_bool",
                        "sum",
                    ),
                    avg_tx_event_latency_ms=(
                        "latency_ms",
                        "mean",
                    ),
                    energy_tx_j=(
                        "energy_j",
                        "sum",
                    ),
                )
                .reset_index()
                .rename(
                    columns={
                        "sender_id":
                            "node_id"
                    }
                )
            )

        else:

            tx_summary = pd.DataFrame(
                columns=[
                    "node_id",
                    "tx_events",
                    "tx_successes",
                    "tx_packet_lost",
                    "avg_tx_event_latency_ms",
                    "energy_tx_j",
                ]
            )

        # ----------------------------------------------------
        # RX
        # ----------------------------------------------------

        if not rx.empty:

            rx_summary = (
                rx
                .groupby("receiver_id")
                .agg(
                    rx_events=(
                        "success_bool",
                        "size",
                    ),
                    rx_successes=(
                        "success_bool",
                        "sum",
                    ),
                    energy_rx_j=(
                        "energy_j",
                        "sum",
                    ),
                )
                .reset_index()
                .rename(
                    columns={
                        "receiver_id":
                            "node_id"
                    }
                )
            )

        else:

            rx_summary = pd.DataFrame(
                columns=[
                    "node_id",
                    "rx_events",
                    "rx_successes",
                    "energy_rx_j",
                ]
            )

        # ====================================================
        # Base = snapshots
        # ====================================================

        summary = phase_energy.merge(
            tx_summary,
            on="node_id",
            how="left",
        )

        summary = summary.merge(
            rx_summary,
            on="node_id",
            how="left",
        )

        integer_cols = [
            "tx_events",
            "tx_successes",
            "tx_packet_lost",
            "rx_events",
            "rx_successes",
        ]

        for col in integer_cols:
            summary[col] = (
                summary[col]
                .fillna(0)
                .astype(int)
            )

        summary["energy_tx_j"] = (
            summary["energy_tx_j"]
            .fillna(0.0)
        )

        summary["energy_rx_j"] = (
            summary["energy_rx_j"]
            .fillna(0.0)
        )

        summary[
            "energy_active_logged_j"
        ] = (
            summary["energy_tx_j"]
            + summary["energy_rx_j"]
        )

        energy_unlogged = (
            summary["energy_total_j"]
            -
            summary[
                "energy_active_logged_j"
            ]
        )

        # Si esto es muy negativo existe una
        # inconsistencia real de contabilidad.
        if (
            energy_unlogged
            < -ENERGY_TOL_J
        ).any():

            bad = summary.loc[
                energy_unlogged
                < -ENERGY_TOL_J,
                [
                    "node_id",
                    "energy_total_j",
                    "energy_active_logged_j",
                ]
            ]

            raise ValueError(
                "La energía activa registrada supera "
                "la energía medida por snapshots:\n"
                f"{bad}"
            )

        # En el modelo actual, la energía no registrada
        # por TX/RX corresponde principalmente a standby.
        summary[
            "energy_standby_j"
        ] = (
            energy_unlogged
            .clip(lower=0.0)
        )

        summary[
            "energy_balance_error_j"
        ] = (
            summary["energy_total_j"]
            -
            (
                summary[
                    "energy_active_logged_j"
                ]
                +
                summary[
                    "energy_standby_j"
                ]
            )
        )

        # Compatibilidad con scripts antiguos.
        summary["residual_energy"] = (
            summary["residual_end_j"]
        )

        summary[
            "tx_event_loss_percent"
        ] = 0.0

        tx_mask = (
            summary["tx_events"] > 0
        )

        summary.loc[
            tx_mask,
            "tx_event_loss_percent",
        ] = (
            100.0
            * summary.loc[
                tx_mask,
                "tx_packet_lost",
            ]
            / summary.loc[
                tx_mask,
                "tx_events",
            ]
        )

        summary[
            "packet_loss_percent"
        ] = summary[
            "tx_event_loss_percent"
        ]

        numeric_round = [
            "residual_start_j",
            "residual_end_j",
            "residual_energy",
            "energy_tx_j",
            "energy_rx_j",
            "energy_active_logged_j",
            "energy_standby_j",
            "energy_total_j",
            "energy_balance_error_j",
        ]

        for col in numeric_round:
            summary[col] = (
                pd.to_numeric(
                    summary[col],
                    errors="coerce",
                )
                .round(10)
            )

        summary[
            "avg_tx_event_latency_ms"
        ] = (
            pd.to_numeric(
                summary[
                    "avg_tx_event_latency_ms"
                ],
                errors="coerce",
            )
            .fillna(0.0)
            .round(4)
        )

        summary[
            "packet_loss_percent"
        ] = (
            summary[
                "packet_loss_percent"
            ]
            .round(4)
        )

        summary = summary[
            [
                "node_id",
                "role",
                "cluster_id",
                "cluster_head",

                "tx_events",
                "tx_successes",
                "rx_events",
                "rx_successes",

                "avg_tx_event_latency_ms",

                "energy_tx_j",
                "energy_rx_j",
                "energy_active_logged_j",
                "energy_standby_j",
                "energy_total_j",
                "energy_balance_error_j",

                "residual_start_j",
                "residual_end_j",
                "residual_energy",

                "packet_loss_percent",
            ]
        ]

        output_csv = os.path.join(
            output_dir,
            f"{run_id}_{phase}_per_node.csv",
        )

        summary.to_csv(
            output_csv,
            index=False,
        )

        print(
            "📁 Resumen por nodo exportado: "
            f"{output_csv}"
        )


# ============================================================
# Resumen GLOBAL
# ============================================================

def summarize_global_by_run(
    input_csv=CANON_CSV,
    output_dir=None,
    phase=None,
    snapshot_csv=None,
    sim_duration_s=None,
):

    if phase is None:
        raise ValueError(
            "phase no puede ser None."
        )

    if not os.path.exists(input_csv):
        raise FileNotFoundError(
            f"Archivo no encontrado: {input_csv}"
        )

    snapshot_csv = _resolve_snapshot_csv(
        input_csv,
        snapshot_csv,
    )

    output_dir = (
        output_dir
        or os.environ.get("OUTPUT_DIR")
        or os.path.dirname(
            os.path.abspath(input_csv)
        )
    )

    os.makedirs(
        output_dir,
        exist_ok=True,
    )

    if sim_duration_s is None:
        sim_duration_s = float(
            os.environ.get(
                "SIM_DURATION_S",
                "600",
            )
        )

    df = pd.read_csv(input_csv)

    df["phase"] = (
        df["phase"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    df = df[
        df["phase"]
        == str(phase).lower()
    ].copy()

    snap = pd.read_csv(snapshot_csv)

    snap["phase"] = (
        snap["phase"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    run_ids = (
        snap[
            snap["phase"]
            == str(phase).lower()
        ]["run_id"]
        .astype(str)
        .unique()
    )

    for run_id in run_ids:

        d = df[
            df["run_id"].astype(str)
            == str(run_id)
        ].copy()

        if not d.empty:

            d["success_bool"] = (
                _bool_series(
                    d["success"]
                )
            )

            d["packet_lost_bool"] = (
                _bool_series(
                    d["packet_lost"]
                )
            )

            for col in [
                "energy_j",
                "latency_ms",
                "bits_sent",
                "bits_received",
                "payload_len",
            ]:

                d[col] = (
                    pd.to_numeric(
                        d[col],
                        errors="coerce",
                    )
                    .fillna(0.0)
                )

            # payload_len YA ESTÁ EN BITS.
            d["payload_bits"] = (
                d["payload_len"]
            )

        else:

            d["success_bool"] = False
            d["packet_lost_bool"] = False
            d["payload_bits"] = 0.0

        # ====================================================
        # Clasificación de eventos
        # ====================================================

        msg = d["msg_type"].astype(str)

        is_tx = (
            d["energy_event_type"]
            == "tx"
        )

        is_rx = (
            d["energy_event_type"]
            == "rx"
        )

        is_data = (
            msg.str.startswith(
                "DATA:"
            )
        )

        is_ack = (
            msg.str.startswith(
                "ACK:"
            )
        )

        is_retry = (
            msg.str.contains(
                ":RETRY",
                regex=False,
            )
        )

        all_tx = d[is_tx]
        all_rx = d[is_rx]

        data_tx = d[
            is_tx
            & is_data
        ]

        data_rx = d[
            is_rx
            & is_data
        ]

        initial_data_tx = d[
            is_tx
            & is_data
            & ~is_retry
        ]

        initial_data_rx = d[
            is_rx
            & is_data
            & ~is_retry
        ]

        retry_tx = d[
            is_tx
            & is_data
            & is_retry
        ]

        ack_tx = d[
            is_tx
            & is_ack
        ]

        # ====================================================
        # Conteos físicos
        # ====================================================

        total_tx_events = int(
            len(all_tx)
        )

        total_rx_events = int(
            len(all_rx)
        )

        successful_tx_events = int(
            all_tx[
                "success_bool"
            ].sum()
        )

        successful_rx_events = int(
            all_rx[
                "success_bool"
            ].sum()
        )

        # ====================================================
        # DATA + ARQ
        # ====================================================

        logical_data_packets = int(
            len(initial_data_tx)
        )

        data_attempts = int(
            len(data_tx)
        )

        retransmissions = int(
            len(retry_tx)
        )

        if (
            data_attempts
            !=
            logical_data_packets
            + retransmissions
        ):
            raise ValueError(
                "Invariante ARQ roto: "
                f"data_attempts={data_attempts}, "
                f"logical_data_packets="
                f"{logical_data_packets}, "
                f"retransmissions="
                f"{retransmissions}"
            )

        data_attempt_successes = int(
            data_rx[
                "success_bool"
            ].sum()
        )

        first_attempt_successes = int(
            initial_data_rx[
                "success_bool"
            ].sum()
        )

        physical_data_losses = int(
            data_rx[
                "packet_lost_bool"
            ].sum()
        )

        ack_attempts = int(
            len(ack_tx)
        )

        ack_failures = int(
            (
                ~ack_tx[
                    "success_bool"
                ]
            ).sum()
        )

        data_attempt_success_percent = (
            100.0
            * data_attempt_successes
            / data_attempts
            if data_attempts > 0
            else 0.0
        )

        first_attempt_success_percent = (
            100.0
            * first_attempt_successes
            / logical_data_packets
            if logical_data_packets > 0
            else 0.0
        )

        retransmission_rate_percent = (
            100.0
            * retransmissions
            / logical_data_packets
            if logical_data_packets > 0
            else 0.0
        )

        ack_failure_percent = (
            100.0
            * ack_failures
            / ack_attempts
            if ack_attempts > 0
            else 0.0
        )

        # ====================================================
        # ENERGÍA REAL DE FASE
        # ====================================================

        phase_energy = _load_phase_energy(
            snapshot_csv,
            run_id,
            phase,
        )

        network_phase_energy_j = float(
            phase_energy[
                "energy_total_j"
            ].sum()
        )

        active_event_energy_j = float(
            d["energy_j"].sum()
            if not d.empty
            else 0.0
        )

        unlogged_energy_j = (
            network_phase_energy_j
            - active_event_energy_j
        )

        if (
            unlogged_energy_j
            < -ENERGY_TOL_J
        ):
            raise ValueError(
                "La energía activa registrada supera "
                "la energía total de snapshots: "
                f"run={run_id}, phase={phase}, "
                f"E_phase="
                f"{network_phase_energy_j}, "
                f"E_active="
                f"{active_event_energy_j}"
            )

        standby_energy_j = max(
            0.0,
            unlogged_energy_j,
        )

        energy_balance_error_j = (
            network_phase_energy_j
            -
            (
                active_event_energy_j
                + standby_energy_j
            )
        )

        num_energy_nodes = int(
            len(phase_energy)
        )

        avg_phase_energy_per_node_j = (
            network_phase_energy_j
            / num_energy_nodes
            if num_energy_nodes > 0
            else 0.0
        )

        # ====================================================
        # LATENCIA
        #
        # Esto NO se presenta como end-to-end.
        # Son latencias de eventos físicos TX.
        # ====================================================

        avg_tx_event_latency_ms = (
            float(
                all_tx[
                    "latency_ms"
                ].mean()
            )
            if len(all_tx)
            else 0.0
        )

        avg_rx_event_latency_ms = (
            float(
                all_rx[
                    "latency_ms"
                ].mean()
            )
            if len(all_rx)
            else 0.0
        )

        avg_data_tx_attempt_latency_ms = (
            float(
                data_tx[
                    "latency_ms"
                ].mean()
            )
            if len(data_tx)
            else 0.0
        )

        avg_ack_tx_latency_ms = (
            float(
                ack_tx[
                    "latency_ms"
                ].mean()
            )
            if len(ack_tx)
            else 0.0
        )

        # ====================================================
        # BITS / eficiencia link-layer DATA
        # ====================================================

        data_tx_bits = float(
            data_tx[
                "bits_sent"
            ].sum()
        )

        ack_tx_bits = float(
            ack_tx[
                "bits_sent"
            ].sum()
        )

        total_link_tx_bits = (
            data_tx_bits
            + ack_tx_bits
        )

        # Solo payload ofrecido originalmente.
        # Un retry NO crea nuevo payload de aplicación.
        initial_application_bits = float(
            initial_data_tx[
                "payload_bits"
            ].sum()
        )

        link_payload_efficiency_percent = (
            100.0
            * initial_application_bits
            / total_link_tx_bits
            if total_link_tx_bits > 0.0
            else 0.0
        )

        # ====================================================
        # IMPORTANTE:
        #
        # No calculamos aquí todavía "logical PDR" ni
        # goodput end-to-end.
        #
        # El CSV actual no contiene logical_packet_id que
        # identifique de manera inequívoca:
        #
        #     intento inicial + retries + ACK
        #
        # Por eso los porcentajes anteriores son explícitamente
        # métricas por intento/evento.
        # ====================================================

        row = {
            "run_id":
                run_id,

            "phase":
                phase,

            "energy_nodes":
                num_energy_nodes,

            "total_tx_events":
                total_tx_events,

            "total_rx_events":
                total_rx_events,

            "successful_tx_events":
                successful_tx_events,

            "successful_rx_events":
                successful_rx_events,

            # DATA / ARQ
            "logical_data_packets":
                logical_data_packets,

            "data_attempts":
                data_attempts,

            "data_attempt_successes":
                data_attempt_successes,

            "first_attempt_successes":
                first_attempt_successes,

            "physical_data_losses":
                physical_data_losses,

            "retransmissions":
                retransmissions,

            "retransmission_rate_percent":
                retransmission_rate_percent,

            "data_attempt_success_percent":
                data_attempt_success_percent,

            "first_attempt_success_percent":
                first_attempt_success_percent,

            "ack_attempts":
                ack_attempts,

            "ack_failures":
                ack_failures,

            "ack_failure_percent":
                ack_failure_percent,

            # Latencia
            "avg_tx_event_latency_ms":
                avg_tx_event_latency_ms,

            "avg_rx_event_latency_ms":
                avg_rx_event_latency_ms,

            "avg_data_tx_attempt_latency_ms":
                avg_data_tx_attempt_latency_ms,

            "avg_ack_tx_latency_ms":
                avg_ack_tx_latency_ms,

            # Bits
            "initial_application_bits":
                initial_application_bits,

            "data_tx_bits":
                data_tx_bits,

            "ack_tx_bits":
                ack_tx_bits,

            "total_link_tx_bits":
                total_link_tx_bits,

            "link_payload_efficiency_percent":
                link_payload_efficiency_percent,

            # Energía
            "network_phase_energy_j":
                network_phase_energy_j,

            "active_event_energy_j":
                active_event_energy_j,

            "standby_energy_j":
                standby_energy_j,

            "avg_phase_energy_per_node_j":
                avg_phase_energy_per_node_j,

            "energy_balance_error_j":
                energy_balance_error_j,

            "sim_duration_s":
                float(sim_duration_s),
        }

        output_csv = os.path.join(
            output_dir,
            f"{run_id}_{phase}_global.csv",
        )

        pd.DataFrame(
            [row]
        ).to_csv(
            output_csv,
            index=False,
        )

        print(
            "📊 Resumen global exportado: "
            f"{output_csv}"
        )


# ============================================================
# Todos los resúmenes del run
# ============================================================

def summarize_all_by_run(
    input_csv=CANON_CSV,
    output_dir=None,
    snapshot_csv=None,
    sim_duration_s=None,
):

    for phase in PHASES:

        print(
            f"\n📡 Procesando fase: "
            f"{phase}"
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
            sim_duration_s=
                sim_duration_s,
        )