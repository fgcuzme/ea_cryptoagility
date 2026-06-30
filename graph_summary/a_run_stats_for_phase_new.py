import os
import glob
import pandas as pd

# === CONFIGURACIÓN ===
# Carpeta raíz del escenario S1 con 200 nodos (ajusta la ruta a la tuya)
BASE_DIR = r"C:\compilables_embed\results_W5_Sh0.5_1000m\nodes_200"

# Número de ejecuciones independientes
N_RUNS = 30
num_nodes = 200

# Mapeo de fase -> sufijo que aparece en el nombre del CSV
PHASE_SUFFIX = {
    "sync": "syn",     # *_syn_per_node.csv
    "auth": "auth",    # *_auth_per_node.csv
    "data": "data",    # *_data_per_node.csv
}

# Nombre de columnas esperadas en los CSV *_per_node
TX_COL = "transmissions"
E_TX_COL = "energy_tx_j"
E_RX_COL = "energy_rx_j"
E_SB_COL = "energy_standby_j"


def load_phase_file(run_dir: str, phase_tag: str) -> pd.DataFrame:
    """
    Busca y carga el CSV *_<phase_tag>_per_node.csv dentro de run_dir.
    Ejemplo: phase_tag="auth" -> *auth_per_node.csv
    """
    pattern = os.path.join(run_dir, f"*_{phase_tag}_per_node.csv")
    matches = glob.glob(pattern)
    if not matches:
        raise FileNotFoundError(f"No se encontró CSV de fase '{phase_tag}' en {run_dir}")
    if len(matches) > 1:
        print(f"[WARN] Múltiples archivos para fase '{phase_tag}' en {run_dir}, usando: {matches[0]}")
    df = pd.read_csv(matches[0])
    return df


def drop_sink(df: pd.DataFrame) -> pd.DataFrame:
    """
    Elimina el sink (node_id == 0) si existe.
    Intenta varias posibles columnas de ID.
    """
    for col in ["node_id", "NodeID", "node", "id"]:
        if col in df.columns:
            return df[df[col] != 0].copy()
    # Si no hay columna de ID, devuelve tal cual
    return df


def aggregate_phase(base_dir: str, n_runs: int = 30):
    """
    Recorre run_01 ... run_30 y acumula energía TX, RX, standby
    y número de transmisiones por fase (sync, auth, data).
    """
    # Estructura de acumulación
    agg = {
        phase: {
            "runs": [],
            "tx_events": [],
            "E_tx": [],
            "E_rx": [],
            "E_sb": [],
        }
        for phase in PHASE_SUFFIX.keys()
    }

    for run in range(1, n_runs + 1):
        run_dir = os.path.join(base_dir, f"run_{run}")
        if not os.path.isdir(run_dir):
            print(f"[WARN] Carpeta no existe, se omite: {run_dir}")
            continue

        print(f"Procesando {run_dir} ...")

        for phase, tag in PHASE_SUFFIX.items():
            try:
                df = load_phase_file(run_dir, tag)
            except FileNotFoundError as e:
                print(f"  [WARN] {e}")
                continue

            df = drop_sink(df)

            # Verifica columnas esperadas
            for col in [TX_COL, E_TX_COL, E_RX_COL, E_SB_COL]:
                if col not in df.columns:
                    raise KeyError(f"Columna '{col}' no encontrada en {run_dir}, fase {phase}")

            tx_events = df[TX_COL].sum()
            E_tx = df[E_TX_COL].sum()
            E_rx = df[E_RX_COL].sum()
            E_sb = df[E_SB_COL].sum()

            agg[phase]["runs"].append(run)
            agg[phase]["tx_events"].append(tx_events)
            agg[phase]["E_tx"].append(E_tx)
            agg[phase]["E_rx"].append(E_rx)
            agg[phase]["E_sb"].append(E_sb)

    return agg


def summarize_for_table(agg):
    """
    A partir de 'agg' (salida de aggregate_phase), imprime los valores
    que necesitas para llenar la Tabla XI.
    """
    print("\n================= RESUMEN POR FASE (30 runs) =================\n")

    summary_rows = []

    for phase in ["sync", "auth", "data"]:
        data = agg[phase]
        if not data["runs"]:
            print(f"[WARN] No hay datos para la fase {phase}")
            continue

        total_tx = sum(data["tx_events"])
        total_E_tx = sum(data["E_tx"])
        total_E_rx = sum(data["E_rx"])
        total_E_sb = sum(data["E_sb"])
        total_E = total_E_tx + total_E_rx + total_E_sb

        # Energía media por RUN (útil si quieres J/run)
        mean_E_tx_run = total_E_tx / len(data["runs"])
        mean_E_rx_run = total_E_rx / len(data["runs"])
        mean_E_sb_run = total_E_sb / len(data["runs"])
        mean_E_run = total_E / len(data["runs"])

        # mJ por evento de transmisión (normalizado por nº de TX)
        E_tx_mJ_per_tx = (total_E_tx / total_tx) * 1000.0
        E_rx_mJ_per_tx = (total_E_rx / total_tx) * 1000.0
        E_sb_mJ_per_tx = (total_E_sb / total_tx) * 1000.0
        E_tot_mJ_per_tx = (total_E / total_tx) * 1000.0

        print(f"--- Fase: {phase.upper()} ---")
        print(f"  Runs         : {len(data['runs'])}")
        print(f"  TX events    : {total_tx}")
        print(f"  E_tx total   : {total_E_tx:.3f} J")
        print(f"  E_rx total   : {total_E_rx:.3f} J")
        print(f"  E_standby    : {total_E_sb:.3f} J")
        print(f"  E_total      : {total_E:.3f} J")
        print(f"  E_tx/run     : {mean_E_tx_run:.3f} J")
        print(f"  E_rx/run     : {mean_E_rx_run:.3f} J")
        print(f"  E_standby/run: {mean_E_sb_run:.3f} J")
        print(f"  E_total/run  : {mean_E_run:.3f} J")
        print(f"  --- mJ por evento de TX ---")
        print(f"  E_tx/tx      : {E_tx_mJ_per_tx:.2f} mJ")
        print(f"  E_rx/tx      : {E_rx_mJ_per_tx:.2f} mJ")
        print(f"  E_standby/tx : {E_sb_mJ_per_tx:.2f} mJ")
        print(f"  E_total/tx   : {E_tot_mJ_per_tx:.2f} mJ\n")

        summary_rows.append({
            "phase": phase,
            "total_tx_events": total_tx,
            "E_tx_J": total_E_tx,
            "E_rx_J": total_E_rx,
            "E_standby_J": total_E_sb,
            "E_total_J": total_E,
            "E_tx_mJ_per_tx": E_tx_mJ_per_tx,
            "E_rx_mJ_per_tx": E_rx_mJ_per_tx,
            "E_standby_mJ_per_tx": E_sb_mJ_per_tx,
            "E_total_mJ_per_tx": E_tot_mJ_per_tx,
        })

    # DataFrame opcional por si quieres exportar a CSV o copiar números cómodamente
    summary_df = pd.DataFrame(summary_rows)
    print("=== RESUMEN TABLA XI (valores globales en 30 runs) ===")
    print(summary_df.to_string(index=False))
    # Si quieres, guarda a CSV:
    summary_df.to_csv(os.path.join(BASE_DIR,f"phase_energy_summary_{num_nodes}nodes_30runs.csv"), index=False)

    return summary_df


if __name__ == "__main__":
    agg = aggregate_phase(BASE_DIR, N_RUNS)
    summary_df = summarize_for_table(agg)
