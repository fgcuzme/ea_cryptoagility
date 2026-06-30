import os
import pandas as pd
import numpy as np

# ==== AJUSTA ESTA RUTA A TU CARPETA DE 200 NODOS ====
ROOT_DIR = r"C:\compilables_embed\results_W5_Sh0.5_1000m\nodes_200"
# ====================================================

RUN_IDS = range(1, 31)  # 30 runs
PHASE_FILES = {
    "Sync": "_syn_per_node.csv",
    "Auth": "_auth_per_node.csv",
    "Data": "_data_per_node.csv",
}

def load_phase_df(run_dir, suffix):
    """
    Busca el csv de una fase dentro de run_dir cuyo nombre termina en suffix,
    por ejemplo '_auth_per_node.csv'.
    """
    for fname in os.listdir(run_dir):
        if fname.endswith(suffix):
            path = os.path.join(run_dir, fname)
            return pd.read_csv(path)
    raise FileNotFoundError(f"No se encontró ningún archivo *{suffix} en {run_dir}")

rows = []

for run_id in RUN_IDS:
    run_dir = os.path.join(ROOT_DIR, f"run_{run_id}")
    if not os.path.isdir(run_dir):
        print(f"[WARN] No existe {run_dir}, se salta este run.")
        continue

    for phase_name, suffix in PHASE_FILES.items():
        try:
            df = load_phase_df(run_dir, suffix)
        except FileNotFoundError as e:
            print(f"[WARN] {e}")
            continue

        # Excluir el sink si viene en la tabla
        if "node_id" in df.columns:
            df = df[df["node_id"] != 0]

        # Sumas por fase y run
        n_tx = df["transmissions"].sum()  # número de eventos de TX de esa fase
        e_tx = df["energy_tx_j"].sum()
        e_rx = df["energy_rx_j"].sum()
        e_sb = df["energy_standby_j"].sum()
        e_total = e_tx + e_rx + e_sb

        # Energía por evento (mJ). Tú decides si usar total o solo TX+RX.
        e_comm = e_tx + e_rx   # solo energía de comunicación
        e_comm_per_tx_mJ = (e_comm / n_tx * 1e3) if n_tx > 0 else np.nan
        e_total_per_tx_mJ = (e_total / n_tx * 1e3) if n_tx > 0 else np.nan

        rows.append({
            "run": run_id,
            "phase": phase_name,
            "transmissions": n_tx,
            "E_tx_J": e_tx,
            "E_rx_J": e_rx,
            "E_sb_J": e_sb,
            "E_comm_J": e_comm,
            "E_total_J": e_total,
            "E_comm_per_tx_mJ": e_comm_per_tx_mJ,
            "E_total_per_tx_mJ": e_total_per_tx_mJ,
        })

# DataFrame con una fila por (run, fase)
df_runs = pd.DataFrame(rows)

print("\n=== Primeras filas (debug) ===")
print(df_runs.head())

# ==== Estadísticas agregadas para Tabla XI ====
# Promedio y desviación estándar por fase sobre las 30 ejecuciones
agg = (
    df_runs
    .groupby("phase")
    .agg(
        transmissions_mean=("transmissions", "mean"),
        transmissions_std=("transmissions", "std"),
        E_comm_J_mean=("E_comm_J", "mean"),
        E_comm_J_std=("E_comm_J", "std"),
        E_total_J_mean=("E_total_J", "mean"),
        E_total_J_std=("E_total_J", "std"),
        E_comm_per_tx_mJ_mean=("E_comm_per_tx_mJ", "mean"),
        E_comm_per_tx_mJ_std=("E_comm_per_tx_mJ", "std"),
        E_total_per_tx_mJ_mean=("E_total_per_tx_mJ", "mean"),
        E_total_per_tx_mJ_std=("E_total_per_tx_mJ", "std"),
    )
    .reset_index()
)

print("\n=== Resumen por fase (para Tabla XI) ===")
print(agg)

# Opcional: fila "Total" sumando por fase para cada run y luego promediando
df_totals_per_run = (
    df_runs
    .groupby("run")
    .agg(
        transmissions=("transmissions", "sum"),
        E_comm_J=("E_comm_J", "sum"),
        E_total_J=("E_total_J", "sum"),
    )
    .reset_index()
)

df_totals_per_run["E_comm_per_tx_mJ"] = (
    df_totals_per_run["E_comm_J"] / df_totals_per_run["transmissions"] * 1e3
)
df_totals_per_run["E_total_per_tx_mJ"] = (
    df_totals_per_run["E_total_J"] / df_totals_per_run["transmissions"] * 1e3
)

total_row = {
    "phase": "Total",
    "transmissions_mean": df_totals_per_run["transmissions"].mean(),
    "transmissions_std": df_totals_per_run["transmissions"].std(),
    "E_comm_J_mean": df_totals_per_run["E_comm_J"].mean(),
    "E_comm_J_std": df_totals_per_run["E_comm_J"].std(),
    "E_total_J_mean": df_totals_per_run["E_total_J"].mean(),
    "E_total_J_std": df_totals_per_run["E_total_J"].std(),
    "E_comm_per_tx_mJ_mean": df_totals_per_run["E_comm_per_tx_mJ"].mean(),
    "E_comm_per_tx_mJ_std": df_totals_per_run["E_comm_per_tx_mJ"].std(),
    "E_total_per_tx_mJ_mean": df_totals_per_run["E_total_per_tx_mJ"].mean(),
    "E_total_per_tx_mJ_std": df_totals_per_run["E_total_per_tx_mJ"].std(),
}

agg_with_total = pd.concat([agg, pd.DataFrame([total_row])], ignore_index=True)

print("\n=== Resumen con fila TOTAL ===")
print(agg_with_total)

# Guardar a CSV por si quieres llevártelo a LaTeX
out_path = os.path.join(ROOT_DIR, "phase_energy_stats_nodes200.csv")
agg_with_total.to_csv(out_path, index=False)
print(f"\nGuardado resumen en: {out_path}")
