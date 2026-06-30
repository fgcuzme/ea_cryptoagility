import os
import glob
import pandas as pd

# === Configuración ===
BASE_DIR = r"G:\Mi unidad\PhD_UMalaga\AÑO 7 2026\Utangle_code\results\nodes_20"
# BASE_DIR = r"C:\compilables_embed\results_W5_Sh0.5_1000m_per0.10\nodes_200"
# BASE_DIR = r"C:\compilables_embed\results_W5_Sh0.5_1000m_per0.15\nodes_200"
# BASE_DIR = r"C:\compilables_embed\results_W5_Sh0.5_1000m_per0.30\nodes_200"

N_RUNS = 1
SIM_DURATION_S = 600.0          # Ventana temporal simulada de la fase DATA

def load_transmissions_for_run(run_idx):
    run_dir = os.path.join(BASE_DIR, f"run_{run_idx}")
    print(run_dir)
    # busca el transmissions.csv dentro de la carpeta del run
    # candidates = glob.glob(os.path.join(run_dir, "*transmissions*.csv"))
    candidates = glob.glob(os.path.join(run_dir, "transmissions.csv"))
    if not candidates:
        raise FileNotFoundError(f"No transmissions.csv for run {run_idx}")
    return pd.read_csv(candidates[0])

rows = []

for r in range(1, N_RUNS + 1):
    df = load_transmissions_for_run(r)

    # Solo mensajes de transmisión (no recepción)
    df_tx = df[df["energy_event_type"].str.lower() == "tx"].copy()

    # A) Throughput bruto: todos los paquetes (SYNC + AUTH + DATA)
    gross_bits = df_tx["bits_sent"].sum()

    # B) Throughput útil: solo DATA con carga
    mask_data = df_tx["phase"].str.upper() == "DATA"
    if "payload_bits" in df_tx.columns:
        useful_bits = df_tx.loc[mask_data, "payload_bits"].sum()
    else:
        # Si no existe payload_bits, puedes aproximar con bits del paquete DATA
        useful_bits = df_tx.loc[mask_data, "bits_sent"].sum()

    R_gross = gross_bits / SIM_DURATION_S      # bps
    R_good  = useful_bits / SIM_DURATION_S     # bps
    efficiency = R_good / R_gross if R_gross > 0 else 0.0

    rows.append({
        "run_id": f"run_{r:02d}",
        "gross_bits": gross_bits,
        "useful_bits": useful_bits,
        "throughput_gross_bps": R_gross,
        "throughput_good_bps": R_good,
        "efficiency": efficiency
    })

throughput_df = pd.DataFrame(rows)
print("\n=== Throughput por run (200 nodos, 600 s) ===")
print(throughput_df.describe())

# Guardar para usar en gráficos o tablas
out_path = os.path.join(BASE_DIR, "throughput_200nodes_30runs.csv")
throughput_df.to_csv(out_path, index=False)
print(f"\nGuardado: {out_path}")
