import pandas as pd

# Ruta al transmissions.csv consolidado (todas las runs del escenario S1, N=200)
csv_path = r"C:\compilables_embed\results_W5_Sh0.5_1000m\datos_30_runs_consolidados_200.csv"

df = pd.read_csv(csv_path)

# Filtro a solo TX
df_tx = df[df["energy_event_type"] == "TX"].copy()

# --- Si NO tienes duración explícita, la calculamos por run ---
# suponiendo columna 'sim_time_s' o similar
if "timestamp_iso" in df_tx.columns:
    dur_by_run = df_tx.groupby("run_id")["timestamp_iso"].agg(["min", "max"])
    dur_by_run["duration_s"] = dur_by_run["max"] - dur_by_run["min"]
else:
    # si ya tienes 'sim_duration_s' en alguna tabla global, lo podrías leer allí
    raise RuntimeError("Añade aquí cómo obtener la duración de cada run")

# Para comodidad, hacemos un dict run_id -> duration_s
dur_map = dur_by_run["duration_s"].to_dict()

rows = []
for run_id, g in df_tx.groupby("run_id"):

    duration_s = dur_map[run_id]

    # Throughput bruto: todos los bits TX
    bits_gross = g["bits"].sum()

    # Throughput útil: solo DATA exitosos
    mask_data_ok = (g["phase"] == "DATA") & (g["success"] == 1)
    bits_useful = g.loc[mask_data_ok, "bits"].sum()

    T_gross = bits_gross / duration_s   # bps
    T_useful = bits_useful / duration_s # bps
    eta = T_useful / T_gross if T_gross > 0 else 0.0

    rows.append({
        "run_id": run_id,
        "duration_s": duration_s,
        "bits_gross": bits_gross,
        "bits_useful": bits_useful,
        "T_gross_bps": T_gross,
        "T_useful_bps": T_useful,
        "efficiency": eta
    })

throughput_runs = pd.DataFrame(rows)
print(throughput_runs.head())

# Promedio en 30 runs (para tabla)
summary = throughput_runs[["T_gross_bps","T_useful_bps","efficiency"]].agg(["mean","std"])
print("\nResumen 30 runs:")
print(summary)
