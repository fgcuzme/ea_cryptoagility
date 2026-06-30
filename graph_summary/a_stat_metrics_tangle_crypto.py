import pandas as pd
import numpy as np
import os

base_path = r"G:/Mi unidad/PhD_UMalaga/AÑO 7 2026/Utangle_code/nodes_20/run_1/"
num_nodes = 20

# === 1) Cargar eventos Tangle ===
df = pd.read_csv(os.path.join(base_path,f"tangle_events_light.csv"))

# Si tienes columna de run_id, perfecto. Si no, y está embebido en el nombre,
# puedes añadirla en el script que genera este CSV.
# Aquí asumimos que ya existe 'run_id' y 'node_id'.

# 2) Filtrar: solo autenticación, solo nodos != 0
df = df[df["phase"] == "auth"].copy()
df = df[df["node_id"] != 0].copy()

# 3) Quedarnos solo con columnas de tiempos que te interesan
time_cols = []
for cand in ["t_hash_ms", "t_canon_ms", "t_sign_ms", "t_verify_ms", "t_tipselect_ms"]:
    if cand in df.columns:
        time_cols.append(cand)

print("Usando columnas de tiempo:", time_cols)

# Asegurar numérico
for col in time_cols:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# === 4) Estadísticas GLOBALes (todas las runs, todos los nodos excepto sink) ===
def describe_times(x):
    return pd.Series({
        "count": len(x.dropna()),
        "mean_ms": x.mean(),
        "p50_ms": x.quantile(0.5),
        "p90_ms": x.quantile(0.9),
        "p99_ms": x.quantile(0.99),
        "min_ms": x.min(),
        "max_ms": x.max()
    })

global_stats = df[time_cols].apply(describe_times).T
print("\n=== Global crypto timings (all runs, all nodes != 0) ===")
print(global_stats)

global_stats.to_csv("tangle_crypto_global_stats.csv")

# === 5) Estadísticas por ejecución (para ver variabilidad entre runs) ===
per_run = (
    df
    .groupby("run_id")[time_cols]
    .agg(["mean", "median", "min", "max"])
)

per_run.to_csv("tangle_crypto_per_run_stats.csv")
print("\nGuardado: tangle_crypto_per_run_stats.csv")
