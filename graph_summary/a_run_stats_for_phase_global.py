import os
import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# === Ajusta esta ruta a tu caso ===
BASE_ROOT = r"C:\compilables_embed\results_W5_Sh0.5_1000m\nodes_200"
N_RUNS = 30
num_nodes = 200

PHASES = {
    "sync": "_syn_per_node.csv",
    "auth": "_auth_per_node.csv",
    "data": "_data_per_node.csv",
}

def load_phase_run_energy(run_dir, pattern):
    """Carga un *_per_node.csv de una fase y devuelve totales de energía."""
    files = glob.glob(os.path.join(run_dir, f"*{pattern}"))
    if not files:
        return None
    df = pd.read_csv(files[0])

    # Suma sobre todos los nodos (columna transmissions está en número de TX)
    E_tx = df["energy_tx_j"].sum()
    E_rx = df["energy_rx_j"].sum()
    E_st = df["energy_standby_j"].sum()
    n_tx = df["transmissions"].sum()

    return {
        "n_tx": n_tx,
        "E_tx_J": E_tx,
        "E_rx_J": E_rx,
        "E_standby_J": E_st,
        "E_total_J": E_tx + E_rx + E_st,
    }

# === 1) Agregar resultados por fase y por run ===
rows = []
for run in range(1, N_RUNS + 1):
    run_dir = os.path.join(BASE_ROOT, f"run_{run:02d}")
    for phase, suffix in PHASES.items():
        vals = load_phase_run_energy(run_dir, suffix)
        if vals is None:
            continue
        vals["run"] = run
        vals["phase"] = phase
        rows.append(vals)

df_runs = pd.DataFrame(rows)

# === 2) Resumen por fase (media y std por run) ===
summary = (
    df_runs
    .groupby("phase")[["E_tx_J", "E_rx_J", "E_standby_J", "E_total_J"]]
    .agg(["mean", "std"])
)

print("\n=== Resumen por fase (J por run) ===")
print(summary)

# === 3) Figura: barras apiladas de energía por fase ===
phases_order = ["sync", "auth", "data"]
labels = ["Sync", "Auth", "Data"]

E_tx_mean = [summary.loc[p, ("E_tx_J", "mean")] for p in phases_order]
E_rx_mean = [summary.loc[p, ("E_rx_J", "mean")] for p in phases_order]
E_st_mean = [summary.loc[p, ("E_standby_J", "mean")] for p in phases_order]

x = np.arange(len(phases_order))

plt.figure()
plt.bar(x, E_tx_mean, label="TX")
plt.bar(x, E_rx_mean, bottom=E_tx_mean, label="RX")
bottom_st = np.array(E_tx_mean) + np.array(E_rx_mean)
plt.bar(x, E_st_mean, bottom=bottom_st, label="Standby")

plt.xticks(x, labels)
plt.ylabel("Energy per run [J]")
plt.title("Energy breakdown per phase (N=200, 30 runs, Scenario S1)")
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(BASE_ROOT,f"energy_breakdown_phases_{num_nodes}nodes_S1.png"), dpi=300)
plt.show()
