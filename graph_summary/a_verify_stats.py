import pandas as pd
import os

base_dir = r"G:\Mi unidad\PhD_UMalaga\AÑO 7 2026\Utangle_code\results\nodes_20\run_1"
file_name = "1200km_W7_Sh0.7_seed1337_run01_syn_per_node.csv"

auth_df = pd.read_csv(os.path.join(base_dir, file_name))


# Verificar totales
print("Authentication Phase:")
print(f"  TX Events: {auth_df['transmissions'].sum()}")
print(f"  E_TX Total: {auth_df['energy_tx_j'].sum():.2f} J")
print(f"  E_RX Total: {auth_df['energy_rx_j'].sum():.2f} J")
print(f"  E_Standby Total: {auth_df['energy_standby_j'].sum():.2f} J")

total_e = (auth_df['energy_tx_j'].sum() + 
           auth_df['energy_rx_j'].sum() + 
           auth_df['energy_standby_j'].sum())
print(f"  Total: {total_e:.2f} J")

# Per-event
n_tx = auth_df['transmissions'].sum()
print(f"\nPer-event (mJ):")
print(f"  E_TX: {auth_df['energy_tx_j'].sum() / n_tx * 1000:.2f} mJ")
print(f"  E_RX: {auth_df['energy_rx_j'].sum() / n_tx * 1000:.2f} mJ")
print(f"  E_Standby: {auth_df['energy_standby_j'].sum() / n_tx * 1000:.2f} mJ")
print(f"  Total: {total_e / n_tx * 1000:.2f} mJ")
