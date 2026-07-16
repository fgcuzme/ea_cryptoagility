from pathlib import Path
import pandas as pd

files = sorted(Path("results/EA_CryptoAgility").glob("*/nodes_20/run_1/ea_policy_events_*.csv"))

for f in files:
    df = pd.read_csv(f)
    scenario = f.parts[-4]

    print("\n", scenario)
    print("rows:", len(df))
    print("\nProfiles:")
    print(df["profile_id"].value_counts())

    print("\nMean energy by profile:")
    print(df.groupby("profile_id")[[
        "tx_size_bytes",
        "crypto_energy_mj",
        "tx_energy_mj",
        "rx_energy_mj",
        "total_energy_mj",
        "latency_ms",
        "pdr"
    ]].mean(numeric_only=True))

    print("\nTotal energy by profile:")
    print(df.groupby("profile_id")[[
        "crypto_energy_mj",
        "tx_energy_mj",
        "rx_energy_mj",
        "total_energy_mj"
    ]].sum(numeric_only=True))