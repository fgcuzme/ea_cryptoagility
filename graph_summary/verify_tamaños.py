from pathlib import Path
import pandas as pd

files = sorted(Path("results/EA_CryptoAgility").glob("*/nodes_20/run_1/ea_policy_events_*.csv"))

for f in files:
    df = pd.read_csv(f)
    scenario = f.parts[-4]

    print("\n", scenario)
    print(
        df.groupby(["message_type", "profile_id"])[
            ["tx_size_bytes", "crypto_energy_mj", "total_energy_mj"]
        ].mean(numeric_only=True)
    )
    
L_MAX_REGULAR = 256
L_MAX_HIGH_RISK = 300

files = sorted(Path("results/EA_CryptoAgility").glob("*/nodes_20/run_1/ea_policy_events_*.csv"))

for f in files:
    df = pd.read_csv(f)
    scenario = f.parts[-4]

    def allowed_lmax(row):
        if row["profile_id"] == "S3":
            return L_MAX_HIGH_RISK
        return L_MAX_REGULAR

    df["allowed_lmax"] = df.apply(allowed_lmax, axis=1)
    over = df[df["tx_size_bytes"] > df["allowed_lmax"]]

    print("\n", scenario)
    print("max tx_size_bytes:", df["tx_size_bytes"].max())

    if len(over) > 0:
        print("WARNING: packets above allowed Lmax")
        print(
            over[
                ["message_type", "profile_id", "tx_size_bytes", "allowed_lmax"]
            ].head()
        )
    else:
        print("OK: all packets within profile-specific Lmax")