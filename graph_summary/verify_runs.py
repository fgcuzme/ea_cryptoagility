from pathlib import Path
import pandas as pd

files = sorted(Path("results/EA_CryptoAgility").glob("*/nodes_20/run_1/ea_policy_events_*.csv"))

for f in files:
    df = pd.read_csv(f)
    print("\n", f)
    print("rows:", len(df))
    print("profiles:")
    print(df["profile_id"].value_counts(dropna=False))
    print("message types:")
    print(df["message_type"].value_counts(dropna=False))
    print("checkpoint rules:")
    print(df["checkpoint_rule"].value_counts(dropna=False))
    print("invalid_policy_meta:", df["invalid_policy_meta"].sum())
    print("invalid_tx_rejected:", df["invalid_tx_rejected"].sum())