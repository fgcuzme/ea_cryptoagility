from pathlib import Path
import pandas as pd

files = sorted(Path("results/EA_CryptoAgility/SC4_HIGH_RISK").glob("nodes_20/run_*/ea_policy_events_*.csv"))

for f in files:
    df = pd.read_csv(f)

    tampered = df[df["attack_label"] == "POLICY_TAMPERING"]
    rejected = tampered[tampered["invalid_tx_rejected"] == True]

    print(f)
    print("tampered:", len(tampered))
    print("rejected:", len(rejected))
    print("IRR:", len(rejected) / len(tampered) if len(tampered) else None)