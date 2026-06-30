# EA-CryptoAgility U-Tangle Modules

These modules extend `fgcuzme/UWSNsecure` with the proposed energy-aware cryptographic agility mechanism for the second paper.

## Why this integrates with UWSNsecure

The public UWSNsecure repository is a Python simulator for lightweight Tangle authentication and ASCON-based data protection. It already includes files for energy, acoustic propagation, PER/SNR, clustering, Tangle, synchronization, transmission summaries, and batch runs. The new modules therefore add only the missing layer:

```text
cross-layer state → policy engine → S0-S4 profile → policy metadata → DAG validation/logging
```

## Files

```text
ea_cryptoagility/
  __init__.py
  ea_types.py
  ea_profiles.py
  ea_policy_engine.py
  ea_policy_metadata.py
  ea_crypto_costs.py
  ea_scenarios.py
  ea_logger.py
  ea_metrics.py
  integration_hooks.py
  run_policy_unit_test.py

example_integration_patch.py
run_ea_scenarios_demo.py
```

## First test

Copy the folder into the root of UWSNsecure and run:

```bash
python -m ea_cryptoagility.run_policy_unit_test
python run_ea_scenarios_demo.py
```

Expected policy behavior:

```text
SC1_NORMAL             → S1 / PERIODIC
SC2_LOW_ENERGY         → S2 / DELAYED_OR_BATCHED
SC3_DEGRADED_CHANNEL   → S2 for telemetry, S4 for emergency
SC4_HIGH_RISK          → S3 / STRICT
SC5_DAG_CONGESTION     → S1 / BATCHED
```

## Integration points

### 1. Before transaction creation/ingestion

Before calling `ingest_tx(...)`, `propagate_tx_to_ch(...)`, or any function that sends a transaction, call:

```python
from ea_cryptoagility.integration_hooks import attach_policy_to_transaction

tx = attach_policy_to_transaction(
    tx=tx,
    node=node_uw[i],
    epoch=current_epoch,
    key=POLICY_KEY,
    per=PER_i,
    retransmission_rate=Ret_i,
    dag_load=D_i,
    security_risk=SR_i,
)
```

This adds:

```python
tx["Policy"]
tx["policy_meta"]
tx["ea_state"]
tx["ea_cost"]
```

### 2. During validation

When a node receives a transaction:

```python
from ea_cryptoagility.integration_hooks import verify_transaction_policy

if not verify_transaction_policy(tx, receiver_node, epoch=current_epoch, key=POLICY_KEY):
    reject_transaction()
```

### 3. Logging

```python
from ea_cryptoagility.integration_hooks import EAEventLogger, log_ea_transaction

logger = EAEventLogger(f"{output_dir}/ea_policy_events.csv")
log_ea_transaction(logger, RUN_ID, SEED, SCENARIO_ID, tx, latency_ms=lat, pdr=pdr)
```

## Calibration

`ea_crypto_costs.py` contains placeholder cryptographic energy values. For the paper, replace them with Raspberry Pi microbenchmark values:

```text
ASCON_AEAD_ENC
ASCON_AEAD_DEC
ED25519_SIGN
ED25519_VERIFY
X25519
POLICY_MAC
CHECKPOINT_HASH
```

Then compute:

```text
E_crypto = P_cpu × t_op
```

## Recommended paper simulations

Use UWSNsecure as the main simulator and Aqua-Sim-ng only for optional acoustic trace validation.

Scenarios:

```text
SC1_NORMAL
SC2_LOW_ENERGY
SC3_DEGRADED_CHANNEL
SC4_HIGH_RISK
SC5_DAG_CONGESTION
```

Main metrics:

```text
profile distribution
energy per transaction
latency
PDR
crypto operation counts
tx_size_bytes
policy_meta_bytes
downgrade_detection_rate
invalid_tx_rejection_rate
DAG confirmation delay
```

## Notes

- Do not implement the DAG in Aqua-Sim-ng for this paper; it will delay the work.
- Use UWSNsecure for DAG + crypto + energy-policy experiments.
- Use Raspberry Pi for crypto microbenchmarks, not necessarily for all full-network runs.
