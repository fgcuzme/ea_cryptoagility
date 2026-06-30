"""
Example integration patch for UWSNsecure.

This file is not meant to replace the current simulation. It shows exactly where
to call EA-CryptoAgility before ingest_tx(...) or before transaction propagation.

Recommended placement:
    - before ingest_tx(RUN_ID, node, tx, ...)
    - before propagate_tx_to_ch(...)
    - before propagate_tx_to_sink_and_cluster(...)
    - before authenticate_nodes_to_ch(...), when a node creates its auth Tx

You can copy these snippets into simulation_test1_light.py / propagacionTx_light.py.
"""

from ea_cryptoagility.integration_hooks import (
    attach_policy_to_transaction,
    verify_transaction_policy,
    EAEventLogger,
    log_ea_transaction,
)

POLICY_KEY = b"replace-with-session-or-cluster-key"
EA_LOG = EAEventLogger("stats/ea_policy_events.csv")

def before_ingest_or_send_tx(RUN_ID, SEED, SCENARIO_ID, node, tx, epoch, per, ret_rate, dag_load, sr):
    # Infer message type from tx["message_type"]. Set explicitly if missing.
    tx.setdefault("message_type", "TELEMETRY")

    tx = attach_policy_to_transaction(
        tx=tx,
        node=node,
        epoch=epoch,
        key=POLICY_KEY,
        per=per,
        retransmission_rate=ret_rate,
        dag_load=dag_load,
        security_risk=sr,
        invalid_signature_rate=0.0,
        downgrade_detected=False,
        replay_detected=False,
    )

    # Now pass tx to your existing U-Tangle/DAG function:
    # ingest_tx(RUN_ID, node, tx, add_as_tip=True)

    log_ea_transaction(
        logger=EA_LOG,
        run_id=RUN_ID,
        seed=SEED,
        scenario_id=SCENARIO_ID,
        tx=tx,
        latency_ms=0.0,
        pdr=1.0,
    )
    return tx


def during_receive_or_validate_tx(receiver_node, tx, epoch):
    valid_policy = verify_transaction_policy(
        tx=tx,
        node=receiver_node,
        epoch=epoch,
        key=POLICY_KEY,
    )

    if not valid_policy:
        # Reject transaction or mark downgrade/policy-tampering attempt.
        tx["invalid_policy_meta"] = True
        return False

    # Continue with your current Ed25519/Ascon/DAG checks.
    return True
