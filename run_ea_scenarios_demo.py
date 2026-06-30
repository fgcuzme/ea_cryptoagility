"""
Standalone demo to verify that the modules work before integrating with UWSNsecure.

Run:
    python run_ea_scenarios_demo.py

Output:
    stats/ea_demo_policy_events.csv
"""

from random import random, seed

from ea_cryptoagility.ea_logger import EAEventLogger
from ea_cryptoagility.ea_scenarios import SCENARIOS
from ea_cryptoagility.integration_hooks import attach_policy_to_transaction, log_ea_transaction

seed(1338)

POLICY_KEY = b"demo-policy-key"
logger = EAEventLogger("stats/ea_demo_policy_events.csv")

for sc_id, sc in SCENARIOS.items():
    for node_id in range(1, 11):
        node = {"NodeID": node_id, "Energy": 100.0 * sc.residual_energy_ratio, "E_init": 100.0, "Role": "SN"}

        # Choose message type using simple threshold over declared mix.
        # For deterministic experiments, replace with np.random.choice and seed.
        r = random()
        acc = 0.0
        msg = None
        for mt, prob in sc.message_mix.items():
            acc += prob
            if r <= acc:
                msg = mt
                break
        msg = msg or list(sc.message_mix.keys())[0]

        tx = {
            "ID": f"{sc_id}-{node_id}",
            "message_type": msg.value,
            "payload": "demo",
        }

        tx = attach_policy_to_transaction(
            tx=tx,
            node=node,
            epoch=1,
            key=POLICY_KEY,
            per=sc.per,
            retransmission_rate=sc.retransmission_rate,
            dag_load=sc.dag_load,
            security_risk=sc.security_risk,
            invalid_signature_rate=sc.invalid_signature_rate,
            downgrade_detected=sc.downgrade_detected,
            replay_detected=sc.replay_detected,
            suspicious_identity=sc.suspicious_identity,
        )

        log_ea_transaction(
            logger=logger,
            run_id="demo",
            seed=1337,
            scenario_id=sc_id,
            tx=tx,
            latency_ms=tx["ea_cost"]["t_air_s"] * 1000.0,
            pdr=max(0.0, 1.0 - sc.per),
            downgrade_injected=sc.downgrade_detected,
            invalid_policy_meta=False,
            invalid_tx_rejected=False,
        )

print("Demo complete: stats/ea_demo_policy_events.csv")
