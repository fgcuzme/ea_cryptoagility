from ea_cryptoagility.ea_policy_engine import select_policy
from ea_cryptoagility.ea_types import CrossLayerState, MessageType
from ea_cryptoagility.ea_policy_metadata import build_policy_metadata, verify_policy_metadata

KEY = b"unit-test-policy-key"

def show(state):
    p = select_policy(state)
    m = build_policy_metadata(p, state, epoch=1, key=KEY)
    ok = verify_policy_metadata(m.as_dict(), p, state, epoch=1, key=KEY)
    print(state.message_type.value, state.per, state.residual_energy_j, 
          state.security_risk, state.dag_load, "=>", p.as_tuple(), "meta_ok=", ok)

if __name__ == "__main__":
    # SC1: normal telemetry -> S1
    show(CrossLayerState(node_id=1, message_type=MessageType.TELEMETRY, residual_energy_j=90, 
                         initial_energy_j=100, per=0.03, retransmission_rate=0.1, dag_load=0.2, security_risk=0.05))

    # SC2: low energy telemetry low risk -> S2
    show(CrossLayerState(node_id=1, message_type=MessageType.TELEMETRY, residual_energy_j=20, 
                         initial_energy_j=100, per=0.05, retransmission_rate=0.2, dag_load=0.2, security_risk=0.05))

    # SC3: emergency degraded channel -> S4
    show(CrossLayerState(node_id=1, message_type=MessageType.EMERGENCY_ALARM, residual_energy_j=70, 
                         initial_energy_j=100, per=0.30, retransmission_rate=3.0, dag_load=0.2, security_risk=0.1))

    # SC4: high risk -> S3
    show(CrossLayerState(node_id=1, message_type=MessageType.TELEMETRY, residual_energy_j=70, 
                         initial_energy_j=100, per=0.05, retransmission_rate=0.5, dag_load=0.2, security_risk=0.85, downgrade_detected=True))

    # SC5: high DAG load -> S1 batched
    show(CrossLayerState(node_id=1, message_type=MessageType.TELEMETRY, residual_energy_j=80, 
                         initial_energy_j=100, per=0.05, retransmission_rate=0.2, dag_load=0.95, security_risk=0.10))
