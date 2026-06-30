"""
EA-CryptoAgility integration package for UWSNsecure / U-Tangle simulations.

This package implements:
- Cross-layer state representation
- Energy-aware cryptographic policy selection
- S0-S4 profile definitions
- Policy metadata generation and verification
- Crypto/communication cost estimation
- Scenario definitions for paper experiments
- CSV event logging
- Integration hooks for dict-based UWSNsecure transactions
"""

from .ea_types import (
    MessageType, ProfileID, CheckpointRule, RekeyRule, PayloadMode,
    Thresholds, CrossLayerState, PolicyTuple, PolicyMetadata
)
from .ea_policy_engine import select_policy, compute_energy_pressure, compute_security_risk
from .ea_policy_metadata import build_policy_metadata, verify_policy_metadata
