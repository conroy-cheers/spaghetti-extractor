"""Stable Stage A orchestration API.

All proof-capable entry points in this module are Nix coordinators. The
individual Python phase implementations are derivation workers and are not a
supported host-side build interface.
"""

from .build import stage_a_build_relational
from .nix_pipeline import (
    stage_a_prepare_relational_nix,
    stage_a_prove_relational_nix,
)
from .pipeline import stage_a_check_relational_proof


stage_a_prepare_relational = stage_a_prepare_relational_nix
stage_a_prove_relational = stage_a_prove_relational_nix

__all__ = [
    "stage_a_build_relational",
    "stage_a_check_relational_proof",
    "stage_a_prepare_relational",
    "stage_a_prove_relational",
]
