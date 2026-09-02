"""Stable operation-coverage surface for transfer reference provenance.

The qualified platform and Behavioral-C package need to prove total semantic
operation coverage, but they do not execute the closure lattice.  Keeping this
small declaration separate prevents changes to callback/object provenance from
invalidating ISA qualification or faithful-C rendering.
"""

from __future__ import annotations

from .interpretation import DomainOperationCoverageV2, total_domain_coverage_v2


def reference_operation_coverage_v2() -> DomainOperationCoverageV2:
    # Every operation has a conservative transfer function.  Precision loss is
    # represented by unknown/conflict and blocks finite-target closure.
    return total_domain_coverage_v2("reference_provenance")
