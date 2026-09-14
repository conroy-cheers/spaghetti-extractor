"""Lightweight fixture API; developer tools are imported from their owners.

Importing a fixture must not import scaffolding or repository metadata: that
would make every fixture consumer depend on the entire production module index.
"""

from .diagnostics import Diagnostic, TestkitError
from .fixtures import FixtureCatalog, fixture
from .model import ImpactIndex, PlannedShard, SuitePlan, TestRecord

__all__ = [
    "Diagnostic",
    "FixtureCatalog",
    "ImpactIndex",
    "PlannedShard",
    "SuitePlan",
    "TestRecord",
    "TestkitError",
    "fixture",
]
