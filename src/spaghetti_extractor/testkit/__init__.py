"""Ergonomic, content-addressed test planning toolkit."""

from .diagnostics import Diagnostic, TestkitError
from .discovery import build_impact_index
from .doctor import DoctorReport, run_doctor
from .fixtures import FixtureCatalog, fixture
from .model import ImpactIndex, PlannedShard, SuitePlan, TestRecord
from .planning import build_suite_plan, changed_paths_from_git
from .rebuild import explain_index_rebuild, explain_plan_rebuild
from .scaffold import (
    apply_scaffold_plan,
    ScaffoldPlan,
    plan_fixture_scaffold,
    plan_phase_scaffold,
    plan_test_scaffold,
)

__all__ = [
    "Diagnostic",
    "DoctorReport",
    "FixtureCatalog",
    "ImpactIndex",
    "PlannedShard",
    "ScaffoldPlan",
    "SuitePlan",
    "TestRecord",
    "TestkitError",
    "build_impact_index",
    "build_suite_plan",
    "changed_paths_from_git",
    "explain_index_rebuild",
    "explain_plan_rebuild",
    "fixture",
    "plan_fixture_scaffold",
    "apply_scaffold_plan",
    "plan_phase_scaffold",
    "plan_test_scaffold",
    "run_doctor",
]
