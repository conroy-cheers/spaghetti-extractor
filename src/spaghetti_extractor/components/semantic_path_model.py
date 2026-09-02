# ruff: noqa: F401
"""Machine-derived finite path models for portable component refinement.

This module contains no target knowledge and accepts no expected behavior.  It
symbolically executes exact machine-IR summaries, replacing only explicitly
bound service events with shared symbolic responses.  The resulting path set
is consumed by CBMC to compare portable C against every represented machine
path.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .inductive_receipts import CheckedInductiveMachineReceiptV1
from .inductive_relation import InductiveCutpointRelationV1
from .inductive_source import InductiveSourcePlanV1
from .interface_ir import ProofKernelComponentInterface
from .machine_binding import MachineProjectionV1
from .semantic_arithmetic import (
    byte_view_offset as _byte_view_offset,
    simplify_logical_arithmetic as _simplify_logical_arithmetic,
)
from .semantic_path_errors import SemanticPathError, SemanticPathViolation
from .semantic_services import (
    BoundServiceEvent as _BoundServiceEvent,
    service_event_index as _service_event_index,
)


_TRANSFER_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_TRANSFER_FLAGS = ("cf", "zf", "sf", "of", "pf", "df", "af")

@dataclass

class _State:
    env: dict[str, dict[str, object]]
    flags: dict[str, dict[str, object]]
    memory: dict[str, dict[str, object]]
    entry_env: dict[str, dict[str, object]]
    entry_flags: dict[str, dict[str, object]]
    entry_memory: dict[str, dict[str, object]]
    guards: list[dict[str, object]]
    trace: list[dict[str, object]]
    visited: set[str]
    private_stack_writes: set[tuple[int, int]]
    pending_service_stack_writes: set[tuple[int, int]]
    service_argument_stack_writes: set[tuple[int, int]]

    def clone(self) -> "_State":
        return _State(
            copy.deepcopy(self.env),
            copy.deepcopy(self.flags),
            copy.deepcopy(self.memory),
            copy.deepcopy(self.entry_env),
            copy.deepcopy(self.entry_flags),
            copy.deepcopy(self.entry_memory),
            copy.deepcopy(self.guards),
            copy.deepcopy(self.trace),
            set(self.visited),
            set(self.private_stack_writes),
            set(self.pending_service_stack_writes),
            set(self.service_argument_stack_writes),
        )


@dataclass(frozen=True)
class _ExecutedUnit:
    semantics: Mapping[str, object]
    call_results: dict[tuple[int, str], dict[str, object]]
    edge_guards: dict[int, dict[str, object]]
    outcome: dict[str, object]
