"""Emit exact nullable code-pointer-table proposals for Lean replay.

Python serializes bytes and finite context facts. The imported Lean checker
parses the PE, relocation directory, table words, and code map before proving
the requested acceptance or rejection equality.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ...errors import StageAInputError


NULLABLE_CODE_POINTER_TABLE_FORMAT = (
    "stage-a-relational-nullable-code-pointer-table-v1"
)
NULLABLE_CODE_POINTER_TABLE_LEAN_FILENAME = (
    "GeneratedRelationalNullableCodePointerTable.lean"
)

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_NAMESPACE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_U32_LIMIT = 1 << 32


class NullableCodePointerTableGenerationError(StageAInputError):
    """A proposal cannot be represented unambiguously in Lean."""


def _natural(value: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise NullableCodePointerTableGenerationError(
            f"{field} must be a natural number"
        )
    return value


def _word(value: int, field: str) -> int:
    result = _natural(value, field)
    if result >= _U32_LIMIT:
        raise NullableCodePointerTableGenerationError(
            f"{field} must fit in an unsigned 32-bit word"
        )
    return result


def _lean_list(values: tuple[object, ...], render) -> str:
    return "[" + ", ".join(render(value) for value in values) + "]"


def _lean_bytes(data: bytes) -> str:
    rows = [
        ", ".join(str(value) for value in data[offset : offset + 32])
        for offset in range(0, len(data), 32)
    ]
    if not rows:
        return "[]"
    return "[\n    " + ",\n    ".join(rows) + "\n  ]"


@dataclass(frozen=True)
class RvaRangeProposal:
    start_rva: int
    end_rva: int

    def lean(self, field: str = "RVA range") -> str:
        start = _word(self.start_rva, f"{field} start")
        end = _word(self.end_rva, f"{field} end")
        return f"{{ startRva := {start}, endRva := {end} }}"


@dataclass(frozen=True)
class CodeTargetProposal:
    target_id: int
    rva: int

    def lean(self) -> str:
        target_id = _natural(self.target_id, "code target id")
        rva = _word(self.rva, "code target RVA")
        return f"{{ targetId := {target_id}, rva := {rva} }}"


@dataclass(frozen=True)
class DispatchEdgeProposal:
    source_context_id: int
    target_id: int

    def lean(self) -> str:
        source = _natural(self.source_context_id, "edge source context id")
        target = _natural(self.target_id, "edge target id")
        return f"{{ sourceContextId := {source}, targetId := {target} }}"


@dataclass(frozen=True)
class TableWriterProposal:
    source_rva: int
    written_range: RvaRangeProposal

    def lean(self) -> str:
        source = _word(self.source_rva, "writer source RVA")
        return (
            f"{{ sourceRva := {source}, writtenRange := "
            f"{self.written_range.lean('writer range')} }}"
        )


@dataclass(frozen=True)
class TableAliasProposal:
    alias_rva: int
    canonical_rva: int

    def lean(self) -> str:
        alias = _word(self.alias_rva, "alias RVA")
        canonical = _word(self.canonical_rva, "canonical RVA")
        return f"{{ aliasRva := {alias}, canonicalRva := {canonical} }}"


@dataclass(frozen=True)
class LoopFactsProposal:
    lower_inclusive: int
    upper_exclusive: int
    step: int
    address_base_rva: int
    address_scale: int = 4
    alignment: int = 4

    def lean(self) -> str:
        values = {
            "lowerInclusive": _natural(
                self.lower_inclusive, "loop lower bound"
            ),
            "upperExclusive": _natural(
                self.upper_exclusive, "loop upper bound"
            ),
            "step": _natural(self.step, "loop step"),
            "addressBaseRva": _word(
                self.address_base_rva, "loop address base RVA"
            ),
            "addressScale": _natural(
                self.address_scale, "loop address scale"
            ),
            "alignment": _natural(self.alignment, "loop alignment"),
        }
        return "{ " + ", ".join(
            f"{name} := {value}" for name, value in values.items()
        ) + " }"


@dataclass(frozen=True)
class NullableCodePointerTableCertificateSpec:
    definition_name: str
    pe_bytes: bytes
    context_id: int
    dispatch_rva: int
    table_rva: int
    header_words: tuple[int, ...]
    caller_range: RvaRangeProposal | None
    code_map: tuple[CodeTargetProposal, ...] | None
    non_null_target_ids: tuple[int, ...] | None
    edges: tuple[DispatchEdgeProposal, ...] | None
    writers: tuple[TableWriterProposal, ...] | None
    aliases: tuple[TableAliasProposal, ...] | None
    loop: LoopFactsProposal | None
    guard: Literal["nonzero", "zero"] | None
    namespace: str = (
        "StageA.Generated.RelationalNullableCodePointerTable"
    )

    def validate(self) -> None:
        if _IDENTIFIER.fullmatch(self.definition_name) is None:
            raise NullableCodePointerTableGenerationError(
                "certificate definition name is not a Lean identifier"
            )
        if _NAMESPACE.fullmatch(self.namespace) is None:
            raise NullableCodePointerTableGenerationError(
                "certificate namespace is not a Lean namespace"
            )
        if not isinstance(self.pe_bytes, bytes):
            raise NullableCodePointerTableGenerationError(
                "PE bytes must be an immutable bytes value"
            )
        _natural(self.context_id, "context id")
        _word(self.dispatch_rva, "dispatch RVA")
        _word(self.table_rva, "table RVA")
        for index, value in enumerate(self.header_words):
            _word(value, f"header word {index}")
        if self.guard not in {None, "nonzero", "zero"}:
            raise NullableCodePointerTableGenerationError(
                f"unsupported guard kind: {self.guard!r}"
            )

    def lean(self) -> str:
        self.validate()

        def knowledge(value: object | None, render) -> str:
            return ".unknown" if value is None else f".exact {render(value)}"

        header = _lean_list(self.header_words, lambda value: str(
            _word(value, "header word")
        ))
        code_map = knowledge(
            self.code_map,
            lambda rows: _lean_list(rows, lambda row: row.lean()),
        )
        target_ids = knowledge(
            self.non_null_target_ids,
            lambda rows: _lean_list(
                rows, lambda value: str(_natural(value, "non-null target id"))
            ),
        )
        edges = knowledge(
            self.edges,
            lambda rows: _lean_list(rows, lambda row: row.lean()),
        )
        writers = knowledge(
            self.writers,
            lambda rows: _lean_list(rows, lambda row: row.lean()),
        )
        aliases = knowledge(
            self.aliases,
            lambda rows: _lean_list(rows, lambda row: row.lean()),
        )
        loop = knowledge(self.loop, lambda value: value.lean())
        guard = knowledge(self.guard, lambda value: f".{value}")
        caller_range = knowledge(
            self.caller_range, lambda value: value.lean("caller range")
        )
        return f"""def {self.definition_name}Bytes : Bytes := {_lean_bytes(self.pe_bytes)}

def {self.definition_name} : Certificate := {{
  peBytes := {self.definition_name}Bytes
  contextId := {self.context_id}
  dispatchRva := {self.dispatch_rva}
  tableRva := {self.table_rva}
  headerWords := {header}
  callerRange := {caller_range}
  codeMap := {code_map}
  nonNullTargetIds := {target_ids}
  edges := {edges}
  writers := {writers}
  aliases := {aliases}
  loop := {loop}
  guard := {guard}
}}"""


# Short alias for callers that do not need the longer artifact name.
NullableCodePointerTableSpec = NullableCodePointerTableCertificateSpec


def nullable_code_pointer_table_source(
    spec: NullableCodePointerTableCertificateSpec,
    *,
    expectation: Literal["unreachable", "accepted", "rejected"] = "unreachable",
) -> str:
    """Render one proposal and kernel proof obligations.

    ``expectation`` selects the proposition emitted into Lean. It is not an
    acceptance result computed by Python.
    """

    spec.validate()
    if expectation not in {"unreachable", "accepted", "rejected"}:
        raise NullableCodePointerTableGenerationError(
            f"unsupported certificate expectation: {expectation!r}"
        )
    checked_value = "false" if expectation == "rejected" else "true"
    theorem_name = f"{spec.definition_name}Checked"
    obligations = f"""theorem {theorem_name} :
    {spec.definition_name}.checked = {checked_value} := by
  decide +kernel

#print axioms {theorem_name}
"""
    if expectation == "unreachable":
        unreachable_name = f"{spec.definition_name}IndirectDispatchUnreachable"
        semantic_name = f"{spec.definition_name}NoIndirectDispatch"
        obligations += f"""
theorem {unreachable_name} :
    {spec.definition_name}.indirectDispatchUnreachable = true := by
  decide +kernel

theorem {semantic_name} :
    ¬ {spec.definition_name}.IndirectDispatchReachable :=
  {spec.definition_name}.noIndirectDispatch_of_unreachable {unreachable_name}

#print axioms {unreachable_name}
#print axioms {semantic_name}
"""
    elif expectation == "rejected":
        unreachable_name = f"{spec.definition_name}DoesNotCertifyUnreachable"
        obligations += f"""
theorem {unreachable_name} :
    {spec.definition_name}.indirectDispatchUnreachable = false := by
  decide +kernel

#print axioms {unreachable_name}
"""

    return f"""import StageA.RelationalNullableCodePointerTable

namespace {spec.namespace}

open StageA.Formal
open StageA.Relational.NullableCodePointerTable

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{spec.lean()}

{obligations}
end {spec.namespace}
"""


def write_nullable_code_pointer_table_module(
    output: Path | str,
    spec: NullableCodePointerTableCertificateSpec,
    *,
    expectation: Literal["unreachable", "accepted", "rejected"] = "unreachable",
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        nullable_code_pointer_table_source(spec, expectation=expectation),
        encoding="utf-8",
    )
    return path
