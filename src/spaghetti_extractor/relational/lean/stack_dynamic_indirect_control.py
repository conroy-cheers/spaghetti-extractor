"""Classify stack/dynamic indirect-control frontiers without proof authority.

The analyzer consumes the exact mixed-original plan object and SHA-bound state
machine.  It emits precise static proposals and runtime proof obligations.  A
generated Lean module rechecks each exact indirect instruction against the
decoded-original authority; report statuses never authorize acceptance.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping, Protocol, Sequence

import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from ...errors import StageAInputError
from .original_indirect_control_authority import (
    OriginalIndirectControlAuthorityBinding,
    OriginalIndirectControlSiteSpec,
    OriginalTargetExpressionSpec,
)
from .nullable_code_pointer_table import (
    LoopFactsProposal,
    NullableCodePointerTableCertificateSpec,
    RvaRangeProposal,
)
from .stack_fixed_code_pointer import LeanStackAdjustment


STACK_DYNAMIC_INDIRECT_CONTROL_FORMAT = (
    "stage-a-stack-dynamic-indirect-control-proposal-v1"
)
STACK_DYNAMIC_INDIRECT_CONTROL_LEAN_FILENAME = (
    "GeneratedRelationalStackDynamicIndirectControl.lean"
)

_U32_LIMIT = 1 << 32
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_WRITE = 0x80000000


class StackDynamicIndirectControlError(StageAInputError):
    """The exact frontier input is malformed or cannot be classified."""


class _RegionInput(Protocol):
    target_id: int
    rva: int


class _IndirectSiteInput(Protocol):
    source_rva: int
    instruction_rva: int
    category: str
    is_call: bool
    continuation_rva: int | None
    target_expression: Mapping[str, Any] | None


class _AnalysisInput(Protocol):
    state_machine_sha256: str
    regions: Sequence[_RegionInput]
    indirect_sites: Sequence[_IndirectSiteInput]


@dataclass(frozen=True)
class StackDynamicBlocker:
    reason_code: str
    detail: str
    next_action: str

    def to_json(self) -> dict[str, str]:
        return {
            "detail": self.detail,
            "next_action": self.next_action,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class IndexedEmptyTableProposal:
    table_rva: int
    range_rva: int
    index_register: str
    lower_inclusive: int
    address_scale: int
    header_words: tuple[int, ...]

    def certificate(
        self,
        *,
        definition_name: str,
        pe_bytes: bytes,
        source_target_id: int,
        instruction_rva: int,
    ) -> NullableCodePointerTableCertificateSpec:
        return NullableCodePointerTableCertificateSpec(
            definition_name=definition_name,
            pe_bytes=pe_bytes,
            context_id=source_target_id,
            dispatch_rva=instruction_rva,
            table_rva=self.table_rva,
            header_words=self.header_words,
            caller_range=RvaRangeProposal(self.range_rva, self.range_rva),
            code_map=(),
            non_null_target_ids=(),
            edges=(),
            writers=(),
            aliases=(),
            loop=LoopFactsProposal(
                lower_inclusive=self.lower_inclusive,
                upper_exclusive=self.lower_inclusive,
                step=1,
                address_base_rva=self.range_rva,
                address_scale=self.address_scale,
                alignment=4,
            ),
            guard="nonzero",
        )


@dataclass(frozen=True)
class StackDynamicSiteFinding:
    stable_id: str
    source_target_id: int
    source_rva: int
    instruction_rva: int
    instruction_bytes: bytes
    continuation_target_id: int
    provenance_class: Literal[
        "stack_slot",
        "indexed_immutable_table",
        "dynamic_range_field",
    ]
    target: OriginalTargetExpressionSpec
    static_facts: Mapping[str, Any]
    indexed_empty_table: IndexedEmptyTableProposal | None
    blockers: tuple[StackDynamicBlocker, ...]

    @property
    def closed(self) -> bool:
        return not self.blockers

    def to_json(self) -> dict[str, Any]:
        return {
            "blockers": [item.to_json() for item in self.blockers],
            "closure_status": "closed" if self.closed else "incomplete",
            "continuation_target_id": self.continuation_target_id,
            "instruction_bytes": self.instruction_bytes.hex(),
            "instruction_rva": self.instruction_rva,
            "provenance_class": self.provenance_class,
            "source_rva": self.source_rva,
            "source_target_id": self.source_target_id,
            "stable_id": self.stable_id,
            "static_facts": dict(self.static_facts),
        }


@dataclass(frozen=True)
class StackDynamicIndirectControlPlan:
    original_pe_sha256: str
    state_machine_sha256: str
    original_pe_bytes: bytes
    findings: tuple[StackDynamicSiteFinding, ...]

    @property
    def complete(self) -> bool:
        return bool(self.findings) and all(item.closed for item in self.findings)

    def to_json(self) -> dict[str, Any]:
        return {
            "artifact_role": {
                "acceptance_authority": False,
                "lean_rechecks_exact_sites": True,
                "proposal_only": True,
                "runtime_membership_inferred": False,
            },
            "counts": {
                "closed": sum(item.closed for item in self.findings),
                "incomplete": sum(not item.closed for item in self.findings),
                "sites": len(self.findings),
            },
            "findings": [item.to_json() for item in self.findings],
            "format": STACK_DYNAMIC_INDIRECT_CONTROL_FORMAT,
            "inputs": {
                "original_pe_sha256": self.original_pe_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "status": "ready" if self.complete else "incomplete",
        }


@dataclass(frozen=True)
class _StateRow:
    rva: int
    instructions: tuple[Mapping[str, Any], ...]


def analyze_stack_dynamic_indirect_controls(
    original_pe: Path | str,
    state_machine: Path | str,
    plan: _AnalysisInput,
    *,
    remaining_source_rvas: Sequence[int] | None = None,
) -> StackDynamicIndirectControlPlan:
    """Classify each remaining memory-derived indirect-control site."""

    pe_path = Path(original_pe)
    state_path = Path(state_machine)
    pe_hash = _sha256(pe_path)
    state_hash = _sha256(state_path)
    if plan.state_machine_sha256 != state_hash:
        raise StackDynamicIndirectControlError(
            "mixed-original plan does not match the state-machine SHA-256"
        )
    pe = _open_pe(pe_path)
    rows = _load_rows(state_path)
    regions = {region.rva: region for region in plan.regions}
    target_by_rva = {region.rva: region.target_id for region in plan.regions}
    if len(target_by_rva) != len(plan.regions):
        raise StackDynamicIndirectControlError(
            "mixed-original regions have ambiguous canonical RVAs"
        )

    if remaining_source_rvas is None:
        cached_remaining = getattr(plan, "remaining_source_rvas", None)
        if cached_remaining is not None:
            remaining = {
                _u32(value, "cached remaining source RVA")
                for value in cached_remaining
            }
        else:
            remaining = {
                blocker.rva
                for blocker in plan.blockers
                if blocker.reason_code == "unresolved_indirect_control"
                and "stack_or_dynamic_pointer" in blocker.detail
                and blocker.rva is not None
            }
    else:
        remaining = {_u32(value, "remaining source RVA") for value in remaining_source_rvas}

    findings: list[StackDynamicSiteFinding] = []
    for site in sorted(
        (
            item
            for item in plan.indirect_sites
            if item.category == "stack_or_dynamic_pointer"
            and item.source_rva in remaining
        ),
        key=lambda item: (item.source_rva, item.instruction_rva),
    ):
        region = regions.get(site.source_rva)
        row = rows.get(site.source_rva)
        if region is None or row is None:
            raise StackDynamicIndirectControlError(
                f"site 0x{site.instruction_rva:x} has no exact source region"
            )
        continuation = site.continuation_rva
        if not site.is_call or continuation is None:
            raise StackDynamicIndirectControlError(
                f"site 0x{site.instruction_rva:x} is not an indirect call"
            )
        continuation_id = target_by_rva.get(continuation)
        if continuation_id is None:
            raise StackDynamicIndirectControlError(
                f"site 0x{site.instruction_rva:x} continuation is unmapped"
            )
        instruction_bytes = _checked_indirect_instruction(pe, row, site)
        provenance, target, facts, empty_table, blockers = _classify_site(
            pe, site
        )
        stable_payload = (
            f"{pe_hash}:{region.target_id}:{site.instruction_rva}:"
            f"{instruction_bytes.hex()}:{provenance}"
        )
        findings.append(StackDynamicSiteFinding(
            stable_id="stack-dynamic-" + hashlib.sha256(
                stable_payload.encode("ascii")
            ).hexdigest()[:20],
            source_target_id=region.target_id,
            source_rva=site.source_rva,
            instruction_rva=site.instruction_rva,
            instruction_bytes=instruction_bytes,
            continuation_target_id=continuation_id,
            provenance_class=provenance,
            target=target,
            static_facts=facts,
            indexed_empty_table=empty_table,
            blockers=blockers,
        ))

    missing = remaining - {item.source_rva for item in findings}
    if missing:
        rendered = ", ".join(f"0x{rva:x}" for rva in sorted(missing))
        raise StackDynamicIndirectControlError(
            f"remaining stack/dynamic sites are absent from the plan: {rendered}"
        )
    return StackDynamicIndirectControlPlan(
        pe_hash, state_hash, pe_path.read_bytes(), tuple(findings)
    )


def stack_dynamic_indirect_control_source(
    plan: StackDynamicIndirectControlPlan,
    binding: OriginalIndirectControlAuthorityBinding,
) -> str:
    """Emit exact-site checks; unresolved runtime facts remain absent."""

    binding.validate()
    definitions: list[str] = []
    checks: list[str] = []
    for index, finding in enumerate(plan.findings):
        name = f"generatedStackDynamicSite{index}"
        spec = OriginalIndirectControlSiteSpec(
            definition_name=name,
            source_target_id=finding.source_target_id,
            instruction_rva=finding.instruction_rva,
            instruction_bytes=finding.instruction_bytes,
            target=finding.target,
            transfer="call",
            continuation_target_id=finding.continuation_target_id,
        )
        definitions.append(spec.lean())
        checks.append(f"""theorem {name}Checked :
    {name}.checked {binding.context_name} = true := by
  decide +kernel

def {name}Evidence :
    CheckedOriginalIndirectControlSite {binding.context_name} := {{
  authority := {binding.authority_name}
  site := {name}
  checked := {name}Checked
}}

#print axioms {name}Checked""")
        if finding.indexed_empty_table is not None:
            table = finding.indexed_empty_table
            base_address = finding.target.base_address
            if base_address is None:
                raise AssertionError("indexed target lost its base address")
            authority_name = (
                f"generatedStackDynamicEmptyIndexedAuthority{index}"
            )
            checks.append(f"""def {authority_name} :
    CheckedEmptyIndexedSourceAuthority {binding.context_name} := {{
  decodedAuthority := {binding.authority_name}
  site := {name}
  siteChecked := {name}Checked
  indexRegister := .{table.index_register}
  baseAddress := {base_address}
  targetShape := by simp [{name}]
  lowerInclusive := {table.lower_inclusive}
  upperExclusive := {table.lower_inclusive}
  emptyInterval := rfl
}}

theorem {authority_name}NoRuntimeIndex :
    ∀ state, ¬ {authority_name}.RuntimeIndexBound state :=
  {authority_name}.noRuntimeIndex

theorem {authority_name}SourceUnreachable
    (reachable : ActualSourceReachability)
    (bound : {authority_name}.ReachabilityBound reachable) :
    SourceUninhabited reachable := by
  rintro ⟨world, state, reached⟩
  exact {authority_name}NoRuntimeIndex state (bound world state reached)

#print axioms {authority_name}NoRuntimeIndex
#print axioms {authority_name}SourceUnreachable""")
    return f"""import StageA.RelationalOriginalStackDynamicControlClosure
import {binding.dependency_module}

namespace {binding.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.StackDynamicIndirectControl
open StageA.Relational.OriginalStackDynamicControlClosure

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{chr(10).join(definitions)}

{chr(10).join(checks)}

end {binding.namespace}
"""


def write_stack_dynamic_indirect_control(
    output: Path | str,
    plan: StackDynamicIndirectControlPlan,
    binding: OriginalIndirectControlAuthorityBinding,
) -> tuple[Path, Path]:
    root = Path(output)
    report = root / "stack-dynamic-indirect-control-plan.json"
    lean = root / "StageA" / STACK_DYNAMIC_INDIRECT_CONTROL_LEAN_FILENAME
    lean.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lean.write_text(
        stack_dynamic_indirect_control_source(plan, binding), encoding="utf-8"
    )
    return report, lean


def _classify_site(
    pe: pefile.PE, site: _IndirectSiteInput
) -> tuple[
    Literal["stack_slot", "indexed_immutable_table", "dynamic_range_field"],
    OriginalTargetExpressionSpec,
    Mapping[str, Any],
    IndexedEmptyTableProposal | None,
    tuple[StackDynamicBlocker, ...],
]:
    expression = site.target_expression
    if not isinstance(expression, Mapping) or expression.get("op") != "load":
        raise StackDynamicIndirectControlError(
            f"site 0x{site.instruction_rva:x} has no exact load expression"
        )
    if expression.get("width") != 4:
        raise StackDynamicIndirectControlError(
            f"site 0x{site.instruction_rva:x} target is not one PE32 word"
        )
    address = expression.get("address")
    constant, registers, scaled = _address_terms(address)
    if len(registers) == 1 and not scaled and registers[0] in {"esp", "ebp"}:
        adjustment = _stack_adjustment(constant)
        return (
            "stack_slot",
            OriginalTargetExpressionSpec(
                "stack_read", registers[0], adjustment=adjustment
            ),
            {
                "stack_adjustment": {
                    "amount": adjustment.amount,
                    "kind": adjustment.kind,
                },
                "stack_register": registers[0],
            },
            None,
            (StackDynamicBlocker(
                "stack_value_provenance_missing",
                "the exact stack read is known, but no checked predecessor trace "
                "establishes the stored callable value across every intervening call",
                "prove the dominating stack write, each call-frame preservation "
                "summary, and slot non-aliasing in the mixed invariant",
            ),),
        )
    if not registers and len(scaled) == 1:
        register, scale = scaled[0]
        if not 0 <= constant < _U32_LIMIT:
            raise StackDynamicIndirectControlError("indexed table base overflows PE32")
        base_rva = constant - int(pe.OPTIONAL_HEADER.ImageBase)
        section = _section_for_rva(pe, base_rva, 8)
        if section is None:
            raise StackDynamicIndirectControlError(
                f"indexed table base 0x{constant:x} is outside the image"
            )
        flags = int(section.Characteristics)
        if flags & (_IMAGE_SCN_MEM_EXECUTE | _IMAGE_SCN_MEM_WRITE):
            raise StackDynamicIndirectControlError(
                f"indexed table base 0x{constant:x} is not immutable data"
            )
        first = _read_u32(pe, base_rva)
        second = _read_u32(pe, base_rva + 4)
        facts = {
            "address_scale": scale,
            "index_register": register,
            "section": bytes(section.Name).rstrip(b"\0").decode("ascii", "strict"),
            "table_base_rva": base_rva,
            "table_base_va": constant,
            "word_0": first,
            "word_1": second,
        }
        empty_table = None
        if first == 0xFFFFFFFF and second == 0 and scale == 4:
            empty_table = IndexedEmptyTableProposal(
                table_rva=base_rva,
                range_rva=base_rva + 4,
                index_register=register,
                lower_inclusive=1,
                address_scale=scale,
                header_words=(first,),
            )
            facts["checked_empty_interval_candidate"] = True
        elif first == 0xFFFFFFFF and second == 0:
            facts["checked_empty_interval_candidate"] = False
        return (
            "indexed_immutable_table",
            OriginalTargetExpressionSpec(
                "indexed_table",
                register,
                base_address=constant,
                scale=scale,
            ),
            facts,
            empty_table,
            (StackDynamicBlocker(
                "indexed_table_reachability_bound_missing",
                "the table bytes are immutable, but no checked predecessor "
                "closure proves every reachable runtime index belongs to the "
                "certified table range",
                "provide IndexedImmutableTableClaim.ReachabilityBound from the "
                "complete decoded predecessor graph; an empty interval then "
                "proves the call source unreachable",
            ),),
        )
    if len(registers) == 1 and not scaled:
        register = registers[0]
        if constant >= (1 << 31):
            raise StackDynamicIndirectControlError(
                "dynamic field has a negative or unrepresented signed offset"
            )
        return (
            "dynamic_range_field",
            OriginalTargetExpressionSpec(
                "dynamic_field", register, offset=constant
            ),
            {"base_register": register, "field_offset": constant},
            None,
            (StackDynamicBlocker(
                "dynamic_callback_registration_missing",
                "the exact field read is known, but no checked allocation and "
                "callback-registration event pairs the selected runtime value",
                "carry the allocation range and RegisteredCallbackPair through "
                "nested frames, then instantiate DynamicCallbackFieldRuntime",
            ),),
        )
    raise StackDynamicIndirectControlError(
        f"site 0x{site.instruction_rva:x} address expression is ambiguous"
    )


def _address_terms(
    expression: Any,
) -> tuple[int, list[str], list[tuple[str, int]]]:
    constants: list[int] = []
    registers: list[str] = []
    scaled: list[tuple[str, int]] = []

    def visit(value: Any) -> None:
        if not isinstance(value, Mapping):
            raise StackDynamicIndirectControlError("address term is not structured")
        op = value.get("op")
        if op == "add32":
            args = value.get("args")
            if not isinstance(args, Sequence) or isinstance(args, (str, bytes)):
                raise StackDynamicIndirectControlError("add32 has no operand list")
            for item in args:
                visit(item)
            return
        if op == "const":
            raw = value.get("value")
            constants.append(_u32(raw, "address constant"))
            return
        if op == "reg":
            name = value.get("name")
            if name not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
                raise StackDynamicIndirectControlError("unsupported address register")
            registers.append(str(name))
            return
        if op == "mul32":
            args = value.get("args")
            if not isinstance(args, Sequence) or len(args) != 2:
                raise StackDynamicIndirectControlError("mul32 is not binary")
            register = next(
                (item.get("name") for item in args
                 if isinstance(item, Mapping) and item.get("op") == "reg"),
                None,
            )
            scale = next(
                (item.get("value") for item in args
                 if isinstance(item, Mapping) and item.get("op") == "const"),
                None,
            )
            if register is None or scale not in {1, 2, 4, 8}:
                raise StackDynamicIndirectControlError(
                    "indexed address is not one register times an IA-32 SIB scale"
                )
            scaled.append((str(register), int(scale)))
            return
        raise StackDynamicIndirectControlError(f"unsupported address op: {op!r}")

    visit(expression)
    return sum(constants) % _U32_LIMIT, registers, scaled


def _stack_adjustment(value: int) -> LeanStackAdjustment:
    signed = value if value < (1 << 31) else value - _U32_LIMIT
    if signed == 0:
        return LeanStackAdjustment("identity")
    if signed > 0:
        return LeanStackAdjustment("add", signed)
    return LeanStackAdjustment("subtract", -signed)


def _checked_indirect_instruction(
    pe: pefile.PE, row: _StateRow, site: _IndirectSiteInput
) -> bytes:
    source = next(
        (item for item in row.instructions if item.get("rva") == site.instruction_rva),
        None,
    )
    if source is None or not isinstance(source.get("bytes"), str):
        raise StackDynamicIndirectControlError("indirect instruction bytes are absent")
    try:
        encoded = bytes.fromhex(str(source["bytes"]))
    except ValueError as error:
        raise StackDynamicIndirectControlError(
            "indirect instruction bytes are malformed"
        ) from error
    exact = bytes(pe.get_data(site.instruction_rva, len(encoded)))
    if exact != encoded:
        raise StackDynamicIndirectControlError(
            "state-machine instruction bytes do not match the PE"
        )
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    decoded = tuple(decoder.disasm(encoded, int(pe.OPTIONAL_HEADER.ImageBase) + site.instruction_rva))
    if len(decoded) != 1 or decoded[0].size != len(encoded):
        raise StackDynamicIndirectControlError("indirect instruction decode is ambiguous")
    instruction = decoded[0]
    if not instruction.group(capstone.CS_GRP_CALL) or len(instruction.operands) != 1:
        raise StackDynamicIndirectControlError("site is not one exact call")
    if instruction.operands[0].type == X86_OP_IMM:
        raise StackDynamicIndirectControlError("site is a direct call")
    if instruction.operands[0].type not in {X86_OP_MEM, X86_OP_REG}:
        raise StackDynamicIndirectControlError("call target operand is unsupported")
    return encoded


def _load_rows(path: Path) -> Mapping[int, _StateRow]:
    rows: dict[int, _StateRow] = {}
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise StackDynamicIndirectControlError(
                    f"state-machine line {line_number} is invalid JSON"
                ) from error
            original = row.get("original") if isinstance(row, Mapping) else None
            if not isinstance(original, Mapping):
                continue
            rva = original.get("rva_start")
            instructions = row.get("instructions")
            if not isinstance(rva, int) or not isinstance(instructions, list):
                continue
            if rva in rows:
                raise StackDynamicIndirectControlError(
                    f"duplicate state-machine source RVA 0x{rva:x}"
                )
            if not all(isinstance(item, Mapping) for item in instructions):
                raise StackDynamicIndirectControlError(
                    f"state-machine row 0x{rva:x} has malformed instructions"
                )
            rows[rva] = _StateRow(rva, tuple(instructions))
    return rows


def _section_for_rva(pe: pefile.PE, rva: int, size: int):
    if rva < 0 or size < 0:
        return None
    for section in pe.sections:
        start = int(section.VirtualAddress)
        span = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        if start <= rva and rva + size <= start + span:
            return section
    return None


def _read_u32(pe: pefile.PE, rva: int) -> int:
    section = _section_for_rva(pe, rva, 4)
    if section is None:
        raise StackDynamicIndirectControlError(f"RVA 0x{rva:x} is unmapped")
    data = bytes(pe.get_data(rva, 4))
    if len(data) != 4:
        raise StackDynamicIndirectControlError(f"RVA 0x{rva:x} is truncated")
    return int.from_bytes(data, "little")


def _open_pe(path: Path) -> pefile.PE:
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except (OSError, pefile.PEFormatError) as error:
        raise StackDynamicIndirectControlError("original is not a valid PE") from error
    if int(pe.OPTIONAL_HEADER.Magic) != 0x10B or int(pe.FILE_HEADER.Machine) != 0x14C:
        raise StackDynamicIndirectControlError("original must be x86 PE32")
    return pe


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise StackDynamicIndirectControlError(f"cannot read {path}") from error
    return digest.hexdigest()


def _u32(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < _U32_LIMIT:
        raise StackDynamicIndirectControlError(f"{field} must be an unsigned PE32 word")
    return value


__all__ = [
    "STACK_DYNAMIC_INDIRECT_CONTROL_FORMAT",
    "STACK_DYNAMIC_INDIRECT_CONTROL_LEAN_FILENAME",
    "StackDynamicBlocker",
    "IndexedEmptyTableProposal",
    "StackDynamicIndirectControlError",
    "StackDynamicIndirectControlPlan",
    "StackDynamicSiteFinding",
    "analyze_stack_dynamic_indirect_controls",
    "stack_dynamic_indirect_control_source",
    "write_stack_dynamic_indirect_control",
]
