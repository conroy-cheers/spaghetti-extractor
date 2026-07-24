"""Emit one-sided original indirect-control authority terms.

The emitter serializes finite proposals and names existing exact original
contexts.  Generated Lean rechecks instruction bytes, decoded behavior, PE
relocations/imports, nullable tables, and finite target inventories.  Runtime
stack/dynamic/callback membership remains a typed Lean premise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ...errors import StageAInputError
from .interpreter_mixed_original import OriginalImportIdentity
from .stack_fixed_code_pointer import LeanStackAdjustment


ORIGINAL_INDIRECT_CONTROL_AUTHORITY_FORMAT = (
    "stage-a-original-indirect-control-authority-v1"
)
ORIGINAL_INDIRECT_CONTROL_AUTHORITY_LEAN_FILENAME = (
    "GeneratedRelationalOriginalIndirectControlAuthority.lean"
)

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_QUALIFIED = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_REGISTERS = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
_U32_LIMIT = 1 << 32


class OriginalIndirectControlAuthorityGenerationError(StageAInputError):
    """A finite authority proposal cannot be represented unambiguously."""


def _natural(value: int, field: str, *, word: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OriginalIndirectControlAuthorityGenerationError(
            f"{field} must be a natural number"
        )
    if word and value >= _U32_LIMIT:
        raise OriginalIndirectControlAuthorityGenerationError(
            f"{field} must fit in an unsigned PE32 word"
        )
    return value


def _name(value: str, field: str, *, identifier: bool = False) -> str:
    pattern = _IDENTIFIER if identifier else _QUALIFIED
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise OriginalIndirectControlAuthorityGenerationError(
            f"{field} is not a valid Lean name"
        )
    return value


def _register(value: str, field: str) -> str:
    if value not in _REGISTERS:
        raise OriginalIndirectControlAuthorityGenerationError(
            f"{field} is not a supported IA-32 register"
        )
    return value


def _lean_bytes(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise OriginalIndirectControlAuthorityGenerationError(
            "instruction bytes must be immutable bytes"
        )
    return "[" + ", ".join(str(value) for value in data) + "]"


def _lean_ascii(data: str, field: str) -> str:
    if not data or not data.isascii():
        raise OriginalIndirectControlAuthorityGenerationError(
            f"{field} must be nonempty ASCII"
        )
    return _lean_bytes(data.encode("ascii"))


def _lean_import_identity(identity: OriginalImportIdentity) -> str:
    dll = _lean_ascii(identity.dll, "import DLL")
    if identity.symbol is not None:
        imported = f"(.symbol {_lean_ascii(identity.symbol, 'import symbol')})"
    else:
        imported = f"(.ordinal {_natural(identity.ordinal or 0, 'import ordinal')})"
    return f"{{ dll := {dll}, name := {imported} }}"


@dataclass(frozen=True)
class OriginalTargetExpressionSpec:
    kind: Literal["register", "stack_read", "dynamic_field", "indexed_table"]
    register: str
    adjustment: LeanStackAdjustment | None = None
    offset: int | None = None
    base_address: int | None = None
    scale: int | None = None

    def lean(self) -> str:
        register = _register(self.register, "target register")
        if self.kind == "register":
            if any(value is not None for value in (
                self.adjustment, self.offset, self.base_address, self.scale
            )):
                raise OriginalIndirectControlAuthorityGenerationError(
                    "register target has extraneous address fields"
                )
            return f".register .{register}"
        if self.kind == "stack_read":
            if self.adjustment is None:
                raise OriginalIndirectControlAuthorityGenerationError(
                    "stack target requires an adjustment"
                )
            if any(value is not None for value in (
                self.offset, self.base_address, self.scale
            )):
                raise OriginalIndirectControlAuthorityGenerationError(
                    "stack target has extraneous address fields"
                )
            return f".stackRead .{register} {self.adjustment.lean()}"
        if self.kind == "dynamic_field":
            if self.offset is None:
                raise OriginalIndirectControlAuthorityGenerationError(
                    "dynamic target requires a field offset"
                )
            if any(value is not None for value in (
                self.adjustment, self.base_address, self.scale
            )):
                raise OriginalIndirectControlAuthorityGenerationError(
                    "dynamic target has extraneous address fields"
                )
            return f".dynamicField .{register} {_natural(self.offset, 'field offset')}"
        if self.kind == "indexed_table":
            if self.base_address is None or self.scale is None:
                raise OriginalIndirectControlAuthorityGenerationError(
                    "indexed-table target requires a base and scale"
                )
            if self.adjustment is not None or self.offset is not None:
                raise OriginalIndirectControlAuthorityGenerationError(
                    "indexed-table target has extraneous address fields"
                )
            if self.scale not in {1, 2, 4, 8}:
                raise OriginalIndirectControlAuthorityGenerationError(
                    "indexed-table scale must be one of the IA-32 SIB scales"
                )
            return (
                f".indexedTable {_natural(self.base_address, 'table base', word=True)} "
                f".{register} {_natural(self.scale, 'table scale')}"
            )
        raise OriginalIndirectControlAuthorityGenerationError(
            f"unsupported target-expression kind: {self.kind!r}"
        )


@dataclass(frozen=True)
class OriginalIndirectControlSiteSpec:
    definition_name: str
    source_target_id: int
    instruction_rva: int
    instruction_bytes: bytes
    target: OriginalTargetExpressionSpec
    transfer: Literal["call", "jump"]
    continuation_target_id: int | None = None

    def lean(self) -> str:
        name = _name(self.definition_name, "site definition", identifier=True)
        source = _natural(self.source_target_id, "source target id")
        rva = _natural(self.instruction_rva, "instruction RVA", word=True)
        encoded = _lean_bytes(self.instruction_bytes)
        if not self.instruction_bytes:
            raise OriginalIndirectControlAuthorityGenerationError(
                "indirect instruction bytes must be nonempty"
            )
        if self.transfer == "call":
            if self.continuation_target_id is None:
                raise OriginalIndirectControlAuthorityGenerationError(
                    "indirect call requires a continuation target"
                )
            transfer = (
                f".call {_natural(self.continuation_target_id, 'continuation target id')}"
            )
        elif self.transfer == "jump":
            if self.continuation_target_id is not None:
                raise OriginalIndirectControlAuthorityGenerationError(
                    "indirect jump cannot carry a continuation target"
                )
            transfer = ".jump"
        else:
            raise OriginalIndirectControlAuthorityGenerationError(
                f"unsupported transfer kind: {self.transfer!r}"
            )
        return f"""def {name} : OriginalIndirectControlSite := {{
  sourceTargetId := {source}
  instructionRva := {rva}
  instructionBytes := {encoded}
  target := {self.target.lean()}
  transfer := {transfer}
}}"""


@dataclass(frozen=True)
class RelocatedCodePointerSeedSpec:
    definition_name: str
    slot_rva: int
    target_id: int

    def lean(self) -> str:
        name = _name(self.definition_name, "seed definition", identifier=True)
        return f"""def {name} : RelocatedCodePointerSeed := {{
  slotRva := {_natural(self.slot_rva, 'seed slot RVA', word=True)}
  targetId := {_natural(self.target_id, 'seed target id')}
}}"""


@dataclass(frozen=True)
class NullableTableControlSpec:
    definition_name: str
    site_name: str
    table_certificate_name: str

    def lean(self) -> str:
        name = _name(self.definition_name, "nullable claim definition", identifier=True)
        site = _name(self.site_name, "nullable site name")
        table = _name(self.table_certificate_name, "table certificate name")
        return f"""def {name} : NullableTableControlClaim := {{
  site := {site}
  table := {table}
}}"""


@dataclass(frozen=True)
class SavedImportControlSpec:
    definition_name: str
    save_source_target_id: int
    restore_source_target_id: int
    site_name: str
    binding_source_target_id: int
    binding_instruction_rva: int
    iat_va: int
    iat_rva: int
    identity: OriginalImportIdentity
    stack_register: str
    stack_adjustment: LeanStackAdjustment
    target_register: str

    def lean(self) -> str:
        name = _name(self.definition_name, "saved-import definition", identifier=True)
        site = _name(self.site_name, "saved-import site name")
        stack = _register(self.stack_register, "saved-import stack register")
        target = _register(self.target_register, "saved-import target register")
        return f"""def {name} : SavedImportControlClaim := {{
  saveSourceTargetId := {_natural(self.save_source_target_id, 'save source target id')}
  restoreSourceTargetId := {_natural(self.restore_source_target_id, 'restore source target id')}
  site := {site}
  binding := {{
    sourceTargetId := {_natural(self.binding_source_target_id, 'IAT binding source target id')}
    instructionRva := {_natural(self.binding_instruction_rva, 'IAT instruction RVA', word=True)}
    iatVa := {_natural(self.iat_va, 'IAT VA', word=True)}
    iatRva := {_natural(self.iat_rva, 'IAT RVA', word=True)}
    identity := {_lean_import_identity(self.identity)}
  }}
  stackRegister := .{stack}
  stackAdjustment := {self.stack_adjustment.lean()}
  targetRegister := .{target}
}}"""


@dataclass(frozen=True)
class DynamicCallbackControlSpec:
    definition_name: str
    site_name: str
    callback_field_offset: int
    allowed_target_ids: tuple[int, ...]

    def lean(self) -> str:
        name = _name(self.definition_name, "callback claim definition", identifier=True)
        site = _name(self.site_name, "callback site name")
        targets = ", ".join(
            str(_natural(value, "callback target id"))
            for value in self.allowed_target_ids
        )
        return f"""def {name} : DynamicCallbackControlClaim := {{
  site := {site}
  callbackFieldOffset := {_natural(self.callback_field_offset, 'callback field offset')}
  allowedTargetIds := [{targets}]
}}"""


@dataclass(frozen=True)
class OriginalIndirectControlAuthorityBinding:
    dependency_module: str
    namespace: str
    context_name: str
    authority_name: str

    def validate(self) -> None:
        for value, field in (
            (self.dependency_module, "dependency module"),
            (self.namespace, "namespace"),
            (self.context_name, "context name"),
            (self.authority_name, "authority name"),
        ):
            _name(value, field)


@dataclass(frozen=True)
class OriginalIndirectControlAuthorityModuleSpec:
    sites: tuple[OriginalIndirectControlSiteSpec, ...] = ()
    seeds: tuple[RelocatedCodePointerSeedSpec, ...] = ()
    nullable_tables: tuple[NullableTableControlSpec, ...] = ()
    saved_imports: tuple[SavedImportControlSpec, ...] = ()
    callbacks: tuple[DynamicCallbackControlSpec, ...] = ()

    def validate(self) -> None:
        names = [item.definition_name for group in (
            self.sites, self.seeds, self.nullable_tables,
            self.saved_imports, self.callbacks
        ) for item in group]
        for name in names:
            _name(name, "definition", identifier=True)
        if len(names) != len(set(names)):
            raise OriginalIndirectControlAuthorityGenerationError(
                "authority definition names must be unique"
            )
        for item in self.sites:
            item.lean()
        for item in self.seeds:
            item.lean()
        for item in self.nullable_tables:
            item.lean()
        for item in self.saved_imports:
            item.lean()
        for item in self.callbacks:
            item.lean()


def _checked_term(name: str, type_name: str, context: str, authority: str) -> str:
    return f"""theorem {name}Checked : {name}.checked {context} = true := by
  decide +kernel

def {name}Evidence : {type_name} {context} := {{
  authority := {authority}
  {"site" if type_name == "CheckedOriginalIndirectControlSite" else "seed" if type_name == "CheckedRelocatedCodePointerSeed" else "claim"} := {name}
  checked := {name}Checked
}}

#print axioms {name}Checked"""


def original_indirect_control_authority_source(
    spec: OriginalIndirectControlAuthorityModuleSpec,
    binding: OriginalIndirectControlAuthorityBinding,
) -> str:
    """Render checked static authorities and their runtime integration types."""

    spec.validate()
    binding.validate()
    context = binding.context_name
    authority = binding.authority_name
    definitions: list[str] = []
    obligations: list[str] = []
    for site in spec.sites:
        definitions.append(site.lean())
        obligations.append(_checked_term(
            site.definition_name,
            "CheckedOriginalIndirectControlSite",
            context,
            authority,
        ))
    for seed in spec.seeds:
        definitions.append(seed.lean())
        obligations.append(_checked_term(
            seed.definition_name,
            "CheckedRelocatedCodePointerSeed",
            context,
            authority,
        ))
    for nullable in spec.nullable_tables:
        definitions.append(nullable.lean())
        obligations.append(_checked_term(
            nullable.definition_name,
            "CheckedNullableTableControlClaim",
            context,
            authority,
        ))
    for saved in spec.saved_imports:
        definitions.append(saved.lean())
        obligations.append(_checked_term(
            saved.definition_name,
            "CheckedSavedImportControlClaim",
            context,
            authority,
        ))
    for callback in spec.callbacks:
        definitions.append(callback.lean())
        obligations.append(_checked_term(
            callback.definition_name,
            "CheckedDynamicCallbackControlClaim",
            context,
            authority,
        ))
    return f"""import StageA.RelationalOriginalIndirectControlAuthority
import {binding.dependency_module}

namespace {binding.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.OriginalIndirectControlAuthority

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{chr(10).join(definitions)}

{chr(10).join(obligations)}

end {binding.namespace}
"""


def write_original_indirect_control_authority_module(
    output: Path | str,
    spec: OriginalIndirectControlAuthorityModuleSpec,
    binding: OriginalIndirectControlAuthorityBinding,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        original_indirect_control_authority_source(spec, binding),
        encoding="utf-8",
    )
    return path


__all__ = [
    "DynamicCallbackControlSpec",
    "ORIGINAL_INDIRECT_CONTROL_AUTHORITY_FORMAT",
    "ORIGINAL_INDIRECT_CONTROL_AUTHORITY_LEAN_FILENAME",
    "NullableTableControlSpec",
    "OriginalIndirectControlAuthorityBinding",
    "OriginalIndirectControlAuthorityGenerationError",
    "OriginalIndirectControlAuthorityModuleSpec",
    "OriginalIndirectControlSiteSpec",
    "OriginalTargetExpressionSpec",
    "RelocatedCodePointerSeedSpec",
    "SavedImportControlSpec",
    "original_indirect_control_authority_source",
    "write_original_indirect_control_authority_module",
]
