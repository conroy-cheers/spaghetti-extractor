"""Generate an exact semantic-source ``Program`` and binding.

The generator only assembles declarations exported by already checked Lean
modules.  Lean remains responsible for the finite ordinary/x87 partition and
for every semantic certificate stored in the imported binding inventories.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


NATIVE_SOURCE_PROGRAM_MODULE = "GeneratedNativeSourceProgram"

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_NAME_PARTS = frozenset(
    {
        "admit",
        "axiom",
        "by",
        "def",
        "else",
        "end",
        "import",
        "in",
        "inductive",
        "instance",
        "let",
        "match",
        "namespace",
        "native_decide",
        "opaque",
        "partial",
        "protected",
        "sorry",
        "structure",
        "theorem",
        "then",
        "unsafe",
        "where",
        "with",
    }
)


class NativeSourceProgramGenerationError(StageAInputError):
    """A requested Lean module or declaration name is malformed."""


@dataclass(frozen=True)
class NativeSourceProgramSpec:
    """Explicit module and declaration bindings for source-program assembly."""

    decoded_original_module: str
    decoded_original_program: str
    decoded_original_side: str
    original_pe: str
    decoded_original_pe_exact: str
    semantic_program_module: str
    semantic_program_records: str
    semantic_program_records_unique: str
    normalization_module: str
    ordinary_record_bindings: str
    x87_schedule_module: str
    x87_witnesses: str
    x87_source_rvas: str
    x87_source_rvas_nodup: str
    namespace: str = "StageA.GeneratedRelational.NativeSourceProgram"
    output_module: str = NATIVE_SOURCE_PROGRAM_MODULE
    x87_provider_name: str = "generatedNativeSourceX87Provider"
    x87_witness_rvas_nodup_name: str = (
        "generatedNativeSourceX87WitnessRvasNodup"
    )
    program_name: str = "generatedNativeSourceProgram"
    ordinary_records_exact_name: str = (
        "generatedNativeSourceOrdinaryRecordsExact"
    )
    partition_name: str = "generatedNativeSourceExactBindingPartition"
    binding_name: str = "generatedNativeSourceExactBinding"
    parameterize_world_program: bool = False

    def validate(self) -> None:
        module_fields = {
            "decoded_original_module",
            "semantic_program_module",
            "normalization_module",
            "x87_schedule_module",
        }
        local_fields = {
            "output_module",
            "x87_provider_name",
            "x87_witness_rvas_nodup_name",
            "program_name",
            "ordinary_records_exact_name",
            "partition_name",
            "binding_name",
        }
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name == "parameterize_world_program":
                if not isinstance(value, bool):
                    raise NativeSourceProgramGenerationError(
                        "parameterize_world_program must be a boolean"
                    )
                continue
            if field.name in module_fields:
                valid = _valid_stage_a_module(value)
                expected = "a canonical StageA module"
            elif field.name in local_fields:
                valid = _valid_local_name(value)
                expected = "a canonical local Lean identifier"
            else:
                valid = _valid_identifier(value)
                expected = "a canonical Lean identifier"
            if not valid:
                raise NativeSourceProgramGenerationError(
                    f"{field.name} must be {expected}"
                )

        generated_names = [
            getattr(self, name) for name in local_fields - {"output_module"}
        ]
        if len(set(generated_names)) != len(generated_names):
            raise NativeSourceProgramGenerationError(
                "generated declaration names must be distinct"
            )


def _valid_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and _LEAN_IDENTIFIER.fullmatch(value) is not None
        and all(
            part.casefold() not in _FORBIDDEN_NAME_PARTS
            for part in value.split(".")
        )
    )


def _valid_local_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and _LOCAL_NAME.fullmatch(value) is not None
        and value.casefold() not in _FORBIDDEN_NAME_PARTS
    )


def _valid_stage_a_module(value: object) -> bool:
    return (
        isinstance(value, str)
        and _STAGE_A_MODULE.fullmatch(value) is not None
        and all(
            part.casefold() not in _FORBIDDEN_NAME_PARTS
            for part in value.split(".")
        )
    )


def native_source_program_source(spec: NativeSourceProgramSpec) -> str:
    """Emit a checked ``Program``, partition, and exact binding."""

    spec.validate()
    if spec.parameterize_world_program:
        program_parameters = " (worldProgram : DecodedWorldProgram)"
        world_program = "worldProgram"
        program_reference = f"{spec.program_name} worldProgram"
        partition_parameters = " (worldProgram : DecodedWorldProgram)"
        partition_reference = f"{spec.partition_name} worldProgram"
        binding_parameters = f"""
    (worldProgram : DecodedWorldProgram)
    (originalSide : worldProgram.candidate = false)
    (originalPeExact : worldProgram.context.originalPe = {spec.original_pe})"""
        binding_side = "originalSide"
        binding_pe = "originalPeExact"
    else:
        program_parameters = ""
        world_program = spec.decoded_original_program
        program_reference = spec.program_name
        partition_parameters = ""
        partition_reference = spec.partition_name
        binding_parameters = ""
        binding_side = spec.decoded_original_side
        binding_pe = spec.decoded_original_pe_exact
    return f"""import {spec.decoded_original_module}
import {spec.semantic_program_module}
import {spec.normalization_module}
import {spec.x87_schedule_module}
import StageA.RelationalSourceInterpreterKernel

namespace {spec.namespace}

open StageA.Formal
open StageA.Relational
open StageA.Relational.SourceWorld.InterpreterKernel

set_option maxRecDepth 100000
set_option maxHeartbeats 0

def {spec.x87_provider_name} : X87Provider :=
  exactX87Provider {spec.x87_witnesses}

/-- The x87 source inventory must be the source-RVA projection of the exact
schedule witnesses. -/
theorem {spec.x87_witness_rvas_nodup_name} :
    ({spec.x87_witnesses}.map
      (fun witness => witness.schedule.sourceRva)).Nodup := by
  simpa only [{spec.x87_source_rvas}] using {spec.x87_source_rvas_nodup}

def {spec.program_name}{program_parameters} : Program := {{
  worldProgram := {world_program}
  records := {spec.semantic_program_records}
  x87SourceRvas := {spec.x87_source_rvas}
  x87Provider := {spec.x87_provider_name}
}}

/-- This is the sole finite computation in the assembly: it checks that the
imported ordinary bindings are exactly the semantic program records.  x87
execution is represented only by the separately checked provider. -/
theorem {spec.ordinary_records_exact_name} :
    {spec.ordinary_record_bindings}.map
        (fun binding => binding.path.record) =
      {spec.semantic_program_records} := by
  native_decide

def {spec.partition_name}{partition_parameters} :
    ExactBindingPartition {spec.original_pe} {program_reference} := {{
  ordinaryBindings := {spec.ordinary_record_bindings}
  ordinaryRecordsExact := by
    simpa only [{spec.program_name}] using {spec.ordinary_records_exact_name}
  recordsUnique := by
    simpa only [{spec.program_name}] using
      {spec.semantic_program_records_unique}
  x87SourcesUnique := by
    simpa only [{spec.program_name}] using {spec.x87_source_rvas_nodup}
  x87Witnesses := {spec.x87_witnesses}
  x87WitnessesCovered := by
    intro sourceRva classified
    change List.Mem sourceRva {spec.x87_source_rvas} at classified
    change List.Mem sourceRva ({spec.x87_witnesses}.map
      (fun witness => witness.schedule.sourceRva)) at classified
    exact List.mem_map.mp classified
  x87ProviderExact := by
    intro sourceRva _classified witness member sourceExact state
    subst sourceRva
    simpa only [{spec.program_name}, {spec.x87_provider_name}] using
      (exactX87Provider_execute {spec.x87_witness_rvas_nodup_name}
        member state)
}}

def {spec.binding_name}{binding_parameters} :
    ExactBinding {spec.original_pe} {program_reference} :=
  {partition_reference}.toExactBinding
    (by
      simpa only [{spec.program_name}] using {binding_side})
    (by
      simpa only [{spec.program_name}] using {binding_pe})

#print axioms {spec.ordinary_records_exact_name}
#print axioms {spec.partition_name}
#print axioms {spec.binding_name}

end {spec.namespace}
"""


def write_native_source_program(
    out: Path | str, spec: NativeSourceProgramSpec
) -> Path:
    """Write the generated module below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    destination = stage_a / f"{spec.output_module}.lean"
    destination.write_text(native_source_program_source(spec), encoding="ascii")
    return destination


relational_native_source_program_source = native_source_program_source
write_relational_native_source_program = write_native_source_program


__all__ = [
    "NATIVE_SOURCE_PROGRAM_MODULE",
    "NativeSourceProgramGenerationError",
    "NativeSourceProgramSpec",
    "native_source_program_source",
    "relational_native_source_program_source",
    "write_native_source_program",
    "write_relational_native_source_program",
]
