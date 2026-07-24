from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from pe_fixtures import pe32_image

from spaghetti_extractor.relational.lean.common import (
    _lean_byte_tree_definitions,
    _lean_import_certificate,
    _lean_pe,
    _lean_relocations,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    InterpreterMixedOriginalSpec,
    OriginalModuleBindings,
    OriginalPERecoveryInput,
    plan_interpreter_mixed_original,
    write_relational_interpreter_mixed_original,
)
from spaghetti_extractor.relational.lean.interpreter_original_carrier_binding import (
    OriginalCarrierBindingSpec,
    generate_original_carrier_binding,
    write_original_carrier_binding,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS
from spaghetti_extractor.stage_binary import _parse_stage_a_pe


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARelationalInterpreterOriginalCarrierBindingKernelTests(
    unittest.TestCase
):
    def test_exact_pe_carrier_and_fail_closed_mutations_compile(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterOriginalCarrierBinding",
            )

            pe_bytes = pe32_image(b"\x90\xc3")
            pe_path = root / "tiny-carrier.exe"
            pe_path.write_bytes(pe_bytes)
            binary = _parse_stage_a_pe(pe_path)
            try:
                original_source = _EXACT_ORIGINAL_PE.format(
                    byte_tree=_lean_byte_tree_definitions(
                        "originalBytes", pe_bytes
                    ),
                    pe_literal=_lean_pe(binary, "originalBytes"),
                    imports_literal=_lean_import_certificate(binary),
                    relocations_literal=_lean_relocations(binary),
                )
                entry_rva = binary.entrypoint_rva
            finally:
                binary.pe.close()
            (stage_a / "GeneratedTinyCarrierOriginalPE.lean").write_text(
                original_source, encoding="utf-8"
            )

            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(
                "".join(
                    json.dumps(row, sort_keys=True) + "\n"
                    for row in _tiny_state_machine(entry_rva)
                ),
                encoding="utf-8",
            )
            original_spec = InterpreterMixedOriginalSpec(
                bindings=OriginalModuleBindings(
                    module="StageA.GeneratedTinyCarrierOriginalPE",
                    namespace=(
                        "StageA.GeneratedRelational.TinyCarrierOriginalPE"
                    ),
                ),
                entry_rva=entry_rva,
                recovery_pe=OriginalPERecoveryInput(
                    pe_path, hashlib.sha256(pe_bytes).hexdigest()
                ),
                shard_size=2,
            )
            plan = plan_interpreter_mixed_original(state_machine, original_spec)
            self.assertTrue(plan.complete, plan.blockers)
            write_relational_interpreter_mixed_original(root, plan)

            binding_spec = OriginalCarrierBindingSpec(
                original_module=(
                    "StageA.GeneratedRelationalInterpreterMixedOriginal"
                ),
                original_namespace=(
                    "StageA.GeneratedRelational.InterpreterMixedOriginal"
                ),
                target_count=len(plan.regions),
                address_count=len(plan.regions) + len(plan.recovered_aliases),
            )
            generated = generate_original_carrier_binding(binding_spec)
            write_original_carrier_binding(root, binding_spec)
            (stage_a / "GeneratedOriginalCarrierBindingAudit.lean").write_text(
                _AUDIT.format(
                    binding_module=generated.module,
                    binding_namespace=generated.namespace,
                    proposal=generated.terms.proposal,
                    certificate=generated.terms.certificate,
                    indexed_resolution=generated.terms.indexed_resolution,
                    return_resolution=generated.terms.return_resolution,
                    exact_binding=generated.terms.exact_binding,
                    mixed_binding=generated.terms.mixed_binding,
                ),
                encoding="utf-8",
            )

            result = _run_lean_relational(
                root, bundle="GeneratedOriginalCarrierBindingAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = str(result["stdout"]) + str(result["stderr"])
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("_native.native_decide", output)
        for name in (
            generated.terms.indexed_resolution,
            generated.terms.return_resolution,
            generated.terms.exact_binding,
            generated.terms.mixed_binding,
            "concreteCertificate",
            "concreteMixedBinding",
            "mutatedPERejected",
            "omittedRegionRejected",
            "duplicateRegionIdRejected",
            "missingCodeMapEntryRejected",
            "duplicateRvaRejected",
            "ambiguousAliasRejected",
        ):
            self.assertIn(name, output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 6, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, RELATIONAL_APPROVED_AXIOMS, report)


def _tiny_state_machine(entry_rva: int) -> list[dict[str, object]]:
    return [
        _record(
            entry_rva,
            {"kind": "fallthrough", "target_rva": entry_rva + 1},
            edges=[entry_rva + 1],
        ),
        _record(entry_rva + 1, {"kind": "return"}),
    ]


def _record(
    rva: int,
    outcome: dict[str, object],
    *,
    edges: list[int] | None = None,
) -> dict[str, object]:
    return {
        "format": "stage-a-semantic-transfer-contract-v1",
        "stage_b_format": "stage-b-state-machine-transfer-v1",
        "original": {"rva_start": rva, "rva_end": rva + 1, "size": 1},
        "outcome": outcome,
        "edge_conditions": [
            {"target_rva": target, "condition": {"op": "true"}}
            for target in (edges or [])
        ],
        "ordered_events": [],
        "external_events": [],
    }


_EXACT_ORIGINAL_PE = r"""import StageA.RelationalInterpreterMixedOriginal

namespace StageA.GeneratedRelational.TinyCarrierOriginalPE

open StageA.Formal StageA.Relational

set_option maxRecDepth 1000000

{byte_tree}

def originalPe : PE32 :=
  {pe_literal}

def originalImportCertificate : ImportTableCertificate :=
  {imports_literal}

def originalRelocations : List BaseRelocation :=
  {relocations_literal}

theorem originalParsed : parsePE32Tree originalPe.bytes = some originalPe := by
  decide +kernel

theorem originalImportsChecked :
    importTableValid originalPe originalImportCertificate = true := by
  decide +kernel

theorem originalRelocationsParsed :
    parseRelocations originalPe = some originalRelocations := by
  decide +kernel

end StageA.GeneratedRelational.TinyCarrierOriginalPE
"""


_AUDIT = r"""import StageA.{binding_module}

namespace StageA.GeneratedRelational.OriginalCarrierBindingAudit

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterOriginalCarrierBinding
open StageA.GeneratedRelational.InterpreterMixedOriginal
open {binding_namespace}

def environment : WorldExternalEnvironment := {{
  result := fun _ event => {{ state := event.state, world := event.world }}
}}

def protocolEnvironment : WorldExternalProtocolEnvironment := {{
  action := fun request =>
    .returned {{ state := request.state, world := request.world }}
}}

def actualProgram : DecodedWorldProgram :=
  generatedOriginalDecodedProgram environment protocolEnvironment []

def concreteCertificate :
    Certificate generatedOriginalStaticContext actualProgram :=
  {certificate} environment protocolEnvironment []

def concreteMixedBinding :
    ExactMixedProgramBinding generatedOriginalStaticContext actualProgram :=
  {mixed_binding} environment protocolEnvironment []

def mutatedPEContext : OriginalDecodedStaticContext := {{
  generatedOriginalStaticContext with
  pe := {{ generatedOriginalStaticContext.pe with bytes := .empty }}
}}

theorem mutatedPERejected :
    {proposal}.exactContextChecked mutatedPEContext = false := by
  decide +kernel

def omittedRegionProgram : DecodedWorldProgram := {{
  actualProgram with regions := actualProgram.regions.drop 1
}}

theorem omittedRegionRejected :
    {proposal}.carrierChecked generatedOriginalStaticContext
      omittedRegionProgram = false := by
  decide +kernel

def duplicateRegionIds : List RegionRelation :=
  match actualProgram.regions with
  | first :: _second :: rest => first :: first :: rest
  | regions => regions

def duplicateRegionIdProgram : DecodedWorldProgram := {{
  actualProgram with regions := duplicateRegionIds
}}

theorem duplicateRegionIdRejected :
    {proposal}.carrierChecked generatedOriginalStaticContext
      duplicateRegionIdProgram = false := by
  decide +kernel

def missingCodeMapContext : OriginalDecodedStaticContext := {{
  generatedOriginalStaticContext with
  codeMap := {{ generatedOriginalStaticContext.codeMap with entries := .empty }}
}}

theorem missingCodeMapEntryRejected :
    {proposal}.exactContextChecked missingCodeMapContext = false := by
  decide +kernel

def duplicateRvaContext : OriginalDecodedStaticContext := {{
  generatedOriginalStaticContext with
  codeMap := {{
    generatedOriginalStaticContext.codeMap with
    addresses := .leaf
      (generatedOriginalStaticContext.codeMap.addresses.toList ++
        generatedOriginalStaticContext.codeMap.addresses.toList)
  }}
}}

theorem duplicateRvaRejected :
    {proposal}.exactContextChecked duplicateRvaContext = false := by
  decide +kernel

def ambiguousAliasContext : OriginalDecodedStaticContext := {{
  generatedOriginalStaticContext with
  codeMap := {{
    entries := .leaf [
      {{ id := 0, regionIndex := 0, rva := 4096,
        aliases := [{{ rva := 4097, paddingIndex := 0 }}] }},
      {{ id := 1, regionIndex := 1, rva := 4097 }}
    ]
    addresses := .leaf [
      {{ targetId := 0, kind := .canonical }},
      {{ targetId := 0, kind := .alias 0 }},
      {{ targetId := 1, kind := .canonical }}
    ]
  }}
}}

theorem ambiguousAliasRejected :
    {proposal}.exactContextChecked ambiguousAliasContext = false := by
  decide +kernel

#print axioms {indexed_resolution}
#print axioms {return_resolution}
#print axioms {exact_binding}
#print axioms {mixed_binding}
#print axioms concreteCertificate
#print axioms concreteMixedBinding
#print axioms mutatedPERejected
#print axioms omittedRegionRejected
#print axioms duplicateRegionIdRejected
#print axioms missingCodeMapEntryRejected
#print axioms duplicateRvaRejected
#print axioms ambiguousAliasRejected

end StageA.GeneratedRelational.OriginalCarrierBindingAudit
"""


if __name__ == "__main__":
    unittest.main()
