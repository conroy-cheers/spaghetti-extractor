from __future__ import annotations

import copy
import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.interpreter_transfer import (
    RELATIONAL_INTERPRETER_TRANSFER_FORMAT,
    RELATIONAL_INTERPRETER_TRANSFER_GENERAL_FORMAT,
    RELATIONAL_INTERPRETER_TRANSFER_GENERAL_PROFILE,
    RELATIONAL_INTERPRETER_TRANSFER_PROFILE,
    interpreter_transfer_inventory,
    relational_interpreter_transfer_source,
)


def _artifact() -> dict[str, str]:
    fields = {
        "format": RELATIONAL_INTERPRETER_TRANSFER_FORMAT,
        "profile": RELATIONAL_INTERPRETER_TRANSFER_PROFILE,
        "source_module": "StageA.InterpreterTransferFixture",
        "certificate_name": "checkedTransfer0",
        "pe_bytes": "StageA.InterpreterTransferFixture.peBytes",
        "contract_bytes": "StageA.InterpreterTransferFixture.contractBytes",
        "instruction_bytes": "StageA.InterpreterTransferFixture.instructionBytes",
        "pe": "StageA.InterpreterTransferFixture.pe",
        "span": "StageA.InterpreterTransferFixture.span",
        "imports": "StageA.InterpreterTransferFixture.imports",
        "machine_contracts": "StageA.InterpreterTransferFixture.contracts",
        "targets": "StageA.InterpreterTransferFixture.targets",
        "decoded": "StageA.InterpreterTransferFixture.decoded",
        "normalized": "StageA.InterpreterTransferFixture.normalized",
        "record": "StageA.InterpreterTransferFixture.record",
        "exported": "StageA.InterpreterTransferFixture.exported",
        "pe_parsed": "StageA.InterpreterTransferFixture.peParsed",
        "instruction_bytes_read": (
            "StageA.InterpreterTransferFixture.instructionBytesRead"
        ),
        "decoded_from_exact_bytes": (
            "StageA.InterpreterTransferFixture.decodedFromExactBytes"
        ),
        "normalized_from_decoded": (
            "StageA.InterpreterTransferFixture.normalizedFromDecoded"
        ),
        "target_map_checked": (
            "StageA.InterpreterTransferFixture.targetMapChecked"
        ),
        "contract_digest_checked": (
            "StageA.InterpreterTransferFixture.contractDigestChecked"
        ),
        "instruction_digest_checked": (
            "StageA.InterpreterTransferFixture.instructionDigestChecked"
        ),
        "instruction_profile_supported": (
            "StageA.InterpreterTransferFixture.instructionProfileSupported"
        ),
        "raw_record_decoded": (
            "StageA.InterpreterTransferFixture.rawRecordDecoded"
        ),
        "transfer_checked": "StageA.InterpreterTransferFixture.transferChecked",
        "transfer_profile_supported": (
            "StageA.InterpreterTransferFixture.transferProfileSupported"
        ),
        "source_rva_bound": "StageA.InterpreterTransferFixture.sourceRvaBound",
        "normalized_profile_supported": (
            "StageA.InterpreterTransferFixture.normalizedProfileSupported"
        ),
        "semantic_agreement": (
            "StageA.InterpreterTransferFixture.semanticAgreement"
        ),
    }
    return fields


def _general_artifact() -> dict[str, str]:
    artifact = _artifact()
    artifact["format"] = RELATIONAL_INTERPRETER_TRANSFER_GENERAL_FORMAT
    artifact["profile"] = RELATIONAL_INTERPRETER_TRANSFER_GENERAL_PROFILE
    artifact.pop("normalized_profile_supported")
    artifact.update(
        {
            "original_macro": "StageA.InterpreterTransferFixture.originalMacro",
            "original_call_boundaries": (
                "StageA.InterpreterTransferFixture.originalCallBoundaries"
            ),
            "footprint": "StageA.InterpreterTransferFixture.footprint",
            "alias_witnesses": "StageA.InterpreterTransferFixture.aliasWitnesses",
            "target_witnesses": "StageA.InterpreterTransferFixture.targetWitnesses",
            "undefined_slots": "StageA.InterpreterTransferFixture.undefinedSlots",
            "return_frame_target": (
                "StageA.InterpreterTransferFixture.returnFrameTarget"
            ),
            "external_target": "StageA.InterpreterTransferFixture.externalTarget",
            "footprint_exact": "StageA.InterpreterTransferFixture.footprintExact",
            "alias_inventory": "StageA.InterpreterTransferFixture.aliasInventory",
            "targets_exact": "StageA.InterpreterTransferFixture.targetsExact",
            "call_boundaries_exact": (
                "StageA.InterpreterTransferFixture.callBoundariesExact"
            ),
            "call_boundaries_decoded": (
                "StageA.InterpreterTransferFixture.callBoundariesDecoded"
            ),
            "alias_disjointness": (
                "StageA.InterpreterTransferFixture.aliasDisjointness"
            ),
            "undefined_inventory": (
                "StageA.InterpreterTransferFixture.undefinedInventory"
            ),
            "undefined_noninterference": (
                "StageA.InterpreterTransferFixture.undefinedNoninterference"
            ),
            "indirect_targets_complete": (
                "StageA.InterpreterTransferFixture.indirectTargetsComplete"
            ),
            "original_macro_decoded": (
                "StageA.InterpreterTransferFixture.originalMacroDecoded"
            ),
        }
    )
    return artifact


def _row(identifier: str = "semantic-transfer:fixture", rva: int = 0x1000) -> dict[str, object]:
    return {
        "id": identifier,
        "status": "pass-must-be-ignored",
        "contract_sha256": "a" * 64,
        "instruction_bytes_sha256": "b" * 64,
        "original": {"rva_start": rva, "rva_end": rva + 3, "size": 3},
        "ordered_events": [
            {
                "family": "memory",
                "kind": "read",
                "width": 4,
                "address": {"op": "reg", "name": "esp", "width": 32},
            }
        ],
        "register_writes": [],
        "flag_writes": [],
        "fpu_state": None,
        "outcome": {"kind": "fallthrough", "target_rva": rva + 3},
    }


class StageARelationalInterpreterTransferGenerationTests(unittest.TestCase):
    def test_composes_only_named_kernel_checked_premises(self) -> None:
        source = relational_interpreter_transfer_source(_artifact())

        for required in (
            "import StageA.RelationalInterpreterTransfer",
            "import StageA.InterpreterTransferFixture",
            "def checkedTransfer0 : InterpreterTransferCertificate",
            "peParsed := StageA.InterpreterTransferFixture.peParsed",
            "contractDigestChecked := StageA.InterpreterTransferFixture.contractDigestChecked",
            "exactInstructionProfile := StageA.InterpreterTransferFixture.instructionProfileSupported",
            "semanticAgreement := StageA.InterpreterTransferFixture.semanticAgreement",
            "checkedTransfer0MacroStepRefinesOriginal",
            "checkedTransfer0RawMacroStepRefinesOriginal",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "WholeProgramCertificate",
            "pe32ProgramsEquivalent",
            "Acceptance",
            "status",
            "jq",
            "hello",
            "by decide",
            "by native_decide",
        ):
            self.assertNotIn(forbidden, source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_rejects_profile_drift_missing_proofs_and_injection(self) -> None:
        cases: list[tuple[dict[str, str], str]] = []

        profile = copy.deepcopy(_artifact())
        profile["profile"] = "external-calls-are-probably-fine-v1"
        cases.append((profile, "unsupported interpreter-transfer profile"))

        missing = copy.deepcopy(_artifact())
        del missing["semantic_agreement"]
        cases.append((missing, "missing required fields"))

        injected = copy.deepcopy(_artifact())
        injected["semantic_agreement"] = "proof; axiom bypass : True"
        cases.append((injected, "qualified Lean identifier"))

        extra = copy.deepcopy(_artifact())
        extra["python_status"] = "pass"
        cases.append((extra, "unexpected fields"))

        for artifact, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(StageAInputError, message):
                    relational_interpreter_transfer_source(artifact)

    def test_general_profile_emits_only_named_checked_obligations(self) -> None:
        source = relational_interpreter_transfer_source(_general_artifact())

        for required in (
            "GeneralInterpreterTransferCertificate",
            "exactFootprint := StageA.InterpreterTransferFixture.footprintExact",
            "aliasInventory := StageA.InterpreterTransferFixture.aliasInventory",
            "callBoundariesExact := StageA.InterpreterTransferFixture.callBoundariesExact",
            "callBoundariesDecoded := StageA.InterpreterTransferFixture.callBoundariesDecoded",
            "undefinedNoninterference := StageA.InterpreterTransferFixture.undefinedNoninterference",
            "dynamicTargetsComplete := StageA.InterpreterTransferFixture.indirectTargetsComplete",
            "originalMacroDecoded := StageA.InterpreterTransferFixture.originalMacroDecoded",
            "checkedTransfer0RawMacroStepRefinesOriginal",
            "checkedTransfer0MacroStepProducesDecodedResult",
        ):
            self.assertIn(required, source)
        for forbidden in ("WholeProgramCertificate", "status", "by decide", "jq", "hello"):
            self.assertNotIn(forbidden, source)

    def test_inventory_ignores_status_and_fails_x87_closed(self) -> None:
        ordinary = _row()
        x87 = _row("semantic-transfer:x87", 0x2000)
        x87["fpu_state"] = {
            "model": "symbolic_x87_stack_v1",
            "stack": [{"op": "fpu_reg", "args": [index]} for index in range(8)],
            "control": {"op": "fpu_control", "args": []},
            "status": {"op": "fpu_status", "args": []},
        }
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            machine.write_text(
                "".join(
                    json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                    for row in (ordinary, x87)
                ),
                encoding="utf-8",
            )
            inventory = interpreter_transfer_inventory(machine)

        self.assertEqual(inventory["total_transfers"], 2)
        self.assertEqual(inventory["structurally_supported"], 1)
        self.assertEqual(inventory["blocked"], 1)
        self.assertEqual(inventory["status_fields_ignored"], 2)
        self.assertEqual(
            inventory["blocker_family_counts"], {"x87_separate_frontier": 1}
        )
        self.assertEqual(
            inventory["blocked_feature_transfer_counts"]["x87.state.missing_tags"],
            1,
        )
        self.assertEqual(inventory["feature_counts"]["flat_memory.read"], 1)
        self.assertEqual(inventory["lean_semantic_certificates_proved"], 0)

    def test_current_gnu_hello_inventory_is_complete_when_present(self) -> None:
        machine = (
            Path(__file__).parents[1]
            / "build/stage-b-gnu-hello-roundtrip/stage-a-static-export/state-machine.jsonl"
        )
        if not machine.is_file():
            self.skipTest("current GNU hello state-machine artifact is unavailable")

        inventory = interpreter_transfer_inventory(machine)

        self.assertEqual(inventory["total_transfers"], 5326)
        self.assertEqual(
            inventory["structurally_supported"] + inventory["blocked"], 5326
        )
        self.assertEqual(len(inventory["blocked_transfers"]), inventory["blocked"])
        self.assertEqual(
            inventory["blocker_family_counts"],
            {"x87_separate_frontier": 110},
        )
        self.assertEqual(inventory["status_fields_ignored"], 5326)

    def test_inventory_preserves_repeated_memory_reads(self) -> None:
        row = _row()
        row["ordered_events"] = [*row["ordered_events"], *row["ordered_events"]]
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            machine.write_text(json.dumps(row) + "\n", encoding="utf-8")
            inventory = interpreter_transfer_inventory(machine)

        self.assertEqual(inventory["structurally_supported"], 1)
        self.assertEqual(inventory["blocker_family_counts"], {})
        self.assertEqual(inventory["feature_counts"]["flat_memory.read"], 2)


if __name__ == "__main__":
    unittest.main()
