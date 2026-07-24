from __future__ import annotations

import copy
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_x87 import (
    CandidateReplayProofSpec,
    relational_interpreter_x87_bundle_sources,
    relational_interpreter_x87_candidate_replay_inventory,
    relational_interpreter_x87_candidate_replay_sources,
    relational_interpreter_x87_module_inventory,
    relational_interpreter_x87_preflight,
    relational_interpreter_x87_source,
)
from spaghetti_extractor.util import sha256_bytes


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _effects(target: int) -> dict[str, object]:
    return {
        "register_writes": [],
        "defined_flag_writes": [],
        "undefined_flags": [],
        "undefined_flag_writes": [],
        "memory_events": [],
        "faults": [],
        "control": {"kind": "fallthrough", "target_rva": target},
        "call_effects": [],
        "ordered_events": [],
        "counts": {
            "register_writes": 0,
            "defined_flag_writes": 0,
            "undefined_flags": 0,
            "undefined_flag_writes": 0,
            "memory_events": 0,
            "faults": 0,
            "call_effects": 0,
            "ordered_events": 0,
        },
    }


def _record(index: int, start: int, encoded: bytes, *, x87: bool) -> dict[str, Any]:
    stop = start + len(encoded)
    decoder = (
        "StageA.Relational.X87.decodeSingletonCommand"
        if x87
        else "StageA.Formal.decodeInstructionExact"
    )
    executor = (
        "StageA.Relational.X87.executeSingletonCommand"
        if x87
        else "StageA.Formal.executeInstruction"
    )
    record: dict[str, Any] = {
        "index": index,
        "rva_start": start,
        "rva_end": stop,
        "bytes": encoded.hex(),
        "bytes_sha256": sha256_bytes(encoded),
        "transfer_bytes_sha256": "",
        "instruction_class": (
            "x87_singleton_checked_replay"
            if x87
            else "ordinary_symbolic_instruction"
        ),
        "classification": {
            "status": "proposal_requires_lean_exact_byte_replay",
            "source": "normalized_symbolic_equivalence_v1",
            "proof_authority": False,
            "mnemonic_guidance": "fld1" if x87 else "nop",
            "operand_guidance": "",
            "checked_decoder": decoder,
            "checked_executor": executor,
        },
        "symbolic_pre_state_sha256": "1" * 64,
        "symbolic_post_state_sha256": "2" * 64,
        "effects": _effects(stop),
    }
    if x87:
        record["x87_singleton_replay"] = {
            "rva_start": start,
            "rva_end": stop,
            "bytes": encoded.hex(),
            "bytes_sha256": sha256_bytes(encoded),
            "checked_decoder": decoder,
            "checked_executor": executor,
            "physical_state_effect": (
                "produced_by_checked_executor_not_inferred_by_exporter"
            ),
        }
    return record


def _row(*, mixed: bool = False, start: int = 0) -> dict[str, Any]:
    specs = [(bytes.fromhex("d9e8"), True)]
    if mixed:
        specs.append((bytes.fromhex("90"), False))
    transfer_bytes = b"".join(encoded for encoded, _ in specs)
    transfer_digest = sha256_bytes(transfer_bytes)
    records = []
    rva = start
    for index, (encoded, x87) in enumerate(specs):
        record = _record(index, rva, encoded, x87=x87)
        record["transfer_bytes_sha256"] = transfer_digest
        record["record_sha256"] = sha256_bytes(_canonical(record))
        records.append(record)
        rva += len(encoded)
    schedule: dict[str, Any] = {
        "format": "stage-a-instruction-ordered-effect-schedule-v1",
        "status": "complete",
        "proof_authority": False,
        "ordering": "strict_contiguous_rva_order",
        "rva_start": start,
        "rva_end": start + len(transfer_bytes),
        "transfer_bytes_sha256": transfer_digest,
        "records": records,
        "blockers": [],
        "counts": {
            "instructions": len(records),
            "x87_singletons": 1,
            "ordinary_instructions": int(mixed),
            "blockers": 0,
        },
    }
    schedule["schedule_sha256"] = sha256_bytes(_canonical(schedule))
    row: dict[str, Any] = {
        "id": "semantic-transfer:fixture-mixed" if mixed else "semantic-transfer:fixture",
        "original": {
            "rva_start": start,
            "rva_end": start + len(transfer_bytes),
            "size": len(transfer_bytes),
        },
        "instructions": [
            {
                "rva": start + sum(len(item[0]) for item in specs[:index]),
                "size": len(encoded),
                "bytes": encoded.hex(),
                "mnemonic": "fld1" if x87 else "nop",
                "op_str": "",
            }
            for index, (encoded, x87) in enumerate(specs)
        ],
        "instruction_bytes_sha256": transfer_digest,
        "fpu_state": {
            "model": "native_exact_x87_command_replay_obligation_v1",
            "replay": {"instruction_effect_schedule": schedule},
        },
        "instruction_effect_schedule": schedule,
        "stage_b_format": "stage-b-state-machine-transfer-v1",
    }
    row["contract_sha256"] = sha256_bytes(
        _canonical({key: value for key, value in row.items() if key != "stage_b_format"})
    )
    return row


def _write_machine(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


class StageARelationalInterpreterX87GenerationTests(unittest.TestCase):
    def test_preflight_inventories_mixed_and_singleton_schedules(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            _write_machine(machine, [_row(), _row(mixed=True)])
            inventory = relational_interpreter_x87_preflight(machine)

        self.assertEqual(inventory["status"], "ready")
        self.assertFalse(inventory["proof_authority"])
        self.assertEqual(
            inventory["counts"],
            {
                "input_transfers": 2,
                "x87_schedules": 2,
                "preflight_checked_schedules": 2,
                "blocked_schedules": 0,
                "mixed_schedules": 1,
                "all_x87_schedules": 1,
                "x87_singleton_replays": 2,
                "ordinary_instruction_records": 1,
            },
        )

    def test_generation_hash_binds_exact_schedule_without_status_authority(self) -> None:
        row = _row()
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            _write_machine(machine, [row])
            source = relational_interpreter_x87_source(
                machine,
                transfer_id=row["id"],
                source_module="StageA.X87ScheduleFixture",
                pe_name="StageA.X87ScheduleFixture.pe",
            )

        for required in (
            "import StageA.RelationalInterpreterX87",
            "def checkedInterpreterX87Schedule : RawInstructionSchedule",
            "opcode := 25",
            "checkedInterpreterX87ScheduleOrderAndReplay",
            "checkedInterpreterX87ScheduleExactPEBytes",
            "checkedInterpreterX87ScheduleSemanticClasses",
            "checkedInterpreterX87ScheduleOrdinaryExecutable",
            "checkedInterpreterX87ScheduleReplayOpcode25",
            "CheckedInstructionSchedule",
            "ExactInterpreterX87ScheduleCertificate",
            "checkedInterpreterX87ScheduleExactCertificate",
            "checkedInterpreterX87ScheduleMacroStepRefines",
            "checkedInterpreterX87ScheduleWitness",
            "ExactInterpreterX87ReplayActionWitness",
            "checkedInterpreterX87ScheduleReplayAction0000Witness",
            "utf8Bytes \"{\\\"",
            "checkedInterpreterX87Schedule.orderAndReplayChecked = true := by decide +kernel",
            "checkedInterpreterX87Schedule.exactPEChecked "
            "StageA.X87ScheduleFixture.pe = true := by decide +kernel",
            "checkedInterpreterX87Schedule.semanticClassesChecked "
            "StageA.X87ScheduleFixture.pe = true := by decide +kernel",
        ):
            self.assertIn(required, source)
        for forbidden in ("WholeProgramCertificate", "pe32ProgramsEquivalent", "jq", "hello"):
            self.assertNotIn(forbidden, source)
        for caller_premise in ("ordinaryRefines", "replayPresent", "replayRefines"):
            self.assertNotIn(caller_premise, source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertNotIn("noncomputable", source)
        self.assertNotIn("native_decide", source)
        exact_certificate = source.split(
            "def checkedInterpreterX87ScheduleExactCertificate", 1
        )[1].split("theorem checkedInterpreterX87ScheduleMacroStepRefines", 1)[0]
        self.assertNotIn("Digests", exact_certificate)
        self.assertIn("recordMember := by decide +kernel", source)
        self.assertIn("actionFound := by decide +kernel", source)

    def test_bundle_uses_canonical_nix_module_names_and_typed_witnesses(self) -> None:
        rows = [_row(), _row(mixed=True, start=16)]
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            _write_machine(machine, rows)
            sources = relational_interpreter_x87_bundle_sources(
                machine,
                source_module="StageA.X87ScheduleFixture",
                pe_name="StageA.X87ScheduleFixture.pe",
                module_prefix="GeneratedX87Schedule",
                definition_prefix="checkedX87Schedule",
            )
            inventory = relational_interpreter_x87_module_inventory(
                machine,
                source_module="StageA.X87ScheduleFixture",
                pe_name="StageA.X87ScheduleFixture.pe",
                module_prefix="GeneratedX87Schedule",
                definition_prefix="checkedX87Schedule",
            )

        self.assertEqual(
            list(sources),
            [
                "GeneratedX87Schedule0000",
                "GeneratedX87Schedule0001",
                "GeneratedX87ScheduleBundle",
            ],
        )

        self.assertTrue(all("." not in module for module in sources))
        bundle = sources["GeneratedX87ScheduleBundle"]
        self.assertIn("import StageA.GeneratedX87Schedule0000", bundle)
        self.assertIn("import StageA.GeneratedX87Schedule0001", bundle)
        self.assertIn("import StageA.RelationalInterpreterAcceptance", bundle)
        self.assertIn(
            "List (ExactInterpreterX87ScheduleWitness "
            "StageA.X87ScheduleFixture.pe)",
            bundle,
        )
        self.assertIn("MemberMacroStepRefines", bundle)
        self.assertIn("ExactOriginalX87Inventory context", bundle)
        self.assertIn("ExactOriginalInventory", bundle)
        self.assertIn("ReplayActionWitnesses", bundle)
        self.assertIn("ReplayActionCount", bundle)
        self.assertIn("MemberReplayActionRefines", bundle)
        self.assertIn("ExactCandidateX87ReplayInventory", bundle)
        self.assertIn("CandidateReplayObligation", bundle)
        self.assertIn("#print axioms checkedX87ScheduleBundle", bundle)
        self.assertEqual(inventory["status"], "ready")
        self.assertFalse(inventory["proof_authority"])
        self.assertEqual(
            inventory["required_external_modules"],
            [
                "RelationalInterpreterAcceptance",
                "RelationalInterpreterX87",
                "X87ScheduleFixture",
            ],
        )
        self.assertEqual(
            inventory["targets"],
            {
                "schedule_nodes": [
                    "GeneratedX87Schedule0000",
                    "GeneratedX87Schedule0001",
                ],
                "bundle_node": "GeneratedX87ScheduleBundle",
                "exact_original_inventory": (
                    "checkedX87ScheduleBundleExactOriginalInventory"
                ),
                "exact_replay_action_inventory": (
                    "checkedX87ScheduleBundleReplayActionWitnesses"
                ),
                "candidate_replay_obligation": (
                    "checkedX87ScheduleBundleCandidateReplayObligation"
                ),
            },
        )
        self.assertEqual(
            inventory["counts"],
            {
                "schedule_modules": 2,
                "bundle_modules": 1,
                "generated_modules": 3,
                "x87_singleton_replays": 2,
                "candidate_replay_obligations": 2,
                "ordinary_instruction_records": 1,
            },
        )

    def test_candidate_replay_graph_is_sharded_and_keeps_native_bridge_open(self) -> None:
        rows = [_row(), _row(mixed=True, start=16)]
        spec = CandidateReplayProofSpec(
            original_source_module="StageA.X87ScheduleFixture",
            original_pe_name="StageA.X87ScheduleFixture.pe",
            table_shard_size=1,
            schedule_module_prefix="GeneratedX87Schedule",
            schedule_definition_prefix="checkedX87Schedule",
            candidate_data_shard_module_prefix="GeneratedCandidateDataShard",
            candidate_data_bundle_module="GeneratedCandidateDataBundle",
            candidate_data_namespace="StageA.CandidateData",
            candidate_entries_prefix="entries",
            candidate_shard_prefix="shard",
            candidate_table_certificate="tableCertificate",
            module_prefix="GeneratedCandidateReplayShard",
            bundle_module="GeneratedCandidateReplayBundle",
            definition_prefix="checkedCandidateReplay",
        )
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            _write_machine(machine, rows)
            sources = relational_interpreter_x87_candidate_replay_sources(
                machine, spec=spec
            )
            inventory = relational_interpreter_x87_candidate_replay_inventory(
                machine, spec=spec
            )

        self.assertEqual(
            list(sources),
            [
                "GeneratedCandidateReplayShard0000",
                "GeneratedCandidateReplayShard0001",
                "GeneratedCandidateReplayBundle",
            ],
        )
        shard = sources["GeneratedCandidateReplayShard0000"]
        self.assertIn("ExactCandidateX87ReplayBinding", shard)
        self.assertIn("reviewedExpectedCandidateReplay", shard)
        self.assertIn("ReplayBearingEntries", shard)
        self.assertIn("decide +kernel", shard)
        self.assertNotIn("native_decide", shard)
        bundle = sources["GeneratedCandidateReplayBundle"]
        self.assertIn("ExactCandidateX87ReplayInventory.ofShards", bundle)
        self.assertIn("CandidateReplayExecutionRelation", bundle)
        self.assertIn("CompiledNativeReplayBridgeRefines Data.tableCertificate", bundle)
        self.assertIn("CompiledNativeBridgeRefinementObligation", bundle)
        for module_source in sources.values():
            self.assertNotIn("native_decide", module_source)
            for marker in ("sorry", "axiom", "unsafe"):
                self.assertIsNone(
                    re.search(rf"\b{marker}\b", module_source), marker
                )
        self.assertEqual(inventory["status"], "source-ready")
        self.assertFalse(inventory["proof_authority"])
        self.assertEqual(inventory["counts"]["table_shards"], 2)
        self.assertEqual(inventory["counts"]["replay_entries"], 2)
        self.assertEqual(inventory["counts"]["replay_actions"], 2)
        self.assertEqual(inventory["native_bridge_status"], "incomplete")

    def test_bundle_rejects_noncanonical_module_graph_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            _write_machine(machine, [_row()])
            with self.assertRaisesRegex(StageAInputError, "module_prefix"):
                relational_interpreter_x87_bundle_sources(
                    machine,
                    source_module="StageA.X87ScheduleFixture",
                    pe_name="StageA.X87ScheduleFixture.pe",
                    module_prefix="StageA.GeneratedX87Schedule",
                )
            with self.assertRaisesRegex(StageAInputError, "source_module"):
                relational_interpreter_x87_bundle_sources(
                    machine,
                    source_module="X87ScheduleFixture",
                    pe_name="StageA.X87ScheduleFixture.pe",
                )

    def test_bundle_rejects_duplicate_source_rvas_before_lean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            _write_machine(machine, [_row(), _row(mixed=True)])
            with self.assertRaisesRegex(StageAInputError, "source RVAs"):
                relational_interpreter_x87_bundle_sources(
                    machine,
                    source_module="StageA.X87ScheduleFixture",
                    pe_name="StageA.X87ScheduleFixture.pe",
                )

    def test_preflight_fails_closed_on_hash_schema_and_schedule_drift(self) -> None:
        cases: list[dict[str, Any]] = []
        bad_hash = copy.deepcopy(_row())
        bad_hash["instruction_effect_schedule"]["records"][0]["bytes"] = "d9ee"
        cases.append(bad_hash)
        extra = copy.deepcopy(_row())
        extra["instruction_effect_schedule"]["records"][0]["capstone_says_ok"] = True
        cases.append(extra)
        detached = copy.deepcopy(_row())
        detached["fpu_state"]["replay"]["instruction_effect_schedule"] = {}
        cases.append(detached)

        for index, row in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                machine = Path(temporary) / "state-machine.jsonl"
                _write_machine(machine, [row])
                inventory = relational_interpreter_x87_preflight(machine)
                self.assertEqual(inventory["status"], "incomplete")
                self.assertEqual(inventory["counts"]["blocked_schedules"], 1)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for generation checks")
    def test_generated_singleton_schedule_is_checked_by_lean(self) -> None:
        row = _row()
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            _write_machine(machine, [row])
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in source_root.glob("*.lean"):
                shutil.copyfile(module, stage_a / module.name)
            (stage_a / "X87ScheduleFixture.lean").write_text(
                """import StageA.Formal
namespace StageA.X87ScheduleFixture
open StageA.Formal
def pe : PE32 := {
  bytes := ByteTree.ofBytes [0xd9, 0xe8]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 2
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 2
    virtualAddress := 0
    rawSize := 2
    rawPointer := 0
    characteristics := 0x60000020
  }]
}
end StageA.X87ScheduleFixture
""",
                encoding="utf-8",
            )
            (stage_a / "GeneratedX87Schedule.lean").write_text(
                relational_interpreter_x87_source(
                    machine,
                    transfer_id=row["id"],
                    source_module="StageA.X87ScheduleFixture",
                    pe_name="StageA.X87ScheduleFixture.pe",
                ),
                encoding="utf-8",
            )
            result = _run_lean_relational(root, bundle="GeneratedX87Schedule")
            bundle_sources = relational_interpreter_x87_bundle_sources(
                machine,
                source_module="StageA.X87ScheduleFixture",
                pe_name="StageA.X87ScheduleFixture.pe",
                module_prefix="GeneratedX87ScheduleBundleCheck",
                definition_prefix="checkedX87ScheduleBundleCheck",
            )
            for module_name, module_source in bundle_sources.items():
                (stage_a / f"{module_name}.lean").write_text(
                    module_source, encoding="utf-8"
                )
            bundle_result = _run_lean_relational(
                root, bundle="GeneratedX87ScheduleBundleCheckBundle"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertEqual(bundle_result["status"], "checked", bundle_result)
        self.assertNotIn("sorryAx", bundle_result["stdout"])


if __name__ == "__main__":
    unittest.main()
