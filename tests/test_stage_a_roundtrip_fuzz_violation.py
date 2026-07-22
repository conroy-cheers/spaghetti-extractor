from __future__ import annotations

import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.roundtrip_fuzz.model import CaseManifest, ArtifactRef
from spaghetti_extractor.roundtrip_fuzz.provenance import (
    build_opaque_stage_b_input_bundle,
    validate_opaque_stage_b_input_bundle,
)
from spaghetti_extractor.roundtrip_fuzz.violation import (
    AUTOMATIC_VIOLATION_DERIVATION_FORMAT,
    VIOLATION_CHECK_FORMAT,
    VIOLATION_WITNESS_FORMAT,
    derive_concrete_violation_witness,
    produce_checked_violation,
    validate_checked_violation,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file, write_json
from tests.stage_a_relational_support import _pe32_image


class RoundTripFuzzViolationTests(unittest.TestCase):
    @staticmethod
    def _checked_node_build() -> dict[str, object]:
        return {
            "format": "stage-a-relational-nix-node-build-v1",
            "status": "checked",
            "node": {
                "compiler_output": (
                    "'StageA.GeneratedRelationalCounterexample."
                    "reachableExactCounterexample' depends on axioms: "
                    "[propext, Classical.choice, Quot.sound]\n"
                ),
            },
        }

    def test_automatic_violation_is_source_mapped_and_lean_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, case_root, prepared = self._automatic_fixture(root)

            derivation = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )

            self.assertEqual(
                derivation["format"], AUTOMATIC_VIOLATION_DERIVATION_FORMAT
            )
            self.assertEqual(derivation["status"], "ready_for_lean_replay")
            self.assertFalse(derivation["trust"]["can_authorize_violated"])
            witness = derivation["witness"]
            self.assertEqual(witness["location"]["original"]["semantic_id"], "entry-add")
            self.assertEqual(witness["location"]["original"]["rva"], 0x1000)
            self.assertEqual(witness["location"]["original"]["bytes_hex"], "40")
            self.assertEqual(witness["location"]["candidate"]["bytes_hex"], "48")
            self.assertEqual(
                witness["location"]["original"]["path"],
                ["straight-line", "entry-add", "entry-add"],
            )
            self.assertEqual(witness["mismatch"]["kind"], "register_relation")
            self.assertEqual(witness["mismatch"]["original_effect"]["location"], "eax")

            out = root / "violation"
            with patch(
                "spaghetti_extractor.roundtrip_fuzz.violation."
                "stage_a_build_relational",
                return_value=self._checked_node_build(),
            ) as build_node:
                production = produce_checked_violation(
                    case=case,
                    case_root=case_root,
                    prepared=prepared,
                    out=out,
                )

            self.assertEqual(production["status"], "checked", production)
            self.assertEqual(
                build_node.call_args.kwargs["target_node"],
                "relationalcounterexample",
            )
            source = Path(production["source"]).read_text(encoding="utf-8")
            self.assertIn("def classifiedMismatch : Bool", source)
            self.assertIn("!(registersRelatedValues", source)
            self.assertIn("theorem classifiedMismatchChecked", source)
            self.assertIn("theorem reachableLaunchAdmissible", source)
            self.assertIn("def originalReachabilityChecked", source)
            self.assertIn("theorem reachableExactCounterexample", source)
            self.assertIn("#print axioms reachableExactCounterexample", source)
            result = validate_checked_violation(
                witness_path=Path(production["witness"]),
                audit_path=Path(production["audit"]),
                case=case,
                case_root=case_root,
                prepared=prepared,
            )
            self.assertEqual(result["status"], "violated", result)
            self.assertEqual(
                result["first_proved_mismatch"]["original"]["semantic_id"],
                "entry-add",
            )

    def test_automatic_violation_rejects_stale_location_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, case_root, prepared = self._automatic_fixture(root)
            derivation = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )
            witness = derivation["witness"]
            witness["location"]["candidate"]["bytes_hex"] = "90"
            witness_path = root / "stale-witness.json"
            write_json(witness_path, witness)
            audit_path = root / "audit.json"
            write_json(audit_path, {})

            with self.assertRaisesRegex(StageAInputError, "candidate bytes"):
                validate_checked_violation(
                    witness_path=witness_path,
                    audit_path=audit_path,
                    case=case,
                    case_root=case_root,
                    prepared=prepared,
                )

    def test_automatic_violation_rejects_stale_path_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, case_root, prepared = self._non_root_automatic_fixture(root)
            derivation = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )
            self.assertEqual(derivation["status"], "ready_for_lean_replay")
            witness = derivation["witness"]
            self.assertEqual(len(witness["reachability"]["original_steps"]), 1)
            witness["reachability"]["original_steps"][0]["bytes_hex"] = "90"
            witness_path = root / "stale-path-witness.json"
            write_json(witness_path, witness)

            with self.assertRaisesRegex(StageAInputError, "path binding|path bytes"):
                validate_checked_violation(
                    witness_path=witness_path,
                    audit_path=root / "unused-audit.json",
                    case=case,
                    case_root=case_root,
                    prepared=prepared,
                )

    def test_automatic_violation_fails_closed_on_unsupported_expression(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, case_root, prepared = self._automatic_fixture(root)
            decoded_path = prepared / "relational-decoded-behaviors.json"
            decoded = json.loads(decoded_path.read_text(encoding="utf-8"))
            candidate_ir = decoded["regions"][0]["candidate_ir"]
            candidate_ir["registers"]["eax"] = {"op": "undefined", "slot": 0}
            decoded["regions"][0]["candidate_ir_sha256"] = self._payload_sha256(
                candidate_ir
            )
            write_json(decoded_path, decoded)

            derivation = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )

            self.assertEqual(derivation["status"], "incomplete")
            self.assertEqual(derivation["reason_code"], "unsupported_expression")
            self.assertIsNone(derivation["witness"])
            with patch(
                "spaghetti_extractor.roundtrip_fuzz.violation."
                "stage_a_build_relational"
            ) as build_node:
                production = produce_checked_violation(
                    case=case,
                    case_root=case_root,
                    prepared=prepared,
                    out=root / "unsupported",
                )
            self.assertEqual(production["status"], "incomplete")
            self.assertEqual(production["reason_code"], "unsupported_expression")
            build_node.assert_not_called()

    def test_automatic_violation_ids_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, case_root, prepared = self._automatic_fixture(root)

            first = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )["witness"]
            second = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )["witness"]

            self.assertEqual(first["id"], second["id"])
            self.assertEqual(first["obligation_id"], second["obligation_id"])
            self.assertEqual(first, second)

    def test_automatic_violation_accepts_normalized_relation_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, case_root, prepared = self._automatic_fixture(root)
            contract_path = prepared / "relation-contract.json"
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            contract["regions"][0]["input_relations"][0]["relation"] = (
                "related_word"
            )
            contract["regions"][0]["output_relations"][0] = {
                "original": "eax",
                "candidate": "eax",
                "relation": "fixed_word",
                "value": 1,
            }
            write_json(contract_path, contract)
            decoded_path = prepared / "relational-decoded-behaviors.json"
            decoded = json.loads(decoded_path.read_text(encoding="utf-8"))
            decoded["relation_contract_sha256"] = sha256_file(contract_path)
            write_json(decoded_path, decoded)

            derivation = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )

            self.assertEqual(derivation["status"], "ready_for_lean_replay")
            self.assertEqual(
                derivation["witness"]["mismatch"]["relation_atom"],
                "register-eax-eax-related-word",
            )

    def test_automatic_violation_respects_mapped_code_words(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, case_root, prepared = self._automatic_fixture(root)
            contract_path = prepared / "relation-contract.json"
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            contract["regions"][0]["code_targets"] = [{
                "id": 0,
                "region_index": 0,
                "original_rva": 0,
                "candidate_rva": 1,
                "original_aliases": [],
                "candidate_aliases": [],
            }]
            write_json(contract_path, contract)
            decoded_path = prepared / "relational-decoded-behaviors.json"
            decoded = json.loads(decoded_path.read_text(encoding="utf-8"))
            decoded["relation_contract_sha256"] = sha256_file(contract_path)
            original_ir = self._behavior_ir("add")
            candidate_ir = self._behavior_ir("add")
            original_ir["registers"]["eax"] = {
                "op": "constant", "value": 0x400000,
            }
            candidate_ir["registers"]["eax"] = {
                "op": "constant", "value": 0x400001,
            }
            row = decoded["regions"][0]
            row["original_ir"] = original_ir
            row["candidate_ir"] = candidate_ir
            row["original_ir_sha256"] = self._payload_sha256(original_ir)
            row["candidate_ir_sha256"] = self._payload_sha256(candidate_ir)
            write_json(decoded_path, decoded)

            mapped = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )
            self.assertEqual(mapped["status"], "incomplete")
            self.assertEqual(
                mapped["reason_code"], "no_supported_reachable_mismatch"
            )

            candidate_ir["registers"]["eax"] = {
                "op": "constant", "value": 0x400002,
            }
            row["candidate_ir"] = candidate_ir
            row["candidate_ir_sha256"] = self._payload_sha256(candidate_ir)
            write_json(decoded_path, decoded)
            unmapped = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )
            self.assertEqual(unmapped["status"], "ready_for_lean_replay")

    def test_automatic_violation_prefers_unique_root_of_split_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, case_root, prepared = self._automatic_fixture(root)
            contract_path = prepared / "relation-contract.json"
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            split_region = json.loads(json.dumps(contract["regions"][0]))
            split_region.update({
                "id": "entry-add-0001",
                "numeric_id": 1,
                "root": False,
            })
            contract["regions"].append(split_region)
            write_json(contract_path, contract)
            decoded_path = prepared / "relational-decoded-behaviors.json"
            decoded = json.loads(decoded_path.read_text(encoding="utf-8"))
            split_decoded = json.loads(json.dumps(decoded["regions"][0]))
            split_decoded["index"] = 1
            decoded["regions"].append(split_decoded)
            decoded["relation_contract_sha256"] = sha256_file(contract_path)
            write_json(decoded_path, decoded)

            derivation = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )

            self.assertEqual(derivation["status"], "ready_for_lean_replay")
            self.assertEqual(
                derivation["witness"]["location"]["original"]["region_index"],
                0,
            )

    def test_automatic_violation_covers_memory_and_direct_control(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, case_root, prepared = self._automatic_fixture(root)
            original_ir = self._behavior_ir("add")
            candidate_ir = self._behavior_ir("add")
            original_ir["writes"] = [{
                "address": {"op": "input_reg", "reg": "esp"},
                "value": {"op": "constant", "value": 1},
            }]
            candidate_ir["writes"] = [{
                "address": {"op": "input_reg", "reg": "esp"},
                "value": {"op": "constant", "value": 2},
            }]
            self._replace_decoded_pair(prepared, original_ir, candidate_ir)

            memory = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )
            self.assertEqual(
                memory["witness"]["mismatch"]["kind"], "memory_write_relation"
            )
            self.assertEqual(
                memory["witness"]["mismatch"]["original_effect"]["location"],
                "writes[0].value",
            )
            with patch(
                "spaghetti_extractor.roundtrip_fuzz.violation."
                "stage_a_build_relational",
                return_value=self._checked_node_build(),
            ):
                production = produce_checked_violation(
                    case=case,
                    case_root=case_root,
                    prepared=prepared,
                    out=root / "memory-violation",
                )
            source = Path(production["source"]).read_text(encoding="utf-8")
            self.assertIn("originalResult.writes[0]?", source)
            self.assertNotIn("originalResult.writes.get?", source)

            original_ir = self._behavior_ir("add")
            candidate_ir = self._behavior_ir("add")
            candidate_ir["outcome"] = {"op": "jump", "target": 1}
            self._replace_decoded_pair(prepared, original_ir, candidate_ir)
            control = derive_concrete_violation_witness(
                case=case, case_root=case_root, prepared=prepared
            )
            self.assertEqual(
                control["witness"]["mismatch"]["kind"], "branch_destination"
            )
            self.assertEqual(
                control["witness"]["mismatch"]["original_effect"]["kind"],
                "control_target",
            )

    def test_writable_cached_audit_is_replayed_by_the_kernel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, case_root, prepared = self._automatic_fixture(root)
            out = root / "checked"
            with patch(
                "spaghetti_extractor.roundtrip_fuzz.violation."
                "stage_a_build_relational",
                return_value=self._checked_node_build(),
            ):
                production = produce_checked_violation(
                    case=case, case_root=case_root, prepared=prepared, out=out
                )
            audit_path = Path(production["audit"])
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            audit["status"] = "solver_sat"
            write_json(audit_path, audit)

            with patch(
                "spaghetti_extractor.roundtrip_fuzz.violation."
                "stage_a_build_relational",
                return_value=self._checked_node_build(),
            ) as replay:
                result = validate_checked_violation(
                    witness_path=Path(production["witness"]),
                    audit_path=audit_path,
                    case=case,
                    case_root=case_root,
                    prepared=prepared,
                )

            self.assertEqual(result["status"], "violated", result)
            self.assertEqual(
                result["trust"]["audit_provenance"],
                "kernel-replayed-writable-cache",
            )
            replay.assert_called_once()

    def test_writable_audit_cannot_authorize_without_kernel_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, case_root, prepared = self._automatic_fixture(root)
            with patch(
                "spaghetti_extractor.roundtrip_fuzz.violation."
                "stage_a_build_relational",
                return_value=self._checked_node_build(),
            ):
                production = produce_checked_violation(
                    case=case,
                    case_root=case_root,
                    prepared=prepared,
                    out=root / "checked",
                )
            audit_path = Path(production["audit"])
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            audit["proof_source_sha256"] = "f" * 64
            write_json(audit_path, audit)

            with patch(
                "spaghetti_extractor.roundtrip_fuzz.violation."
                "stage_a_build_relational",
                return_value={
                    "format": "stage-a-relational-nix-node-build-v1",
                    "status": "incomplete",
                    "node": {"compiler_output": "rejected"},
                },
            ) as replay:
                result = validate_checked_violation(
                    witness_path=Path(production["witness"]),
                    audit_path=audit_path,
                    case=case,
                    case_root=case_root,
                    prepared=prepared,
                )

            self.assertEqual(result["status"], "incomplete", result)
            self.assertEqual(
                result["trust"]["audit_provenance"], "kernel-replay-failed"
            )
            replay.assert_called_once()

    def test_opaque_stage_b_bundle_excludes_original_and_undeclared_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reference = root / "reference.json"
            state_machine = root / "state-machine.jsonl"
            annotation = root / "annotation.json"
            reference.write_text("{}\n", encoding="utf-8")
            state_machine.write_text("{}\n", encoding="utf-8")
            annotation.write_text("{}\n", encoding="utf-8")
            semantic = root / "semantic-transfer-contracts.jsonl"
            semantic.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "reference contract"):
                build_opaque_stage_b_input_bundle(
                    out=root / "bundle",
                    original_pe=reference,
                    reference_contract=reference,
                    semantic_transfer_contracts=semantic,
                    state_machine=state_machine,
                    manual_annotations=(("invariant", annotation),),
                )

    @staticmethod
    def _negative_case(root: Path) -> CaseManifest:
        artifacts = [
            ArtifactRef.from_path(role=role, root=root, path=root / name).to_payload()
            for role, name in (
                ("semantic_program", "semantic.json"),
                ("original_pe", "original.exe"),
                ("candidate_pe", "candidate.exe"),
                ("relation_contract", "relation.json"),
            )
        ]
        semantic_sha256 = next(
            row["sha256"] for row in artifacts if row["role"] == "semantic_program"
        )
        return CaseManifest.parse({
            "format": "stage-a-roundtrip-case-v1",
            "id": "negative-addend",
            "semantic_program_sha256": semantic_sha256,
            "parent_seed": 1,
            "template": "straight-line",
            "transformations": [],
            "expectation": {
                "disposition": "violated",
                "witness_family": "register-relation-v1",
                "reason_family": None,
            },
            "mutation": {
                "id": "wrong-addend",
                "semantic_delta": "candidate changes the returned word",
                "location_id": "entry-add",
            },
            "capability_profile": "x86-pe32-relational-v3",
            "capabilities": ["direct-jump"],
            "proof_families": ["segment-refinement"],
            "artifacts": artifacts,
            "replay": ["spaghetti-extractor", "stage-a-fuzz-run"],
            "shard": 0,
        })

    @staticmethod
    def _witness_payload(
        case: CaseManifest, case_root: Path, prepared: Path,
    ) -> dict[str, object]:
        registers = {
            register: 0
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        state = {
            "registers": registers,
            "eflags": 2,
            "memory_words": [],
            "path_guards": ["entry-path"],
            "world_state_sha256": "0" * 64,
        }
        return {
            "format": VIOLATION_WITNESS_FORMAT,
            "id": "violation-wrong-addend",
            "obligation_id": "segment:entry-add:register:eax",
            "family": "register-relation-v1",
            "bindings": {
                "original_sha256": case.artifact("original_pe").sha256,
                "candidate_sha256": case.artifact("candidate_pe").sha256,
                "relation_contract_sha256": sha256_file(
                    prepared / "relation-contract.json"
                ),
                "decoded_behaviors_sha256": sha256_file(
                    prepared / "relational-decoded-behaviors.json"
                ),
                "capability_profile": "x86-pe32-relational-v3",
            },
            "location": {
                "original": {
                    "semantic_id": "entry-add",
                    "region_index": 0,
                    "rva": 0x1000,
                    "bytes_hex": "90",
                    "path": ["entry-add"],
                },
                "candidate": {
                    "semantic_id": "entry-add",
                    "region_index": 0,
                    "rva": 0x1000,
                    "bytes_hex": "91",
                    "path": ["entry-add"],
                },
            },
            "original_pre_state": state,
            "candidate_pre_state": state,
            "mismatch": {
                "kind": "register_relation",
                "relation_atom": "eax-exact",
                "original_effect": {"kind": "word", "location": "eax", "value": 1},
                "candidate_effect": {"kind": "word", "location": "eax", "value": 2},
                "observation": "return-value",
                "event_index": None,
            },
            "replay": ["spaghetti-extractor", "stage-a-fuzz-run"],
        }

    @classmethod
    def _automatic_fixture(
        cls, root: Path,
    ) -> tuple[CaseManifest, Path, Path]:
        case_root = root / "case"
        prepared = root / "prepared"
        case_root.mkdir()
        (prepared / "lean" / "StageA").mkdir(parents=True)
        (case_root / "semantic.json").write_text("{}\n", encoding="utf-8")
        (case_root / "original.exe").write_bytes(_pe32_image(b"\x40"))
        (case_root / "candidate.exe").write_bytes(_pe32_image(b"\x48"))
        contract = cls._automatic_contract()
        write_json(case_root / "relation.json", contract)
        write_json(prepared / "relation-contract.json", contract)
        original_sha256 = sha256_file(case_root / "original.exe")
        candidate_sha256 = sha256_file(case_root / "candidate.exe")
        original_ir = cls._behavior_ir("add")
        candidate_ir = cls._behavior_ir("sub")
        decoded = {
            "format": "stage-a-relational-decoded-behaviors-v1",
            "status": "extracted_untrusted_checked_by_generated_lean_proofs",
            "original_sha256": original_sha256,
            "candidate_sha256": candidate_sha256,
            "relation_contract_sha256": sha256_file(
                prepared / "relation-contract.json"
            ),
            "regions": [{
                "index": 0,
                "original_ir": original_ir,
                "candidate_ir": candidate_ir,
                "original_ir_sha256": cls._payload_sha256(original_ir),
                "candidate_ir_sha256": cls._payload_sha256(candidate_ir),
                "original_term": "originalExactDecodedBehavior",
                "candidate_term": "candidateExactDecodedBehavior",
            }],
        }
        write_json(prepared / "relational-decoded-behaviors.json", decoded)
        return cls._negative_case(case_root), case_root, prepared

    @classmethod
    def _non_root_automatic_fixture(
        cls, root: Path,
    ) -> tuple[CaseManifest, Path, Path]:
        case_root = root / "case"
        prepared = root / "prepared"
        case_root.mkdir()
        (prepared / "lean" / "StageA").mkdir(parents=True)
        (case_root / "semantic.json").write_text("{}\n", encoding="utf-8")
        (case_root / "original.exe").write_bytes(_pe32_image(b"\xeb\x00\x40"))
        (case_root / "candidate.exe").write_bytes(_pe32_image(b"\xeb\x00\x48"))
        contract = cls._automatic_contract()
        registers = contract["regions"][0]["inputs"]
        contract["regions"][0].update({
            "id": "entry",
            "function_id": "entry",
            "original": {"rva_start": 0x1000, "rva_end": 0x1002, "size": 2},
            "candidate": {"rva_start": 0x1000, "rva_end": 0x1002, "size": 2},
            "code_targets": [{
                "id": 1, "region_index": 1,
                "original_rva": 0x1002, "candidate_rva": 0x1002,
                "original_aliases": [], "candidate_aliases": [],
            }],
            "target_ids": [1],
        })
        body = dict(contract["regions"][0])
        body.update({
            "id": "body", "numeric_id": 1, "function_id": "body", "root": False,
            "original": {"rva_start": 0x1002, "rva_end": 0x1003, "size": 1},
            "candidate": {"rva_start": 0x1002, "rva_end": 0x1003, "size": 1},
            "code_targets": [], "target_ids": [],
        })
        contract["regions"].append(body)
        contract["code_targets"] = [{
            "id": 0, "region_index": 0,
            "original_rva": 0x1000, "candidate_rva": 0x1000,
            "original_aliases": [], "candidate_aliases": [],
        }, {
            "id": 1, "region_index": 1,
            "original_rva": 0x1002, "candidate_rva": 0x1002,
            "original_aliases": [], "candidate_aliases": [],
        }]
        write_json(case_root / "relation.json", contract)
        write_json(prepared / "relation-contract.json", contract)
        jump_ir = cls._behavior_ir("add")
        jump_ir["registers"] = {
            register: {"op": "input_reg", "reg": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        jump_ir["flags"] = {}
        jump_ir["outcome"] = {"op": "jump", "target": 1}
        original_ir = cls._behavior_ir("add")
        candidate_ir = cls._behavior_ir("sub")
        decoded = {
            "format": "stage-a-relational-decoded-behaviors-v1",
            "status": "extracted_untrusted_checked_by_generated_lean_proofs",
            "original_sha256": sha256_file(case_root / "original.exe"),
            "candidate_sha256": sha256_file(case_root / "candidate.exe"),
            "relation_contract_sha256": sha256_file(
                prepared / "relation-contract.json"
            ),
            "regions": [{
                "index": 0,
                "original_ir": jump_ir, "candidate_ir": jump_ir,
                "original_ir_sha256": cls._payload_sha256(jump_ir),
                "candidate_ir_sha256": cls._payload_sha256(jump_ir),
                "original_term": "entryOriginal", "candidate_term": "entryCandidate",
            }, {
                "index": 1,
                "original_ir": original_ir, "candidate_ir": candidate_ir,
                "original_ir_sha256": cls._payload_sha256(original_ir),
                "candidate_ir_sha256": cls._payload_sha256(candidate_ir),
                "original_term": "bodyOriginal", "candidate_term": "bodyCandidate",
            }],
        }
        write_json(prepared / "relational-decoded-behaviors.json", decoded)
        case_payload = cls._negative_case(case_root).to_payload()
        case_payload["mutation"]["location_id"] = "body"
        case_payload["mutation"]["id"] = "wrong-body-addend"
        return CaseManifest.parse(case_payload), case_root, prepared

    @staticmethod
    def _automatic_contract() -> dict[str, object]:
        registers = [
            {"original": register, "candidate": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        ]
        return {
            "format": "stage-a-relation-contract-v1",
            "regions": [{
                "id": "entry-add",
                "numeric_id": 0,
                "function_id": "entry-add",
                "root": True,
                "original": {"rva_start": 0x1000, "rva_end": 0x1001, "size": 1},
                "candidate": {"rva_start": 0x1000, "rva_end": 0x1001, "size": 1},
                "inputs": registers,
                "input_relations": [
                    {**pair, "relation": "exact"} for pair in registers
                ],
                "outputs": [{"original": "eax", "candidate": "eax"}],
                "output_relations": [{
                    "original": "eax", "candidate": "eax", "relation": "exact",
                }],
                "flag_inputs": [],
                "flag_outputs": [],
                "values": [],
                "bounds": [],
                "address_separations": [],
                "input_dynamic_range_relations": [],
                "input_dynamic_stack_range_relations": [],
                "input_import_relations": [],
            }],
            "code_targets": [],
            "machine_import_call_contracts": [],
        }

    @staticmethod
    def _behavior_ir(operation: str) -> dict[str, object]:
        registers: dict[str, object] = {
            register: {"op": "input_reg", "reg": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        registers["eax"] = {
            "op": operation,
            "left": {"op": "input_reg", "reg": "eax"},
            "right": {"op": "constant", "value": 1},
        }
        return {
            "format": "stage-a-normalized-behavior-v1",
            "registers": registers,
            "writes": [],
            "flags": {},
            "outcome": {"op": "jump", "target": 0},
        }

    @staticmethod
    def _payload_sha256(payload: object) -> str:
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return sha256(encoded).hexdigest()

    @classmethod
    def _replace_decoded_pair(
        cls,
        prepared: Path,
        original_ir: dict[str, object],
        candidate_ir: dict[str, object],
    ) -> None:
        path = prepared / "relational-decoded-behaviors.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        row = payload["regions"][0]
        row["original_ir"] = original_ir
        row["candidate_ir"] = candidate_ir
        row["original_ir_sha256"] = cls._payload_sha256(original_ir)
        row["candidate_ir_sha256"] = cls._payload_sha256(candidate_ir)
        write_json(path, payload)


if __name__ == "__main__":
    unittest.main()
