from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.roundtrip_fuzz.model import CaseManifest, ArtifactRef
from spaghetti_extractor.roundtrip_fuzz.provenance import (
    build_opaque_stage_b_input_bundle,
    validate_opaque_stage_b_input_bundle,
)
from spaghetti_extractor.roundtrip_fuzz.violation import (
    VIOLATION_CHECK_FORMAT,
    VIOLATION_WITNESS_FORMAT,
    validate_checked_violation,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file, write_json
from tests.stage_a_relational_support import _pe32_image


class RoundTripFuzzViolationTests(unittest.TestCase):
    def test_checked_violation_binds_exact_bytes_and_lean_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_root = root / "case"
            prepared = root / "prepared"
            case_root.mkdir()
            prepared.mkdir()
            (case_root / "semantic.json").write_text("{}\n", encoding="utf-8")
            (case_root / "original.exe").write_bytes(_pe32_image(b"\x90\xeb\xfd"))
            (case_root / "candidate.exe").write_bytes(_pe32_image(b"\x91\xeb\xfd"))
            (case_root / "relation.json").write_text("{}\n", encoding="utf-8")
            (prepared / "relation-contract.json").write_text(
                '{"format":"normalized"}\n', encoding="utf-8"
            )
            (prepared / "relational-decoded-behaviors.json").write_text(
                '{"format":"decoded"}\n', encoding="utf-8"
            )
            case = self._negative_case(case_root)
            witness_path = root / "witness.json"
            write_json(witness_path, self._witness_payload(case, case_root, prepared))
            audit_path = root / "audit.json"
            write_json(audit_path, {
                "format": VIOLATION_CHECK_FORMAT,
                "status": "checked",
                "witness_sha256": sha256_file(witness_path),
                "theorem": (
                    "StageA.GeneratedRelationalCounterexample.exactCounterexample"
                ),
                "lean_trust": 0,
                "observed_axioms": ["propext", "Classical.choice", "Quot.sound"],
                "unexpected_axioms": [],
                "decoded_behaviors_sha256": sha256_file(
                    prepared / "relational-decoded-behaviors.json"
                ),
                "original_sha256": case.artifact("original_pe").sha256,
                "candidate_sha256": case.artifact("candidate_pe").sha256,
            })

            result = validate_checked_violation(
                witness_path=witness_path,
                audit_path=audit_path,
                case=case,
                case_root=case_root,
                prepared=prepared,
            )

            self.assertEqual(result["status"], "violated", result)
            self.assertFalse(result["trust"]["can_authorize_pass"])

            audit = dict(__import__("json").loads(audit_path.read_text(encoding="utf-8")))
            audit["status"] = "solver_sat"
            write_json(audit_path, audit)
            rejected = validate_checked_violation(
                witness_path=witness_path,
                audit_path=audit_path,
                case=case,
                case_root=case_root,
                prepared=prepared,
            )
            self.assertEqual(rejected["status"], "incomplete")
            self.assertFalse(rejected["checks"]["audit_checked"])

    def test_opaque_stage_b_bundle_excludes_original_and_undeclared_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reference = root / "reference.json"
            state_machine = root / "state-machine.jsonl"
            annotation = root / "annotation.json"
            reference.write_text("{}\n", encoding="utf-8")
            state_machine.write_text("{}\n", encoding="utf-8")
            annotation.write_text("{}\n", encoding="utf-8")
            bundle = root / "bundle"
            payload = build_opaque_stage_b_input_bundle(
                out=bundle,
                stage_a_artifacts=(
                    ("reference_contract", reference),
                    ("state_machine", state_machine),
                ),
                manual_annotations=(("invariant", annotation),),
            )

            self.assertFalse(payload["policy"]["original_pe_present"])
            self.assertEqual(
                validate_opaque_stage_b_input_bundle(bundle / "manifest.json")["status"],
                "pass",
            )

            (bundle / "inputs" / "undeclared.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "undeclared files"):
                validate_opaque_stage_b_input_bundle(bundle / "manifest.json")

            with self.assertRaisesRegex(StageAInputError, "prohibited"):
                build_opaque_stage_b_input_bundle(
                    out=root / "bad-bundle",
                    stage_a_artifacts=(
                        ("reference_contract", reference),
                        ("state_machine", state_machine),
                        ("original_pe", reference),
                    ),
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


if __name__ == "__main__":
    unittest.main()
