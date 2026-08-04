from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor_target_gnu_hello.gnu_hello_original_target_control_evidence import (
    ORIGINAL_TARGET_CONTROL_BLOCKERS_FORMAT,
    ORIGINAL_TARGET_CONTROL_DECLARATIONS_FORMAT,
    ORIGINAL_TARGET_CONTROL_EVIDENCE_FORMAT,
    OriginalTargetControlEvidenceError,
    generate_original_target_control_evidence,
)


_EFFECTS_FORMAT = "stage-a-gnu-hello-source-transition-index-declarations-v1"
_TRANSITION_FORMAT = "stage-a-gnu-hello-source-transition-index-v1"
_COMBINED_FORMAT = (
    "stage-a-original-combined-execution-inventory-declarations-v1"
)
_NAMESPACE = "StageA.ControlEmitterFixture"
_EFFECT_MODULE = "StageA.ControlEmitterFixture"
_CERTIFICATE_MODULE = "StageA.ControlTransitionShard000000"
_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


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


def _write_json(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row(target_id: int, outcome: dict[str, object]) -> dict[str, object]:
    return {
        "stage_b_format": "stage-b-state-machine-transfer-v1",
        "id": f"target-{target_id}",
        "original": {
            "rva_start": 0x1000 + target_id * 0x10,
            "rva_end": 0x1001 + target_id * 0x10,
        },
        "ordered_events": [],
        "external_events": [],
        "faults": [],
        "outcome": outcome,
    }


def _rva(target_id: int) -> int:
    return 0x1000 + target_id * 0x10


def _representative_rows() -> list[dict[str, object]]:
    rows = [
        _row(0, {"kind": "fallthrough", "target_rva": _rva(1)}),
        _row(1, {"kind": "jump", "target_rva": _rva(2)}),
        _row(
            2,
            {
                "kind": "branch",
                "true_target_rva": _rva(3),
                "false_target_rva": _rva(4),
            },
        ),
        _row(3, {"kind": "fallthrough", "target_rva": _rva(4)}),
        _row(4, {"kind": "return"}),
        _row(5, {"kind": "fallthrough", "target_rva": _rva(6)}),
        _row(6, {"kind": "external_jump"}),
        _row(7, {"kind": "fault"}),
        _row(8, {"kind": "indirect_jump", "target": {"op": "reg", "name": "eax"}}),
        _row(9, {"kind": "external_jump"}),
    ]
    rows[3]["ordered_events"] = [
        {
            "kind": "internal_call",
            "instruction_rva": _rva(3),
            "target_rva": _rva(4),
            "return_rva": _rva(5),
        }
    ]
    rows[5]["ordered_events"] = [
        {
            "kind": "external_call",
            "instruction_rva": _rva(5),
            "return_rva": _rva(6),
            "dll": "fixture.dll",
            "symbol": "returns",
        }
    ]
    return rows


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.rows = _representative_rows()
        self.state_machine = root / "state-machine.jsonl"
        self.state_machine.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in self.rows),
            encoding="ascii",
        )
        targets = []
        for target_id in range(len(self.rows)):
            if target_id == 7:
                evidence = {
                    "facts": {
                        "module": _EFFECT_MODULE,
                        "declaration": f"{_NAMESPACE}.facts{target_id}",
                    },
                    "successful_components": {
                        "module": _EFFECT_MODULE,
                        "declaration": f"{_NAMESPACE}.components{target_id}",
                    },
                }
                kind = "x87"
            else:
                evidence = {
                    "checked_effect": {
                        "module": _EFFECT_MODULE,
                        "declaration": f"{_NAMESPACE}.effect{target_id}",
                    }
                }
                kind = "ordinary"
            targets.append(
                {
                    "target_id": target_id,
                    "source_rva": _rva(target_id),
                    "kind": kind,
                    "evidence": evidence,
                }
            )
        self.effects = _write_json(
            root / "source-target-effect-declarations.json",
            {
                "format": _EFFECTS_FORMAT,
                "namespace": _NAMESPACE,
                "module_prefix": "ControlTransition",
                "shard_span": 512,
                "targets": targets,
            },
        )
        self.transition = _write_json(
            root / "source-transition-index.json",
            {
                "format": _TRANSITION_FORMAT,
                "inputs": {
                    "declaration_inventory": {
                        "path": self.effects.name,
                        "sha256": _sha256(self.effects),
                    }
                },
                "counts": {"targets": len(targets)},
                "modules": [
                    "ControlTransitionData",
                    "ControlTransitionShard000000",
                    "ControlTransition",
                ],
            },
        )
        self.combined = _write_json(
            root / "original-combined-inventory.json",
            {
                "format": _COMBINED_FORMAT,
                "counts": {"reachable_targets": len(targets)},
                "lean": {
                    "module": _EFFECT_MODULE,
                    "program": f"{_NAMESPACE}.program",
                    "original_context": f"{_NAMESPACE}.context",
                    "inventory": f"{_NAMESPACE}.inventory",
                    "reachable_target_ids": f"{_NAMESPACE}.targetIds",
                },
                "external_target_contracts": [
                    {"target_id": 5, "disposition": "returns"},
                    {"target_id": 6, "disposition": "terminates"},
                ],
            },
        )

    def generate(self, out: Path, *, shard_size: int = 3):
        return generate_original_target_control_evidence(
            out,
            source_target_effect_declarations=self.effects,
            transition_index_manifest=self.transition,
            state_machine=self.state_machine,
            combined_target_inventory=self.combined,
            shard_size=shard_size,
        )


class OriginalTargetControlEvidenceTests(unittest.TestCase):
    def test_emits_deterministic_shards_for_all_supported_control_classes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            first = fixture.generate(root / "first")
            second = fixture.generate(root / "second")
            manifest = json.loads(first.manifest.read_text())
            second_manifest = json.loads(second.manifest.read_text())
            declarations = json.loads(first.declarations.read_text())
            blockers = json.loads(first.blockers.read_text())
            generated = "\n".join(path.read_text() for path in first.modules)

        self.assertEqual(first.target_count, 10)
        self.assertEqual(first.shard_count, 4)
        self.assertEqual(first.blocked_count, 2)
        self.assertEqual(manifest, second_manifest)
        self.assertEqual(manifest["format"], ORIGINAL_TARGET_CONTROL_EVIDENCE_FORMAT)
        self.assertEqual(
            declarations["format"], ORIGINAL_TARGET_CONTROL_DECLARATIONS_FORMAT
        )
        self.assertEqual(blockers["format"], ORIGINAL_TARGET_CONTROL_BLOCKERS_FORMAT)
        self.assertEqual(
            [row["control_class"] for row in declarations["targets"]],
            [
                "fallthrough",
                "jump",
                "branch",
                "call",
                "return",
                "external:returns",
                "external:terminates",
                "fault",
                "indirect_jump",
                "external",
            ],
        )
        for required in (
            "FallthroughControl",
            "JumpControl",
            "BranchControl",
            "CallControl",
            "ReturnControl",
            "ExternalCallControl",
            "ExternalJumpControl",
            "TerminatedPost",
            "FaultPost",
            "RunningPost",
            "CallbackRunningPost",
            "CheckedTransition",
            "ReachabilityPost",
            "CallFramePost",
        ):
            self.assertIn(required, generated)
        self.assertNotRegex(generated, r"\b(?:axiom|opaque|sorry|admit|native_decide)\b")

    def test_indirect_and_uncontracted_external_targets_fail_closed_stably(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            result = fixture.generate(fixture.root / "out")
            blockers = json.loads(result.blockers.read_text())["blockers"]

        self.assertEqual(
            blockers,
            [
                {
                    "reason_code": "unresolved_indirect_control",
                    "source_rva": _rva(8),
                    "target_id": 8,
                },
                {
                    "reason_code": "uncontracted_external_control",
                    "source_rva": _rva(9),
                    "target_id": 9,
                },
            ],
        )

    def test_exact_hash_row_inventory_and_contract_shape_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            transition = json.loads(fixture.transition.read_text())
            transition["inputs"]["declaration_inventory"]["sha256"] = "f" * 64
            _write_json(fixture.transition, transition)
            with self.assertRaisesRegex(
                OriginalTargetControlEvidenceError, "does not bind exact"
            ):
                fixture.generate(root / "bad-hash")

            fixture = _Fixture(root / "rows")
            fixture.state_machine.write_text(
                fixture.state_machine.read_text()
                + json.dumps(_row(10, {"kind": "return"}))
                + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                OriginalTargetControlEvidenceError, "inventory differs"
            ):
                fixture.generate(root / "bad-rows")

            fixture = _Fixture(root / "contracts")
            combined = json.loads(fixture.combined.read_text())
            combined["external_target_contracts"][0]["theorem"] = "submitted"
            _write_json(fixture.combined, combined)
            with self.assertRaisesRegex(
                OriginalTargetControlEvidenceError, "contain exactly"
            ):
                fixture.generate(root / "bad-contract")

    def test_production_scale_covers_all_3490_targets_and_keeps_blockers_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            count = 3490
            rows: list[dict[str, object]] = []
            targets: list[dict[str, object]] = []
            controls = ("fallthrough", "jump", "branch", "return")
            for target_id in range(count):
                successor = (target_id + 1) % count
                kind = controls[target_id % len(controls)]
                if target_id == count - 2:
                    outcome: dict[str, object] = {
                        "kind": "indirect_jump",
                        "target": {"op": "reg", "name": "eax"},
                    }
                elif target_id == count - 1:
                    outcome = {"kind": "external_jump"}
                elif kind == "branch":
                    outcome = {
                        "kind": "branch",
                        "true_target_rva": _rva(successor),
                        "false_target_rva": _rva((target_id + 2) % count),
                    }
                elif kind == "return":
                    outcome = {"kind": "return"}
                else:
                    outcome = {"kind": kind, "target_rva": _rva(successor)}
                rows.append(_row(target_id, outcome))
                targets.append(
                    {
                        "target_id": target_id,
                        "source_rva": _rva(target_id),
                        "kind": "ordinary",
                        "evidence": {
                            "checked_effect": {
                                "module": _EFFECT_MODULE,
                                "declaration": f"{_NAMESPACE}.effect{target_id}",
                            }
                        },
                    }
                )
            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                encoding="ascii",
            )
            effects = _write_json(
                root / "effects.json",
                {
                    "format": _EFFECTS_FORMAT,
                    "namespace": _NAMESPACE,
                    "module_prefix": "ControlTransition",
                    "shard_span": 512,
                    "targets": targets,
                },
            )
            transition_modules = [
                "ControlTransitionData",
                *[
                    f"ControlTransitionShard{index:06d}"
                    for index in range((count + 511) // 512)
                ],
                "ControlTransition",
            ]
            transition = _write_json(
                root / "transition.json",
                {
                    "format": _TRANSITION_FORMAT,
                    "inputs": {
                        "declaration_inventory": {
                            "sha256": _sha256(effects),
                        }
                    },
                    "counts": {"targets": count},
                    "modules": transition_modules,
                },
            )
            combined = _write_json(
                root / "combined.json",
                {
                    "format": _COMBINED_FORMAT,
                    "counts": {"reachable_targets": count},
                    "lean": {
                        "module": _EFFECT_MODULE,
                        "program": f"{_NAMESPACE}.program",
                        "original_context": f"{_NAMESPACE}.context",
                        "inventory": f"{_NAMESPACE}.inventory",
                        "reachable_target_ids": f"{_NAMESPACE}.targetIds",
                    },
                },
            )

            def generate(out: Path):
                return generate_original_target_control_evidence(
                    out,
                    source_target_effect_declarations=effects,
                    transition_index_manifest=transition,
                    state_machine=state_machine,
                    combined_target_inventory=combined,
                    shard_size=128,
                )

            first = generate(root / "first")
            second = generate(root / "second")
            first_manifest = json.loads(first.manifest.read_text())
            second_manifest = json.loads(second.manifest.read_text())
            declarations = json.loads(first.declarations.read_text())["targets"]
            blockers = json.loads(first.blockers.read_text())["blockers"]

        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(first.target_count, count)
        self.assertEqual(first.emitted_count, count)
        self.assertEqual(first.shard_count, 28)
        self.assertEqual(len(declarations), count)
        self.assertEqual(
            [row["target_id"] for row in declarations], list(range(count))
        )
        self.assertEqual(
            blockers,
            [
                {
                    "reason_code": "unresolved_indirect_control",
                    "source_rva": _rva(count - 2),
                    "target_id": count - 2,
                },
                {
                    "reason_code": "uncontracted_external_control",
                    "source_rva": _rva(count - 1),
                    "target_id": count - 1,
                },
            ],
        )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_generated_representative_shards_compile_and_pass_axiom_audit(self) -> None:
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
                "RelationalOriginalTargetControlPreservation",
            )
            definitions = "\n".join(
                f"def effect{target_id} : Nat := {target_id}"
                for target_id in range(10)
                if target_id != 7
            )
            (stage_a / "ControlEmitterFixture.lean").write_text(
                """import StageA.RelationalOriginalTargetControlPreservation

namespace StageA.ControlEmitterFixture

def program : Nat := 0
def context : Nat := 0
def inventory : Nat := 0
def targetIds : List Nat := [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
"""
                + definitions
                + """
def facts7 : Nat := 7
def components7 : Nat := 7

end StageA.ControlEmitterFixture
""",
                encoding="ascii",
            )
            (stage_a / "ControlTransitionData.lean").write_text(
                "import StageA.ControlEmitterFixture\n", encoding="ascii"
            )
            certificates = "\n".join(
                f"def generatedActiveTargetTransitionCertificate_{target_id} : Nat := {target_id}"
                for target_id in range(10)
            )
            (stage_a / "ControlTransitionShard000000.lean").write_text(
                """import StageA.ControlTransitionData

namespace StageA.ControlEmitterFixture
"""
                + certificates
                + "\nend StageA.ControlEmitterFixture\n",
                encoding="ascii",
            )
            (stage_a / "ControlTransition.lean").write_text(
                "import StageA.ControlTransitionShard000000\n", encoding="ascii"
            )
            fixture = _Fixture(root / "inputs")
            fixture.generate(root, shard_size=3)
            result = _run_lean_relational(
                root, bundle="GeneratedOriginalTargetControlEvidenceAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
