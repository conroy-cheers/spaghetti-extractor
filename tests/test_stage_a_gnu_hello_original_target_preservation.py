from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor_target_gnu_hello.gnu_hello_original_target_preservation import (
    GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_FORMAT,
    GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_NEEDS_FORMAT,
    GnuHelloOriginalTargetPreservationError,
    generate_gnu_hello_original_target_preservation,
)


_EFFECTS_FORMAT = "stage-a-gnu-hello-source-transition-index-declarations-v1"
_TRANSITION_FORMAT = "stage-a-gnu-hello-source-transition-index-v1"
_COMBINED_FORMAT = "stage-a-original-combined-execution-inventory-declarations-v1"
_CONTEXT_FORMAT = "stage-a-original-execution-preservation-context-v1"
_MODULE = "StageA.TargetPreservationFixture"


def _ref(name: str) -> dict[str, str]:
    return {"module": _MODULE, "declaration": f"{_MODULE}.{name}"}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _value_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    return path


def _state_row(
    target_id: int,
    *,
    control: str = "fallthrough",
    memory: str = "none",
    external: bool = False,
) -> dict[str, object]:
    events: list[dict[str, object]] = []
    if memory == "read_only":
        events.append({"kind": "read", "address": {"op": "reg", "name": "eax"}})
    elif memory == "stack_writes":
        events.append({"kind": "write", "address": {"op": "reg", "name": "esp"}})
    elif memory == "static_writes":
        events.append(
            {"kind": "write", "address": {"op": "const", "value": 0x5000}}
        )
    elif memory == "symbolic_writes":
        events.append(
            {
                "kind": "write",
                "address": {
                    "op": "add32",
                    "args": [
                        {"op": "reg", "name": "eax"},
                        {"op": "reg", "name": "ecx"},
                    ],
                },
            }
        )
    outcome: dict[str, object] = {"kind": control}
    if control in {"fallthrough", "jump"}:
        outcome["target_rva"] = 0x1000 + target_id
    elif control == "branch":
        outcome["true_target_rva"] = 0x1000 + target_id
        outcome["false_target_rva"] = 0x1000 + target_id
    return {
        "id": f"target-{target_id}",
        "original": {
            "rva_start": 0x1000 + target_id,
            "rva_end": 0x1001 + target_id,
        },
        "outcome": outcome,
        "memory_events": events,
        "external_events": [{"kind": "external_call"}] if external else [],
    }


class _Fixture:
    def __init__(
        self, root: Path, rows: list[dict[str, object]], kinds: list[str]
    ) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.state_machine = root / "state-machine.jsonl"
        self.state_machine.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="ascii",
        )
        span = 512
        namespace = "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex"
        modules = sorted(
            {
                f"GeneratedGnuHelloSourceTransitionIndexShard{index // span:06d}"
                for index in range(len(rows))
            }
        )
        targets = []
        for target_id, (row, kind) in enumerate(zip(rows, kinds, strict=True)):
            module = f"StageA.TargetEffects{target_id // span:06d}"
            if kind == "ordinary":
                evidence = {
                    "checked_effect": {
                        "module": module,
                        "declaration": f"{module}.checked{target_id}",
                    }
                }
            else:
                evidence = {
                    "facts": {
                        "module": module,
                        "declaration": f"{module}.facts{target_id}",
                    },
                    "successful_components": {
                        "module": module,
                        "declaration": f"{module}.components{target_id}",
                    },
                }
            original = row["original"]
            assert isinstance(original, dict)
            targets.append(
                {
                    "target_id": target_id,
                    "source_rva": original["rva_start"],
                    "kind": kind,
                    "evidence": evidence,
                }
            )
        self.effects = _write(
            root / "source-target-effect-declarations.json",
            {
                "format": _EFFECTS_FORMAT,
                "namespace": namespace,
                "module_prefix": "GeneratedGnuHelloSourceTransitionIndex",
                "shard_span": span,
                "targets": targets,
            },
        )
        self.transition = _write(
            root / "source-transition-index.json",
            {
                "format": _TRANSITION_FORMAT,
                "inputs": {
                    "declaration_inventory": {
                        "path": self.effects.name,
                        "sha256": _sha(self.effects),
                    }
                },
                "counts": {"targets": len(rows)},
                "modules": modules,
                "exports": {
                    "exact_source_program": (
                        "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex."
                        "generatedExactSourceProgram"
                    ),
                    "instruction_semantics_adequate": (
                        "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex."
                        "generatedInstructionSemanticsAdequate"
                    ),
                },
            },
        )
        self.combined = _write(
            root / "original-combined-inventory.json",
            {
                "format": _COMBINED_FORMAT,
                "inputs": {},
                "lean": {
                    "module": "StageA.CombinedFixture",
                    "inventory": "StageA.CombinedFixture.inventory",
                    "original_context": "StageA.CombinedFixture.context",
                },
                "counts": {
                    "reachable_targets": len(rows),
                    "static_word_slots": 3,
                    "register_requirements": 2,
                    "stack_dynamic_requirements": 1,
                    "value_flow_facts": 4,
                },
            },
        )

    @property
    def hashes(self) -> dict[str, str]:
        return {
            "state_machine_sha256": _sha(self.state_machine),
            "source_target_effect_declarations_sha256": _sha(self.effects),
            "transition_index_manifest_sha256": _sha(self.transition),
            "combined_inventory_manifest_sha256": _sha(self.combined),
        }

    def context(self) -> Path:
        return _write(
            self.root / "context.json",
            {
                "format": _CONTEXT_FORMAT,
                "inputs": self.hashes,
                "declarations": {
                    "source_program": _ref("sourceProgram"),
                    "instruction_semantics_adequate": _ref("adequate"),
                },
            },
        )

    def runtime_and_control(self) -> dict[str, Path]:
        mixed = _write(
            self.root / "mixed-original.json",
            {"format": "fixture", "targets": len(json.loads(self.combined.read_text())["counts"])},
        )
        input_paths = {
            "mixed_original_plan": mixed,
            "source_target_effect_declarations": self.effects,
            "state_machine": self.state_machine,
        }
        input_hashes = {name: _sha(path) for name, path in input_paths.items()}
        binding = _value_sha(dict(sorted(input_hashes.items())))
        proposal_targets: list[dict[str, object]] = []
        check_targets: list[dict[str, object]] = []
        rows = [json.loads(line) for line in self.state_machine.read_text().splitlines()]
        for target_id, row in enumerate(rows):
            original = row["original"]
            writes = []
            for index, event in enumerate(row.get("memory_events", [])):
                if event.get("kind") != "write":
                    continue
                address = event["address"]
                if address.get("op") == "const":
                    provenance = {"class": "image_static_slot"}
                elif address.get("op") == "reg" and address.get("name") in {"esp", "ebp"}:
                    provenance = {"class": "stack_range"}
                else:
                    provenance = {"class": "dynamic_range"}
                writes.append(
                    {
                        "address_expression": address,
                        "address_expression_sha256": _value_sha(address),
                        "provenance": provenance,
                        "width": 4,
                        "write_id": f"target-{target_id}-write-{index:04d}",
                    }
                )
            target = {
                "artifact_binding_sha256": binding,
                "blockers": [],
                "ready_for_lean_check": True,
                "source_rva": original["rva_start"],
                "target_id": target_id,
                "writes": writes,
            }
            target["requirement_sha256"] = _value_sha(target)
            proposal_targets.append(target)
            check_targets.append(
                {
                    "artifact_binding_sha256": binding,
                    "ready_for_lean_check": True,
                    "requirement_sha256": target["requirement_sha256"],
                    "source_rva": original["rva_start"],
                    "target_id": target_id,
                    "write_ids": [write["write_id"] for write in writes],
                }
            )
        proposal = _write(
            self.root / "runtime-memory-access-proposal.json",
            {
                "artifact_binding_sha256": binding,
                "format": "stage-a-runtime-memory-access-proposal-v1",
                "inputs": {
                    name: {"path": path.name, "sha256": input_hashes[name]}
                    for name, path in sorted(input_paths.items())
                },
                "targets": proposal_targets,
            },
        )
        check = _write(
            self.root / "runtime-memory-partition-check-inputs.json",
            {
                "artifact_binding_sha256": binding,
                "format": "stage-a-runtime-memory-partition-check-inputs-v1",
                "proposal": {"path": proposal.name, "sha256": _sha(proposal)},
                "targets": check_targets,
            },
        )
        declarations = _write(
            self.root / "original-target-control-evidence-declarations.json",
            {
                "format": "stage-a-original-target-control-evidence-declarations-v1",
                "targets": [
                    {
                        "call_frame_post": f"StageA.Control.target{target_id}CallFramePost",
                        "checked_transition": f"StageA.Control.target{target_id}CheckedTransition",
                        "control_class": row["outcome"]["kind"],
                        "module": "StageA.Control",
                        "reachability_post": f"StageA.Control.target{target_id}ReachabilityPost",
                        "source_rva": row["original"]["rva_start"],
                        "target_id": target_id,
                    }
                    for target_id, row in enumerate(rows)
                ],
            },
        )
        blockers = _write(
            self.root / "original-target-control-evidence-blockers.json",
            {
                "format": "stage-a-original-target-control-evidence-blockers-v1",
                "blockers": [],
            },
        )
        control = _write(
            self.root / "original-target-control-evidence.json",
            {
                "format": "stage-a-original-target-control-evidence-v1",
                "inputs": {
                    "combined_target_inventory": _sha(self.combined),
                    "source_target_effect_declarations": _sha(self.effects),
                    "state_machine": _sha(self.state_machine),
                    "transition_index_manifest": _sha(self.transition),
                },
                "declarations": declarations.name,
                "blockers": blockers.name,
            },
        )
        return {"runtime": check, "control": control}

    def generate(
        self,
        out: Path,
        authorities: dict[str, Path] | None = None,
        *,
        shard_size: int = 64,
    ):
        return generate_gnu_hello_original_target_preservation(
            out,
            state_machine=self.state_machine,
            source_target_effect_declarations=self.effects,
            transition_index_manifest=self.transition,
            combined_inventory_manifest=self.combined,
            authority_artifacts=authorities,
            shard_size=shard_size,
        )


class GnuHelloOriginalTargetPreservationTests(unittest.TestCase):
    def test_autonomously_emits_checked_seeds_but_not_false_providers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(
                root,
                [
                    _state_row(0, memory="read_only"),
                    _state_row(1, control="return", memory="stack_writes"),
                ],
                ["ordinary", "x87"],
            )
            result = fixture.generate(
                root / "out", {"context": fixture.context()}, shard_size=1
            )
            declarations = json.loads(result.declarations.read_text())
            frontier = json.loads(result.frontier.read_text())
            generated = "\n".join(path.read_text() for path in result.modules)

        self.assertEqual(result.target_count, 2)
        self.assertEqual(result.checked_seed_count, 2)
        self.assertEqual(result.complete_count, 0)
        self.assertEqual(result.blocked_count, 2)
        self.assertEqual(result.shard_count, 2)
        self.assertEqual(len(declarations["targets"]), 2)
        self.assertIn("generatedTarget0CheckedEffect", generated)
        self.assertIn("generatedTarget0NormalizedEffectsImplement", generated)
        self.assertIn("generatedTarget0RuntimeMemoryBefore", generated)
        self.assertIn("generatedTarget1Certificate", generated)
        self.assertNotIn("Provider :", generated)
        self.assertNotRegex(generated, r"\b(?:axiom|opaque|sorry|admit)\b")
        self.assertEqual(frontier["counts"]["checked_seeds"], 2)
        self.assertFalse(frontier["ready"])

    def test_rejects_externally_supplied_structured_post_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root, [_state_row(0)], ["ordinary"])
            supplied = _write(
                root / "supplied.json",
                {
                    "format": "stage-a-original-target-structured-post-evidence-v1",
                    "targets": [{"target_id": 0, "components": {"post": _ref("post")}}],
                },
            )
            with self.assertRaisesRegex(
                GnuHelloOriginalTargetPreservationError,
                "must derive it autonomously",
            ):
                fixture.generate(
                    root / "out",
                    {"context": fixture.context(), "supplied": supplied},
                )

    def test_memory_classes_report_exact_soundness_artifact_needs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(
                root,
                [
                    _state_row(0),
                    _state_row(1, memory="stack_writes"),
                    _state_row(2, memory="symbolic_writes"),
                    _state_row(3, memory="static_writes"),
                ],
                ["ordinary"] * 4,
            )
            authorities = {"context": fixture.context(), **fixture.runtime_and_control()}
            result = fixture.generate(root / "out", authorities)
            frontier = json.loads(result.frontier.read_text())
            needs = json.loads(result.needs.read_text())
            declarations = json.loads(result.declarations.read_text())
            generated = "\n".join(path.read_text() for path in result.modules)

        blocked = {row["target_id"]: row for row in frontier["blockers"]}
        self.assertNotIn(0, blocked)
        self.assertEqual(frontier["counts"]["complete"], 1)
        self.assertEqual(result.complete_count, 1)
        declaration_by_target = {
            row["target_id"]: row for row in declarations["targets"]
        }
        self.assertEqual(
            declaration_by_target[0]["provider"],
            "StageA.GeneratedRelational.GnuHelloOriginalTargetPreservation."
            "generatedTarget0Provider",
        )
        self.assertIn("generatedTarget0NoWriteEvidence", generated)
        self.assertIn("generatedTarget0FamilyPreservation", generated)
        self.assertNotRegex(generated, r"\b(?:axiom|opaque|sorry|admit)\b")
        self.assertIn("runtime_write_membership_lean_check", blocked[1]["missing_checked_evidence"])
        self.assertIn("runtime_write_membership_lean_check", blocked[2]["missing_checked_evidence"])
        self.assertIn("static_write_relation", blocked[3]["missing_checked_evidence"])
        self.assertEqual(needs["format"], GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_NEEDS_FORMAT)
        requirement = {
            row["id"]: row for row in needs["required_artifacts"]
        }["checked_runtime_write_membership"]
        self.assertEqual(requirement["target_ids"], [1, 2])

    def test_consumes_hash_bound_runtime_and_control_proposals_without_trusting_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(
                root,
                [_state_row(0, memory="stack_writes")],
                ["ordinary"],
            )
            authorities = {"context": fixture.context(), **fixture.runtime_and_control()}
            result = fixture.generate(root / "out", authorities)
            frontier = json.loads(result.frontier.read_text())
            declarations = json.loads(result.declarations.read_text())
            generated = "\n".join(path.read_text() for path in result.modules)

        missing = frontier["blockers"][0]["missing_checked_evidence"]
        self.assertNotIn("runtime_memory_check_input", missing)
        self.assertNotIn("control_check_input", missing)
        self.assertIn("runtime_write_membership_lean_check", missing)
        self.assertIn("control_routing_lean_check", missing)
        self.assertIsNotNone(declarations["targets"][0]["runtime_memory_proposal"])
        self.assertIsNotNone(declarations["targets"][0]["control_proposal"])
        self.assertIn("RuntimeWriteProposalsExact", generated)
        self.assertIn("ControlProposal", generated)
        self.assertEqual(result.complete_count, 0)

    def test_tampered_runtime_proposal_fails_before_lean_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(
                root,
                [_state_row(0, memory="stack_writes")],
                ["ordinary"],
            )
            authorities = {"context": fixture.context(), **fixture.runtime_and_control()}
            check = json.loads(authorities["runtime"].read_text())
            proposal = root / check["proposal"]["path"]
            value = json.loads(proposal.read_text())
            value["targets"][0]["writes"][0]["width"] = 8
            _write(proposal, value)
            with self.assertRaisesRegex(
                GnuHelloOriginalTargetPreservationError,
                "does not bind its exact proposal",
            ):
                fixture.generate(root / "out", authorities)

    def test_indirect_authority_is_checked_by_source_rva(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(
                root, [_state_row(0, control="indirect_jump")], ["ordinary"]
            )
            blocked = fixture.generate(root / "blocked", {"context": fixture.context()})
            blocker = json.loads(blocked.frontier.read_text())["blockers"][0]
            self.assertIn("indirect_target_authority", blocker["missing_checked_evidence"])

            site = _write(
                root / "site.json",
                {
                    "format": "stage-a-register-indirect-control-authorities-v1",
                    "sites": [{"source_rva": 0x1000}],
                },
            )
            with_site = fixture.generate(
                root / "with-site", {"context": fixture.context(), "site": site}
            )
            blocker = json.loads(with_site.frontier.read_text())["blockers"][0]
            self.assertNotIn(
                "indirect_target_authority", blocker["missing_checked_evidence"]
            )

    def test_transition_hash_and_state_row_omission_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root, [_state_row(0)], ["ordinary"])
            transition = json.loads(fixture.transition.read_text())
            transition["inputs"]["declaration_inventory"]["sha256"] = "f" * 64
            _write(fixture.transition, transition)
            with self.assertRaisesRegex(
                GnuHelloOriginalTargetPreservationError,
                "does not bind exact target-effect declarations",
            ):
                fixture.generate(root / "bad-hash")

            fixture = _Fixture(root / "second", [_state_row(0)], ["ordinary"])
            fixture.state_machine.write_text(
                json.dumps(_state_row(1), sort_keys=True) + "\n", encoding="ascii"
            )
            with self.assertRaisesRegex(
                GnuHelloOriginalTargetPreservationError,
                "omits reachable source RVAs",
            ):
                fixture.generate(root / "missing-row")

    def test_scale_emits_all_3490_checked_seeds_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            controls = ("fallthrough", "jump", "branch", "return", "external_jump")
            memories = ("none", "read_only", "stack_writes", "static_writes")
            rows = [
                _state_row(
                    target_id,
                    control=controls[target_id % len(controls)],
                    memory=memories[target_id % len(memories)],
                    external=target_id % 17 == 0,
                )
                for target_id in range(3490)
            ]
            kinds = [
                "x87" if target_id % 97 == 0 else "ordinary"
                for target_id in range(3490)
            ]
            fixture = _Fixture(root, rows, kinds)
            context = fixture.context()
            first = fixture.generate(
                root / "first", {"context": context}, shard_size=128
            )
            second = fixture.generate(
                root / "second", {"context": context}, shard_size=128
            )
            first_manifest = json.loads(first.manifest.read_text())
            second_manifest = json.loads(second.manifest.read_text())
            declarations = json.loads(first.declarations.read_text())
            frontier = json.loads(first.frontier.read_text())
            needs = json.loads(first.needs.read_text())
            generated = "\n".join(path.read_text() for path in first.modules)

        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(first_manifest["format"], GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_FORMAT)
        self.assertEqual(first.target_count, 3490)
        self.assertEqual(first.checked_seed_count, 3490)
        self.assertEqual(first.complete_count, 0)
        self.assertEqual(first.blocked_count, 3490)
        self.assertEqual(len(declarations["targets"]), 3490)
        self.assertTrue(
            all(row["runtime_memory_precondition"] for row in declarations["targets"])
        )
        self.assertEqual(generated.count("RuntimeMemoryBefore"), 3490)
        self.assertEqual(
            needs["currently_emitted"]["checked_runtime_memory_preconditions"],
            3490,
        )
        self.assertEqual(len(frontier["blockers"]), 3490)
        self.assertEqual(
            [row["target_id"] for row in frontier["blockers"]], list(range(3490))
        )


if __name__ == "__main__":
    unittest.main()
