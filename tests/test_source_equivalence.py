from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.source_equivalence import (
    C0SourceManifest,
    C0ToolchainProfile,
    SOURCE_ACCEPTANCE_INSTANCE_THEOREM,
    _validate_lean_source_bundle,
    generate_c0_source_project,
)
from spaghetti_extractor.stage_b_state_machine import (
    augment_state_machine_with_padding_bridges,
    normalize_stage_a_semantic_transfer,
)
from stage_a_relational_support import _pe32_image


def _tiny_transfer() -> dict:
    instruction_bytes = bytes.fromhex("b807000000c3")
    return {
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": "semantic-transfer:tiny-return-seven",
        "function": "mainCRTStartup",
        "block_id": "entry",
        "status": "reimplementable",
        "reachable": True,
        "expression_model": "stage-a-semantic-ir-v1",
        "original": {"rva_start": 0x1000, "rva_end": 0x1006},
        "instructions": [{"rva": 0x1000, "bytes": instruction_bytes.hex()}],
        "instruction_bytes_sha256": hashlib.sha256(instruction_bytes).hexdigest(),
        "register_writes": [
            {
                "register": "eax",
                "value": {"op": "const", "value": 7, "width": 32},
            }
        ],
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "outcome": {
            "kind": "return",
            "value": {"op": "const", "value": 7, "width": 32},
        },
        "fpu_state": None,
    }


def _write_state_machine(path: Path) -> None:
    row = normalize_stage_a_semantic_transfer(_tiny_transfer())
    path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")


class SourceEquivalenceTests(unittest.TestCase):
    def test_padding_bridge_closes_direct_noop_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(_pe32_image(bytes.fromhex("eb039090909090c3")))
            jump = _tiny_transfer()
            jump.update({
                "id": "semantic-transfer:jump-to-padding",
                "block_id": "jump-to-padding",
                "original": {"rva_start": 0x1000, "rva_end": 0x1002},
                "instructions": [{
                    "rva": 0x1000, "size": 2, "bytes": "eb03",
                    "mnemonic": "jmp", "op_str": "0x401005",
                }],
                "instruction_bytes_sha256": hashlib.sha256(
                    bytes.fromhex("eb03")
                ).hexdigest(),
                "register_writes": [],
                "flag_writes": [],
                "edge_conditions": [
                    {"condition": {"op": "true"}, "target_rva": 0x1005}
                ],
                "outcome": {"kind": "jump", "target_rva": 0x1005},
            })
            returned = _tiny_transfer()
            returned.update({
                "id": "semantic-transfer:return-after-padding",
                "block_id": "return-after-padding",
                "original": {"rva_start": 0x1007, "rva_end": 0x1008},
                "instructions": [{
                    "rva": 0x1007, "size": 1, "bytes": "c3",
                    "mnemonic": "ret", "op_str": "",
                }],
                "instruction_bytes_sha256": hashlib.sha256(b"\xc3").hexdigest(),
            })
            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(
                "".join(
                    json.dumps(normalize_stage_a_semantic_transfer(row), sort_keys=True)
                    + "\n"
                    for row in (jump, returned)
                ),
                encoding="utf-8",
            )
            block_map = root / "map.json"
            block_map.write_text(json.dumps({
                "waivers": [{
                    "id": "original-padding-1005-1007",
                    "binary": "original",
                    "rva": 0x1005,
                    "size": 2,
                }]
            }), encoding="utf-8")

            result = augment_state_machine_with_padding_bridges(
                state_machine=state_machine,
                original_pe=original,
                block_map=block_map,
                out=root / "augmented.jsonl",
            )

            self.assertEqual(result.padding_bridge_count, 1)
            self.assertEqual(result.bridged_rvas, (0x1005,))
            rows = [
                json.loads(line)
                for line in (root / "augmented.jsonl").read_text().splitlines()
            ]
            bridge = next(row for row in rows if row["original"]["rva_start"] == 0x1005)
            self.assertEqual(bridge["outcome"], {
                "kind": "fallthrough", "target_rva": 0x1007,
            })
            self.assertEqual([item["mnemonic"] for item in bridge["instructions"]], [
                "nop", "nop",
            ])

    def test_padding_bridge_rejects_non_noop_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(_pe32_image(bytes.fromhex("eb039090904090c3")))
            jump = _tiny_transfer()
            jump.update({
                "id": "semantic-transfer:jump-to-code",
                "block_id": "jump-to-code",
                "original": {"rva_start": 0x1000, "rva_end": 0x1002},
                "instructions": [{"rva": 0x1000, "size": 2, "bytes": "eb03"}],
                "instruction_bytes_sha256": hashlib.sha256(
                    bytes.fromhex("eb03")
                ).hexdigest(),
                "register_writes": [],
                "flag_writes": [],
                "outcome": {"kind": "jump", "target_rva": 0x1005},
            })
            returned = _tiny_transfer()
            returned.update({
                "id": "semantic-transfer:return-after-code",
                "block_id": "return-after-code",
                "original": {"rva_start": 0x1007, "rva_end": 0x1008},
                "instructions": [{"rva": 0x1007, "size": 1, "bytes": "c3"}],
                "instruction_bytes_sha256": hashlib.sha256(b"\xc3").hexdigest(),
            })
            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(
                "".join(
                    json.dumps(normalize_stage_a_semantic_transfer(row), sort_keys=True)
                    + "\n"
                    for row in (jump, returned)
                ),
                encoding="utf-8",
            )
            block_map = root / "map.json"
            block_map.write_text(json.dumps({"waivers": [{
                "id": "invalid-padding", "binary": "original",
                "rva": 0x1005, "size": 2,
            }]}), encoding="utf-8")

            with self.assertRaisesRegex(Exception, "non-no-op instruction"):
                augment_state_machine_with_padding_bridges(
                    state_machine=state_machine,
                    original_pe=original,
                    block_map=block_map,
                    out=root / "augmented.jsonl",
                )

    def test_c0_toolchain_profile_rejects_flag_drift(self) -> None:
        payload = {
            "format": "stage-a-c0-toolchain-profile-v1",
            "id": "i686-mingw-freestanding-c0-v1",
            "target": "i686-w64-mingw32",
            "tools": {
                name: {"path": f"/nix/store/example/bin/{name}", "sha256": "0" * 64}
                for name in ("compiler", "assembler", "linker")
            },
            "flags": [
                "-std=c11",
                "-O0",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-asynchronous-unwind-tables",
                "-nostdlib",
                "-Wl,--entry,_mainCRTStartup",
                "-Wl,--subsystem,console",
                "-Wl,--no-insert-timestamp",
            ],
            "runtime": {
                "profile": "spaghetti-c0-runtime-v1",
                "sha256": "1" * 64,
            },
            "policy": {
                "crt": False,
                "threads": False,
                "inline_assembly": False,
                "undefined_behavior": False,
                "windows_apis_are_external_events": True,
                "correctness_is_a_lean_theorem_parameter": True,
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            profile.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(
                C0ToolchainProfile.load(profile).identifier,
                "i686-mingw-freestanding-c0-v1",
            )
            payload["flags"][1] = "-O2"
            profile.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(Exception, "compiler flags differ"):
                C0ToolchainProfile.load(profile)

    def test_unimplemented_runtime_transfer_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transfer = _tiny_transfer()
            transfer["register_writes"][0]["register"] = "ebx"
            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(
                json.dumps(normalize_stage_a_semantic_transfer(transfer), sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            result = generate_c0_source_project(
                state_machine=state_machine,
                entry_rva=0x1000,
                out_dir=root / "source",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn(
                "c0_v1_runtime_transfer_not_implemented",
                {blocker["code"] for blocker in result["blockers"]},
            )

            manifest_path = root / "source/source-manifest.json"
            manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_payload["status"] = "complete"
            manifest_path.write_text(
                json.dumps(manifest_payload, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                Exception, "complete C0 source manifest contains blockers"
            ):
                C0SourceManifest.load(manifest_path)

    def test_c0_source_is_canonical_hash_bound_and_compiler_consumable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_machine = root / "state-machine.jsonl"
            _write_state_machine(state_machine)
            result = generate_c0_source_project(
                state_machine=state_machine,
                entry_rva=0x1000,
                out_dir=root / "source",
            )

            self.assertEqual(result["status"], "complete", result)
            self.assertFalse(result["trust"]["python_renderer_authoritative"])
            self.assertFalse(result["trust"]["original_instruction_bytes_embedded"])
            manifest_path = root / "source/source-manifest.json"
            manifest = C0SourceManifest.load(manifest_path)
            manifest.validate_files(manifest_path.parent)
            source = (root / "source/c0-program.c").read_text(encoding="ascii")
            self.assertIn("spaghetti_c0_program", source)
            self.assertNotIn("b807000000c3", source)

            compiler = shutil.which("i686-w64-mingw32-gcc")
            if compiler is not None:
                subprocess.run(
                    [
                        compiler,
                        "-std=c11",
                        "-O0",
                        "-ffreestanding",
                        "-fno-builtin",
                        "-fno-asynchronous-unwind-tables",
                        "-nostdlib",
                        "-Wl,--entry,_mainCRTStartup",
                        "-Wl,--subsystem,console",
                        "-Wl,--no-insert-timestamp",
                        "c0-program.c",
                        "spaghetti-c0-runtime-v1.c",
                        "-o",
                        "candidate.exe",
                    ],
                    cwd=root / "source",
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertTrue((root / "source/candidate.exe").is_file())

            (root / "source/c0-program.c").write_text(source + "\n", encoding="ascii")
            with self.assertRaisesRegex(Exception, "artifact (size|hash) changed"):
                manifest.validate_files(manifest_path.parent)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for source checks")
    def test_lean_independently_renders_the_generated_c0_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_machine = root / "state-machine.jsonl"
            _write_state_machine(state_machine)
            generate_c0_source_project(
                state_machine=state_machine,
                entry_rva=0x1000,
                out_dir=root / "source",
            )
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            lean_root = root / "lean"
            shutil.copytree(source_root, lean_root / "StageA")
            shutil.copyfile(
                root / "source/GeneratedC0Program.lean",
                lean_root / "StageA/GeneratedC0Program.lean",
            )
            result = _run_lean_relational(
                lean_root,
                bundle="GeneratedC0Program",
            )
            self.assertEqual(result["status"], "checked", result)
            self.assertNotIn("sorryAx", result["stdout"])

    def test_source_audit_alone_cannot_authorize_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            manifest = root / "source-manifest.json"
            original.write_bytes(b"not inspected by this unit")
            manifest.write_text("{}\n", encoding="utf-8")
            source_checks = {
                "StageA.GeneratedRelational.generatedC0SourceExact": [
                    "Classical.choice", "Quot.sound", "propext"
                ],
                "StageA.GeneratedRelational.generatedC0ProgramClosed": ["propext"],
            }
            result = _validate_lean_source_bundle(
                {
                    "format": "stage-a-lean-target-bundle-v2",
                    "lean_trust": 0,
                    "nodes": [
                        {
                            "outputs": [
                                {
                                    "axiom_audit": {
                                        "complete": True,
                                        "requested": list(source_checks),
                                        "inventories": source_checks,
                                    }
                                }
                            ]
                        }
                    ],
                },
                {
                    "format": "stage-a-c0-proof-binding-v1",
                    "original_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
                    "source_manifest_sha256": hashlib.sha256(
                        manifest.read_bytes()
                    ).hexdigest(),
                    "acceptance_theorem": SOURCE_ACCEPTANCE_INSTANCE_THEOREM,
                },
                manifest,
                original,
            )
            self.assertIn(
                "lean_original_source_whole_program_theorem_missing",
                {issue["code"] for issue in result["issues"]},
            )

    def test_unapproved_axiom_on_acceptance_instance_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            manifest = root / "source-manifest.json"
            original.write_bytes(b"unit")
            manifest.write_text("{}\n", encoding="utf-8")
            result = _validate_lean_source_bundle(
                {
                    "format": "stage-a-lean-target-bundle-v2",
                    "lean_trust": 0,
                    "nodes": [
                        {
                            "outputs": [
                                {
                                    "axiom_audit": {
                                        "complete": True,
                                        "requested": [SOURCE_ACCEPTANCE_INSTANCE_THEOREM],
                                        "inventories": {
                                            SOURCE_ACCEPTANCE_INSTANCE_THEOREM: ["sorryAx"]
                                        },
                                    }
                                },
                                {
                                    "axiom_audit": {
                                        "complete": True,
                                        "requested": [
                                            SOURCE_ACCEPTANCE_INSTANCE_THEOREM
                                        ],
                                        "inventories": {
                                            SOURCE_ACCEPTANCE_INSTANCE_THEOREM: [
                                                "propext"
                                            ]
                                        },
                                    }
                                }
                            ]
                        }
                    ],
                },
                {
                    "format": "stage-a-c0-proof-binding-v1",
                    "original_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
                    "source_manifest_sha256": hashlib.sha256(
                        manifest.read_bytes()
                    ).hexdigest(),
                    "acceptance_theorem": SOURCE_ACCEPTANCE_INSTANCE_THEOREM,
                },
                manifest,
                original,
            )
            self.assertIn(
                "unapproved_lean_axioms",
                {issue["code"] for issue in result["issues"]},
            )


if __name__ == "__main__":
    unittest.main()
