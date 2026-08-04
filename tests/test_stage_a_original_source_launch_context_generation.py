from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor_target_gnu_hello.gnu_hello_original_source_launch_context import (
    CHECKED_PROTOCOL_RESPONSES_DECLARATIONS_FORMAT,
    ORIGINAL_SOURCE_LAUNCH_CONTEXT_FORMAT,
    OriginalSourceLaunchContextError,
    generate_original_source_launch_context,
)
from spaghetti_extractor.util import sha256_file


def _write(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    return path


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.combined = _write(
            root / "combined.json",
            {
                "format": (
                    "stage-a-original-combined-execution-inventory-"
                    "declarations-v1"
                ),
                "lean": {
                    "module": (
                        "StageA.GeneratedRelationalOriginalCombinedInventory"
                    ),
                    "namespace": (
                        "StageA.GeneratedRelational.OriginalCombinedInventory"
                    ),
                    "inventory": (
                        "StageA.GeneratedRelational.OriginalCombinedInventory."
                        "generatedInventory"
                    ),
                    "original_context": (
                        "StageA.GeneratedRelational.OriginalCombinedInventory."
                        "generatedOriginalContext"
                    ),
                },
                "static_word_slots": [
                    {
                        "slot_rva": 0x2000 + index * 4,
                        "relation": "fixed_code_pointer",
                        "declaration": (
                            "StageA.GeneratedRelational."
                            "OriginalCombinedInventory."
                            f"generatedStaticWordRequirement{index:04d}"
                        ),
                    }
                    for index in range(3)
                ],
            },
        )
        namespace = "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex"
        self.transition_document = {
            "format": "stage-a-gnu-hello-source-transition-index-v1",
            "modules": [
                "GeneratedGnuHelloSourceTransitionIndexData",
                "GeneratedGnuHelloSourceTransitionIndexShard000000",
                "GeneratedGnuHelloSourceTransitionIndex",
            ],
            "exports": {
                "concrete_exact_binding": (
                    f"{namespace}.generatedConcreteExactBinding"
                ),
                "active_target_transition_index": (
                    f"{namespace}.generatedActiveTargetTransitionIndex"
                ),
                "active_target_ids_exact": (
                    f"{namespace}.generatedActiveTargetIdsExact"
                ),
            },
        }
        self.transition = _write(
            root / "transition.json", self.transition_document
        )
        self.compiled = _write(
            root / "compiled.json",
            {
                "format": (
                    "stage-a-gnu-hello-native-source-compiled-authority-"
                    "declarations-v1"
                ),
                "lean": {
                    "namespace": (
                        "StageA.GeneratedRelational."
                        "GnuHelloNativeSourceCompiledAuthority"
                    ),
                    "output_module": (
                        "GeneratedGnuHelloNativeSourceCompiledAuthority"
                    ),
                },
            },
        )
        self.effects = _write(
            root / "effects.json", {"exact_checked_effects": [1, 2, 3]}
        )
        self.runtime = _write(
            root / "runtime.json",
            {
                "format": "stage-a-gnu-hello-runtime-foundation-v1",
                "outputs": {
                    "lean_module": "StageA/GeneratedGnuHelloRuntimeFoundation.lean"
                },
            },
        )
        self.target = _write(
            root / "target.json",
            {
                "format": "stage-a-original-execution-proof-v1",
                "exports": {
                    "target_step_index": {
                        "module": "StageA.GeneratedTargetStepFixture",
                        "declaration": (
                            "StageA.GeneratedTargetStepFixture."
                            "generatedCombinedTargetStepIndex"
                        ),
                    }
                },
            },
        )
        self.protocol_document = {
            "format": CHECKED_PROTOCOL_RESPONSES_DECLARATIONS_FORMAT,
            "inputs": {
                "combined_inventory_manifest": sha256_file(self.combined),
                "transition_index_manifest": sha256_file(self.transition),
                "compiled_authority_declarations": sha256_file(self.compiled),
            },
            "lean": {
                "module": "StageA.GeneratedCheckedProtocolFixture",
                "responses": (
                    "StageA.GeneratedCheckedProtocolFixture."
                    "generatedProtocolResponses"
                ),
            },
        }
        self.protocol = _write(
            root / "protocol.json", self.protocol_document
        )

    def generate(self, out: str):
        return generate_original_source_launch_context(
            self.root / out,
            combined_inventory_manifest=self.combined,
            transition_index_manifest=self.transition,
            compiled_authority_declarations=self.compiled,
            runtime_foundation_manifest=self.runtime,
            target_step_manifest=self.target,
            protocol_responses_declarations=self.protocol,
            preservation_inputs={"source_target_effect_declarations": self.effects},
        )


class StageAOriginalSourceLaunchContextGenerationTests(unittest.TestCase):
    def test_emits_hash_bound_concrete_declarations_and_exact_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            result = fixture.generate("out")
            manifest = json.loads(result.manifest.read_text(encoding="ascii"))
            source = result.module.read_text(encoding="ascii")
            compiled_digest = sha256_file(fixture.compiled)

        self.assertEqual(manifest["format"], ORIGINAL_SOURCE_LAUNCH_CONTEXT_FORMAT)
        self.assertTrue(manifest["ready"])
        self.assertFalse(manifest["proof_authority"])
        self.assertEqual(
            manifest["closed_context"],
            "StageA.GeneratedRelational.OriginalSourceLaunchContext."
            "generatedClosedContext",
        )
        self.assertEqual(
            manifest["inputs"]["compiled_authority_declarations"],
            compiled_digest,
        )
        declarations = manifest["lean"]["declarations"]
        for name in (
            "generatedSourceProgram",
            "generatedProject",
            "generatedOriginalContext",
            "generatedInventory",
            "generatedExactBinding",
            "generatedActiveTargets",
            "generatedActiveTargetIdsExact",
            "generatedInstructionSemanticsCheckedProof",
            "generatedInstructionSemanticsAdequateOfChecked",
            "generatedInstructionSemanticsAdequate",
            "generatedStaticWordRequirementsValid",
            "generatedCombinedLaunchSeedCheckedProof",
            "generatedLaunchSeedRequirement",
            "generatedLaunchSeed",
            "generatedLaunchInventoryHoldsOfSeed",
            "generatedSourceLaunchWorld",
            "generatedSourceLaunchMemory",
            "generatedSourceLaunchState",
            "generatedCheckedSourceLaunch",
            "generatedLaunchRealizable",
            "generatedStaticLaunchContext",
            "generatedProtocolResponsesRequirement",
            "generatedProtocolResponses",
            "generatedExternalHook",
            "generatedTargetStepIndex",
            "generatedClosedContext",
            "generatedProgramRecordKernelCompatibility",
        ):
            self.assertIn(name, declarations)
        self.assertEqual(manifest["blockers"], [])
        self.assertIn("generatedProjectProgramExact", source)
        self.assertIn("instructionSemanticsAdequate_of_checked", source)
        self.assertIn("generatedInstructionSemanticsCheckedProof", source)
        self.assertIn("generatedCombinedLaunchSeedCheckedProof", source)
        self.assertIn("Runtime.generatedLaunchWorld with dynamicRanges := []", source)
        self.assertIn("loaderPopulatedPreferredBaseMemory", source)
        self.assertIn("generatedCheckedSourceLaunch", source)
        self.assertIn("OriginalCombinedPE32ConsoleLaunchSeed", source)
        self.assertIn("CheckedOriginalCombinedMachineProtocolResponses", source)
        self.assertIn("generatedClosedContext", source)
        for forbidden in ("axiom ", "opaque ", "sorry", "native_decide", "status"):
            self.assertNotIn(forbidden, source)

    def test_output_is_reproducible_and_changes_with_dependency_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            first = fixture.generate("first")
            second = fixture.generate("second")
            self.assertEqual(first.module.read_bytes(), second.module.read_bytes())
            self.assertEqual(
                first.manifest.read_bytes(), second.manifest.read_bytes()
            )

            fixture.effects.write_text(
                '{"exact_checked_effects":[1,2,3,4]}\n', encoding="ascii"
            )
            changed = fixture.generate("changed")
            self.assertNotEqual(
                first.module.read_bytes(), changed.module.read_bytes()
            )
            self.assertNotEqual(
                first.manifest.read_bytes(), changed.manifest.read_bytes()
            )

    def test_rejects_substituted_transition_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.transition_document["exports"]["active_target_ids_exact"] = (
                "StageA.SubmittedProof.arbitrary"
            )
            _write(fixture.transition, fixture.transition_document)

            with self.assertRaisesRegex(
                OriginalSourceLaunchContextError,
                "not the canonical checked declaration",
            ):
                fixture.generate("rejected")

    def test_rejects_missing_exact_transition_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.transition_document["modules"].remove(
                "GeneratedGnuHelloSourceTransitionIndexData"
            )
            _write(fixture.transition, fixture.transition_document)

            with self.assertRaisesRegex(
                OriginalSourceLaunchContextError, "omits required module"
            ):
                fixture.generate("rejected")

    def test_rejects_protocol_responses_bound_to_different_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.protocol_document["inputs"][
                "combined_inventory_manifest"
            ] = "f" * 64
            _write(fixture.protocol, fixture.protocol_document)

            with self.assertRaisesRegex(
                OriginalSourceLaunchContextError,
                "binds a different combined_inventory_manifest",
            ):
                fixture.generate("rejected")

    def test_rejects_canonical_suffixes_under_substituted_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.transition_document["exports"] = {
                name: value.replace(
                    "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex",
                    "StageA.SubmittedProof",
                )
                for name, value in fixture.transition_document["exports"].items()
            }
            _write(fixture.transition, fixture.transition_document)

            with self.assertRaisesRegex(
                OriginalSourceLaunchContextError,
                "canonical generated namespace",
            ):
                fixture.generate("rejected")


if __name__ == "__main__":
    unittest.main()
