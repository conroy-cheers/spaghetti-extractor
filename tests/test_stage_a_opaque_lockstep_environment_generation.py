from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.opaque_lockstep_environment import (
    OPAQUE_LOCKSTEP_ENVIRONMENT_FORMAT,
    parse_opaque_lockstep_environment_artifact,
    relational_opaque_lockstep_environment_source,
)
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES


def _artifact() -> dict[str, Any]:
    return {
        "format": OPAQUE_LOCKSTEP_ENVIRONMENT_FORMAT,
        "call_sites": [
            {
                "id": 7,
                "source_target_id": 11,
                "continuation_target_id": 12,
                "disposition": "returns",
                "import": {"dll": "kernel32.dll", "symbol": "WriteFile"},
                "original_iat_rva": 0x9010,
                "candidate_iat_rva": 0xA018,
                "argument_sources": [
                    {
                        "original": {"kind": "register", "register": "eax"},
                        "candidate": {"kind": "stack_word", "offset": 4},
                    },
                    {
                        "original": {"kind": "stack_word", "offset": 8},
                        "candidate": {"kind": "stack_word", "offset": 12},
                    },
                ],
                "memory_observations": [
                    {
                        "argument_index": 1,
                        "original_offset": 0,
                        "candidate_offset": 0,
                        "bytes": 16,
                        "relation": "exact_bytes",
                    },
                    {
                        "argument_index": 1,
                        "original_offset": 16,
                        "candidate_offset": 20,
                        "bytes": 8,
                        "relation": "related_words",
                    },
                ],
                "boundary_invariant": {
                    "register_relations": [
                        {
                            "original": "esp",
                            "candidate": "esp",
                            "relation": "related_word",
                        }
                    ]
                },
                "target_invariant": {},
            }
        ],
    }


class StageAOpaqueLockstepEnvironmentGenerationTests(unittest.TestCase):
    def test_emits_machine_level_data_without_acceptance_claim(self) -> None:
        source = relational_opaque_lockstep_environment_source(_artifact())

        self.assertIn("import StageA.RelationalOpaqueLockstepEnvironment", source)
        self.assertIn("def opaqueLockstepCallSite7 : OpaqueLockstepCallSite", source)
        self.assertIn("(.symbol [87, 114, 105, 116, 101, 70, 105, 108, 101])", source)
        self.assertIn("originalIatRva := 36880", source)
        self.assertIn("candidateIatRva := 40984", source)
        self.assertIn("disposition := .returns", source)
        self.assertIn(".register .eax", source)
        self.assertIn(".stackWord 12", source)
        self.assertIn("relation := .exactBytes", source)
        self.assertIn("relation := .relatedWords", source)
        self.assertIn("opaqueLockstepCallSiteIdsUniqueChecked", source)
        self.assertIn("opaqueLockstepCallSiteShapesChecked", source)
        self.assertNotIn("CheckedOpaqueLockstepEnvironment", source)
        self.assertNotIn("EnvironmentRefines", source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_typed_parser_exposes_acceptance_integration_data(self) -> None:
        artifact = parse_opaque_lockstep_environment_artifact(_artifact())

        self.assertEqual(len(artifact.call_sites), 1)
        site = artifact.call_sites[0]
        self.assertEqual(site.id, 7)
        self.assertEqual(site.imported["symbol"], "WriteFile")
        self.assertEqual(site.argument_sources[0].original.register, "eax")
        self.assertEqual(site.memory_observations[1].relation, "related_words")

    def test_fails_closed_on_unextractable_identity_or_abi_state(self) -> None:
        cases: list[tuple[str, dict[str, Any], str]] = []

        missing_identity = deepcopy(_artifact())
        del missing_identity["call_sites"][0]["import"]
        cases.append(("missing identity", missing_identity, "missing required fields: import"))

        ambiguous_identity = deepcopy(_artifact())
        ambiguous_identity["call_sites"][0]["import"] = {
            "dll": "kernel32.dll",
            "symbol": "WriteFile",
            "ordinal": 3,
        }
        cases.append(("ambiguous identity", ambiguous_identity, "exactly one"))

        unknown_register = deepcopy(_artifact())
        unknown_register["call_sites"][0]["argument_sources"][0]["original"] = {
            "kind": "register",
            "register": "eip",
        }
        cases.append(("unknown register", unknown_register, "register is unsupported"))

        unknown_source = deepcopy(_artifact())
        unknown_source["call_sites"][0]["argument_sources"][0]["original"] = {
            "kind": "prototype_parameter",
        }
        cases.append(("prototype source", unknown_source, "kind must be"))

        out_of_bounds = deepcopy(_artifact())
        out_of_bounds["call_sites"][0]["memory_observations"][0][
            "argument_index"
        ] = 4
        cases.append(("memory argument", out_of_bounds, "outside argument_sources"))

        misaligned_words = deepcopy(_artifact())
        misaligned_words["call_sites"][0]["memory_observations"][1]["bytes"] = 6
        cases.append(("word span", misaligned_words, "divisible by four"))

        for name, payload, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(StageAInputError, message):
                    parse_opaque_lockstep_environment_artifact(payload)

    def test_rejects_ambiguous_or_noncanonical_sites(self) -> None:
        duplicate = deepcopy(_artifact())
        duplicate["call_sites"].append(deepcopy(duplicate["call_sites"][0]))
        with self.assertRaisesRegex(StageAInputError, "ids are ambiguous"):
            parse_opaque_lockstep_environment_artifact(duplicate)

        unordered = deepcopy(_artifact())
        second = deepcopy(unordered["call_sites"][0])
        second["id"] = 3
        unordered["call_sites"].append(second)
        with self.assertRaisesRegex(StageAInputError, "canonical site-id order"):
            parse_opaque_lockstep_environment_artifact(unordered)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_generated_source_is_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        generated = relational_opaque_lockstep_environment_source(_artifact())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in (
                *RELATIONAL_KERNEL_MODULES,
                "RelationalOpaqueLockstepEnvironment",
            ):
                shutil.copyfile(source_root / f"{module}.lean", stage_a / f"{module}.lean")
            (stage_a / "GeneratedOpaqueLockstepEnvironment.lean").write_text(
                generated, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="GeneratedOpaqueLockstepEnvironment"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
