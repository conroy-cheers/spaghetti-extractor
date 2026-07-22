from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.roundtrip_fuzz.genericity import (
    GENERICITY_BASELINE_FORMAT,
    load_genericity_baseline,
    scan_acceptance_genericity,
)
from spaghetti_extractor.roundtrip_fuzz.metrics import GenericityInventory
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import write_json


class StageARoundTripFuzzGenericityTests(unittest.TestCase):
    def test_detects_fixture_identity_dispatch_in_proof_core(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary)
            (package / "relational").mkdir()
            (package / "lean" / "StageA").mkdir(parents=True)
            (package / "relational" / "bad.py").write_text(
                "def accept(case_id):\n    if case_id == 'jq':\n        return True\n",
                encoding="utf-8",
            )
            (package / "lean" / "StageA" / "Core.lean").write_text(
                "theorem genericRefinement : True := by trivial\n",
                encoding="utf-8",
            )

            evidence = scan_acceptance_genericity(package_root=package)

        self.assertEqual(len(evidence.forbidden_dispatch_hits), 1)
        self.assertIn("case_id", evidence.forbidden_dispatch_hits[0])
        self.assertEqual(len(evidence.current.special_case_conditionals), 1)
        self.assertTrue(any(
            rule.endswith("::genericRefinement")
            for rule in evidence.current.proof_rules
        ))

    def test_detects_aliased_mapping_identity_and_match_literal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary)
            (package / "relational").mkdir()
            (package / "lean" / "StageA").mkdir(parents=True)
            (package / "relational" / "bad.py").write_text(
                "def accept(payload):\n"
                "    identity = payload.get('case_id')\n"
                "    alias = identity\n"
                "    if alias == 'ordinary-case':\n"
                "        return True\n"
                "    match payload.get('template'):\n"
                "        case 'jq':\n"
                "            return True\n",
                encoding="utf-8",
            )
            (package / "lean" / "StageA" / "Core.lean").write_text(
                "inductive Operation where\n"
                "  | add\n"
                "\n"
                "def evaluate : Nat -> Nat\n"
                "  | 0 => 1\n"
                "  | value => value\n",
                encoding="utf-8",
            )

            evidence = scan_acceptance_genericity(package_root=package)

        self.assertEqual(len(evidence.forbidden_dispatch_hits), 2)
        self.assertEqual(
            evidence.current.lean_constructors,
            ("lean/StageA/Core.lean::Operation.add",),
        )

    def test_inventory_keys_do_not_change_when_source_lines_move(self) -> None:
        def scan(source: str):
            temporary = tempfile.TemporaryDirectory()
            package = Path(temporary.name)
            (package / "relational").mkdir()
            (package / "lean" / "StageA").mkdir(parents=True)
            (package / "relational" / "profile.py").write_text(
                source, encoding="utf-8"
            )
            (package / "lean" / "StageA" / "Core.lean").write_text(
                "theorem genericRefinement : True := by trivial\n",
                encoding="utf-8",
            )
            return temporary, scan_acceptance_genericity(package_root=package)

        first_tmp, first = scan(
            "def choose(profile):\n    if profile == 'flat-v1':\n        return 1\n"
        )
        second_tmp, second = scan(
            "\n\ndef choose(profile):\n    if profile == 'flat-v1':\n        return 1\n"
        )
        try:
            self.assertEqual(
                first.current.profile_branches,
                second.current.profile_branches,
            )
        finally:
            first_tmp.cleanup()
            second_tmp.cleanup()

    def test_current_acceptance_core_has_no_fixture_dispatch(self) -> None:
        package = Path(__file__).parents[1] / "src" / "spaghetti_extractor"
        evidence = scan_acceptance_genericity(package_root=package)
        self.assertEqual(evidence.forbidden_dispatch_hits, ())
        self.assertEqual(evidence.current.special_case_conditionals, ())
        self.assertGreater(len(evidence.current.lean_constructors), 10)
        self.assertGreater(len(evidence.current.proof_rules), 10)

    def test_loads_strict_diagnostic_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "baseline.json"
            write_json(path, {
                "format": GENERICITY_BASELINE_FORMAT,
                "inventory": GenericityInventory(
                    structural_shapes=("shape-a",),
                    proof_rules=("Core.genericRelated",),
                    source_lines=12,
                ).to_payload(),
                "authority": {"proof_authority": False},
            })
            baseline = load_genericity_baseline(path)

        self.assertEqual(baseline.structural_shapes, ("shape-a",))
        self.assertEqual(baseline.proof_rules, ("Core.genericRelated",))
        self.assertEqual(baseline.source_lines, 12)

    def test_rejects_unknown_baseline_inventory_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "baseline.json"
            write_json(path, {
                "format": GENERICITY_BASELINE_FORMAT,
                "inventory": {"proof_rules": [], "fixture_overrides": []},
            })
            with self.assertRaisesRegex(StageAInputError, "unknown fields"):
                load_genericity_baseline(path)


if __name__ == "__main__":
    unittest.main()
