from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.gnu_hello_concrete_environment_pair import (
    GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_INPUT_FORMAT,
    GnuHelloConcreteEnvironmentPairError,
    write_gnu_hello_concrete_environment_pair,
)


def _input() -> dict[str, object]:
    site = {
        "id": 3,
        "import_identity": "kernel32.dll!WriteFile",
        "disposition": "returns",
        "argument_sources": [{"stack_offset": 4}],
        "read_footprints": [{"argument": 1, "bytes": 5}],
        "write_footprints": [{"argument": 3, "bytes": 4}],
        "callbacks": [],
        "footprints_complete": True,
        "callbacks_complete": True,
    }
    return {
        "format": GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_INPUT_FORMAT,
        "candidate_sha256": "a" * 64,
        "reachable_external_site_ids": [3],
        "lockstep_sites": [site],
        "lean": {
            "imports": ["StageA.CheckedGnuHelloEnvironmentPair"],
            "context": "StageA.CheckedGnuHelloEnvironmentPair.context",
            "sites": "StageA.CheckedGnuHelloEnvironmentPair.sites",
            "static_compilation": (
                "StageA.CheckedGnuHelloEnvironmentPair.compilation"
            ),
            "static_authority": (
                "StageA.CheckedGnuHelloEnvironmentPair.staticAuthority"
            ),
            "checked_pair": "StageA.CheckedGnuHelloEnvironmentPair.checkedPair",
        },
    }


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="ascii")
    return path


class StageAGnuHelloConcreteEnvironmentPairTests(unittest.TestCase):
    def test_emits_singleton_admitted_pair_with_exact_site_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outputs = write_gnu_hello_concrete_environment_pair(
                root / "out", input_manifest=_write(root / "input.json", _input())
            )
            source = outputs.module.read_text(encoding="ascii")
            profile = json.loads(outputs.profile.read_text(encoding="ascii"))
            report = json.loads(outputs.report.read_text(encoding="ascii"))

        self.assertIn("CheckedConcreteWorldNativeEnvironmentPair", source)
        self.assertIn("checkedPair.externalEvidenceAt", source)
        self.assertIn("checkedPair.sourceFamilyAt", source)
        self.assertNotRegex(source, r"\b(?:axiom|opaque|sorry|admit)\b")
        self.assertEqual(profile["lean"]["source_family_scope"], "admitted_pairs")
        self.assertEqual(profile["lockstep"]["sites"][0]["id"], 3)
        self.assertEqual(report["pair_cardinality"], 1)
        self.assertEqual(report["site_coverage"], "exact")

    def test_missing_reachable_site_fails_closed(self) -> None:
        value = _input()
        value["reachable_external_site_ids"] = [3, 9]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                GnuHelloConcreteEnvironmentPairError, "not exact"
            ):
                write_gnu_hello_concrete_environment_pair(
                    root / "out", input_manifest=_write(root / "input.json", value)
                )

    def test_incomplete_footprints_or_callbacks_fail_closed(self) -> None:
        for field in ("footprints_complete", "callbacks_complete"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                value = copy.deepcopy(_input())
                value["lockstep_sites"][0][field] = False
                root = Path(temporary)
                with self.assertRaisesRegex(
                    GnuHelloConcreteEnvironmentPairError, "incomplete"
                ):
                    write_gnu_hello_concrete_environment_pair(
                        root / "out",
                        input_manifest=_write(root / "input.json", value),
                    )

    def test_ambiguous_site_ids_fail_closed(self) -> None:
        value = _input()
        value["reachable_external_site_ids"] = [3, 3]
        value["lockstep_sites"] = [
            copy.deepcopy(value["lockstep_sites"][0]),
            copy.deepcopy(value["lockstep_sites"][0]),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                GnuHelloConcreteEnvironmentPairError, "unique"
            ):
                write_gnu_hello_concrete_environment_pair(
                    root / "out", input_manifest=_write(root / "input.json", value)
                )


if __name__ == "__main__":
    unittest.main()
