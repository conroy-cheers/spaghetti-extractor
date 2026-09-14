"""Public navigation and explicit selection of untrusted boundary alternatives."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from spaghetti_extractor.cli import main

TESTKIT = {"commands": ("component list", "boundary inspect", "boundary propose")}


class ComponentProposalNavigationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = [{
            "id": "component-proposal:" + identity,
            "proposal_sha256": identity * 64,
            "membership": {"unit_ids": ["unit:a"], "unit_count": size,
                           "rva_start": 4096, "rva_end": 4100},
            "proposal_kinds": ["loop"], "blockers": [],
            "boundary": {"exits": []}, "interface_hint": {},
            "score": {"vector": {}},
        } for identity, size in (("a", 3), ("b", 5))]
        self.package = SimpleNamespace(proposals_at_rva=Mock(return_value=self.rows))
        self.patches = [
            patch("spaghetti_extractor.commands.workflows._realize_path",
                  return_value=Path("/unused")),
            patch("spaghetti_extractor.commands.workflows.load_component_proposal_package_v2",
                  return_value=self.package),
            patch("spaghetti_extractor.commands.workflows._boundary_subject",
                  return_value={"dynamic": True, "canonicalSubject": "component-seed:0x1000"}),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_near_lists_reviewable_choices_as_json(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["component", "list", "fixture", "--near", "0x1000",
                                   "--json"]), 0)
        payload = json.loads(output.getvalue())
        self.assertFalse(payload["authority"])
        self.assertEqual([row["id"] for row in payload["alternatives"]],
                         [row["id"] for row in self.rows])
        self.package.proposals_at_rva.assert_called_once_with(4096)

    def test_explicit_choice_survives_inspection_and_editable_export(self) -> None:
        arguments = ["fixture", "component-seed:0x1000", "--proposal",
                     "component-proposal:b"]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["boundary", "inspect", *arguments, "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue())["proposal"]["id"],
                         "component-proposal:b")
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "draft"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["boundary", "propose", *arguments,
                                       "--output", str(destination)]), 0)
            inspection = json.loads((destination / "component-proposal-inspection.json").read_text())
            self.assertFalse(inspection["authority"])
            self.assertEqual(inspection["proposal"]["id"], "component-proposal:b")
            self.assertIn('#error', (destination / "src/component.c").read_text())

    def test_unrelated_choice_rejects_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "draft"
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["boundary", "propose", "fixture",
                                       "component-seed:0x1000", "--proposal",
                                       "component-proposal:unrelated", "--output", str(destination)]), 2)
            self.assertFalse(destination.exists())
