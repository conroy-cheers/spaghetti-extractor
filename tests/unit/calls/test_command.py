from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.calls.dialects.ia32 import IA32DialectCheckerV1
from spaghetti_extractor.cli import main
from tests.unit.calls._support import graph, layouts, machine_evidence, subject


TESTKIT = {"commands": ("expert call-protocol-check",)}


class CallProtocolCommandTests(unittest.TestCase):
    def test_expert_check_builds_the_complete_content_bound_artifact_family(self) -> None:
        types = graph()
        layout_set = layouts(types)
        frame = IA32DialectCheckerV1("pe32-i386-gnu-v1").lower(subject=subject(), function_type_id="call", type_graph=types, layout_set=layout_set)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            intent = root / "intent.json"
            layout_path = root / "layouts.json"
            frame_path = root / "frame.json"
            evidence_path = root / "evidence.json"
            machine_ir = root / "machine-ir.jsonl"
            output = root / "output"
            intent.write_text(json.dumps({
                "format": "spaghetti-extractor-call-protocol-intent-v1",
                "id": "fixture-call",
                "subject": subject(),
                "abi_dialect": "pe32-i386-gnu-v1",
                "faithful_function_type_id": "call",
                "types": [item.to_payload() for item in types.nodes],
                "source_names": {"types": {}, "fields": [], "values": {}},
                "lifecycle": [],
                "idiomatic_projections": [],
                "rationale": "Reviewed fixture call.",
            }), encoding="utf-8")
            layout_path.write_text(json.dumps(layout_set.to_payload()), encoding="utf-8")
            frame_path.write_text(json.dumps(frame.to_payload()), encoding="utf-8")
            evidence_path.write_text(json.dumps(machine_evidence(frame).to_payload()), encoding="utf-8")
            for path in (
                machine_ir,
            ):
                path.write_text("{}\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                status = main([
                    "expert", "call-protocol-check",
                    "--intent", str(intent),
                    "--layouts", str(layout_path),
                    "--frame", str(frame_path),
                    "--machine-ir", str(machine_ir),
                    "--machine-evidence", str(evidence_path),
                    "--out", str(output),
                ])
            self.assertEqual(status, 0)
            self.assertTrue((output / "checked-call-protocol.json").is_file())
            self.assertIn("spx_checked_call", (output / "faithful-call.h").read_text(encoding="utf-8"))
            report = json.loads((output / "call-status.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "complete")


if __name__ == "__main__":
    unittest.main()
