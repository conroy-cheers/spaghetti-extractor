from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.hybrid_authority_v2 import canonical_json_bytes
from spaghetti_extractor.static_hybrid_final_audit_v2 import (
    StaticHybridFinalAuditV2Error,
    build_static_hybrid_final_audit_v2,
    validate_static_hybrid_final_audit_v2,
)
from spaghetti_extractor.static_hybrid_authority_v2 import (
    build_static_hybrid_authority_v2,
)
from tests.test_static_hybrid_authority_v2 import (
    BINARY_SHA,
    _authority,
    _complete_report,
    _interprocedural,
    _manifest,
    _row,
)


class StaticHybridFinalAuditV2Tests(unittest.TestCase):
    def _inputs(self, root: Path):
        rows = [_row()]
        report = _complete_report(rows)
        bundle = report["authority_bundle"]
        machine = root / "machine-ir.jsonl"
        manifest = root / "machine-ir-manifest.json"
        bundle_path = root / "authority-bundle.json"
        machine.write_bytes(b"".join(canonical_json_bytes(row) + b"\n" for row in rows))
        manifest.write_text(json.dumps({"format": "fixture"}), encoding="utf-8")
        bundle_path.write_bytes(canonical_json_bytes(bundle))
        return report, bundle_path, machine, manifest

    def test_complete_replayed_authority_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, bundle, machine, manifest = self._inputs(Path(temporary))
            audit = build_static_hybrid_final_audit_v2(
                static_authority=report,
                authority_bundle=bundle,
                machine_ir=machine,
                machine_ir_manifest=manifest,
            )

            self.assertEqual(audit["status"], "pass")
            self.assertEqual(audit["findings"], [])
            self.assertEqual(
                validate_static_hybrid_final_audit_v2(
                    audit,
                    static_authority=report,
                    authority_bundle=bundle,
                    machine_ir=machine,
                    machine_ir_manifest=manifest,
                ),
                audit,
            )

    def test_open_authority_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, bundle, machine, manifest = self._inputs(Path(temporary))
            rows = [_row()]
            _qualification, _selection, isa = _authority()
            report = build_static_hybrid_authority_v2(
                machine_ir_rows=rows,
                machine_ir_manifest=_manifest(rows),
                pe_sha256=BINARY_SHA,
                behavioral_roots=[{"kind": "pe_entry", "rva": 0x1000}],
                entry_state_analysis=None,
                interprocedural_result=_interprocedural(),
                isa_selection_authority=isa,
            )
            audit = build_static_hybrid_final_audit_v2(
                static_authority=report,
                authority_bundle=report["authority_bundle"],
                machine_ir=machine,
                machine_ir_manifest=manifest,
            )

            self.assertEqual(audit["status"], "incomplete")
            self.assertTrue(audit["findings"])
            self.assertEqual(audit["diagnostics"], report["diagnostics"])
            self.assertEqual(
                audit["diagnostics"]["primary_blocker_ids"],
                report["primary_blocker_ids"],
            )

    def test_dependent_blocker_metadata_is_not_flattened(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, bundle, machine, manifest = self._inputs(Path(temporary))
            report = copy.deepcopy(report)
            report["status"] = "incomplete"
            report["authorizes_candidate_generation"] = False
            # The final audit validates/replays the report, so use a naturally
            # incomplete report rather than fabricating blocker records.
            rows = [_row()]
            _qualification, _selection, isa = _authority()
            report = build_static_hybrid_authority_v2(
                machine_ir_rows=rows,
                machine_ir_manifest=_manifest(rows),
                pe_sha256=BINARY_SHA,
                behavioral_roots=[{"kind": "pe_entry", "rva": 0x1000}],
                entry_state_analysis=None,
                interprocedural_result=_interprocedural(),
                isa_selection_authority=isa,
            )

            audit = build_static_hybrid_final_audit_v2(
                static_authority=report,
                authority_bundle=report["authority_bundle"],
                machine_ir=machine,
                machine_ir_manifest=manifest,
            )

            self.assertEqual(
                audit["diagnostics"]["blockers"],
                report["diagnostics"]["blockers"],
            )
            self.assertEqual(
                audit["diagnostics"]["dependent_consequence_ids"],
                report["diagnostics"]["dependent_consequence_ids"],
            )

    def test_stale_audit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, bundle, machine, manifest = self._inputs(Path(temporary))
            audit = build_static_hybrid_final_audit_v2(
                static_authority=report,
                authority_bundle=bundle,
                machine_ir=machine,
                machine_ir_manifest=manifest,
            )
            stale = copy.deepcopy(audit)
            stale["machine_ir"]["sha256"] = "0" * 64

            with self.assertRaisesRegex(
                StaticHybridFinalAuditV2Error, "stale"
            ):
                validate_static_hybrid_final_audit_v2(
                    stale,
                    static_authority=report,
                    authority_bundle=bundle,
                    machine_ir=machine,
                    machine_ir_manifest=manifest,
                )


if __name__ == "__main__":
    unittest.main()
