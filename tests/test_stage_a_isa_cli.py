from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.isa_cli import (
    build_isa_kernel_qualification,
    generate_isa_corpus,
    normalize_isa_catalog,
    write_isa_qualification_campaign,
)
from spaghetti_extractor.isa_campaign import parse_isa_qualification_campaign
from spaghetti_extractor.isa_conformance_bochs import BOCHS_BACKEND_ID
from spaghetti_extractor.isa_conformance_lean import LEAN_ISA_BACKEND_ID
from spaghetti_extractor.isa_conformance_unicorn import UNICORN_BACKEND_ID
from spaghetti_extractor.isa_kernel_qualification import (
    parse_kernel_qualification,
)
from tests.test_stage_a_isa_catalog import catalog_payload, xed_payload, xed_template
from tests.test_stage_a_isa_corpus_generator import _report_payload


def _write(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class StageAISACommandBoundaryTests(unittest.TestCase):
    def test_normalizes_realistic_xed_aliases_and_reports_dispositions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "xed.json"
            out = root / "normalized.json"
            _write(
                source,
                xed_payload(
                    xed_template(4),
                    xed_template(8),
                    xed_template(9, category="SYSCALL"),
                ),
            )

            result = normalize_isa_catalog(catalog=source, out=out)

            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["counts"]["templates"], 2)
            self.assertEqual(result["counts"]["source_aliases"], 1)
            self.assertFalse(result["proof_authority"])

    def test_complete_xed_catalog_produces_a_visible_unqualified_campaign(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "xed.json"
            out = root / "campaign.json"
            _write(
                source,
                xed_payload(
                    xed_template(4),
                    xed_template(8, iform="FORM_B", iclass="CLASS_B"),
                ),
            )

            result = write_isa_qualification_campaign(
                catalog=source,
                out=out,
            )

            campaign = parse_isa_qualification_campaign(
                json.loads(out.read_text(encoding="utf-8"))
            )
            self.assertEqual(result["status"], "complete")
            self.assertEqual(campaign.counts["forms"], 2)
            self.assertEqual(campaign.counts["qualified"], 0)
            self.assertEqual(campaign.counts["frontier"], 2)
            self.assertFalse(campaign.trust.proof_authority)

    def test_generated_corpus_runs_through_raw_consensus_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog = root / "catalog.json"
            generated_dir = root / "generated"
            _write(catalog, catalog_payload())
            generation = generate_isa_corpus(
                catalog=catalog,
                seed=17,
                out=generated_dir,
            )
            self.assertEqual(generation["status"], "generated")

            corpus_payload = json.loads(
                (generated_dir / "corpus.json").read_text(encoding="utf-8")
            )
            from spaghetti_extractor.isa_conformance import (
                parse_isa_conformance_corpus,
            )

            executor = type(
                "Executor",
                (),
                {"corpus": parse_isa_conformance_corpus(corpus_payload)},
            )()
            report_paths = {}
            for label, backend in (
                ("bochs", BOCHS_BACKEND_ID),
                ("unicorn", UNICORN_BACKEND_ID),
                ("lean", LEAN_ISA_BACKEND_ID),
            ):
                path = root / f"{label}-report.json"
                report = _report_payload(executor, backend)
                if label == "lean":
                    report["backend"]["kind"] = "semantic_model"
                _write(path, report)
                report_paths[label] = path
            lean_forms = root / "lean-forms.json"
            _write(
                lean_forms,
                {
                    "format": "stage-a-lean-isa-semantic-forms-v1",
                    "corpus_id": executor.corpus.id,
                    "classifier_sha256": "1" * 64,
                    "cases": [
                        {
                            "case_id": case.id,
                            "semantic_form": "fixture.binary.increment",
                        }
                        for case in executor.corpus.cases
                    ],
                    "trust": {
                        "role": "isa_conformance_evidence_only",
                        "proof_authority": False,
                        "closes_stage_a_proof": False,
                    },
                },
            )
            kernel = root / "kernel.json"
            _write(
                kernel,
                {
                    "format": "stage-a-isa-semantic-kernel-binding-v1",
                    "id": "fixture-kernel",
                    "decoder_sha256": "2" * 64,
                    "semantics_sha256": "3" * 64,
                    "lean_version": "Lean fixture",
                    "source": {},
                    "trust": {
                        "role": "compiled_lean_semantic_kernel_identity",
                        "proof_authority": False,
                        "closes_stage_a_proof": False,
                    },
                },
            )
            qualification = root / "qualification.json"
            crosswalk = root / "crosswalk.json"

            result = build_isa_kernel_qualification(
                corpus=generated_dir / "corpus.json",
                lean_forms=lean_forms,
                bochs_report=report_paths["bochs"],
                unicorn_report=report_paths["unicorn"],
                lean_report=report_paths["lean"],
                semantic_kernel=kernel,
                out=qualification,
                crosswalk_out=crosswalk,
                generated_corpus=generated_dir / "generated-corpus.json",
            )

            self.assertEqual(result["status"], "qualified")
            parsed = parse_kernel_qualification(
                json.loads(qualification.read_text(encoding="utf-8"))
            )
            self.assertEqual(parsed.status.value, "qualified")
            self.assertFalse(parsed.trust.proof_authority)
            self.assertTrue(crosswalk.is_file())
            crosswalk_payload = json.loads(
                crosswalk.read_text(encoding="utf-8")
            )
            self.assertEqual(
                {row["catalog_form_id"] for row in crosswalk_payload["cases"]},
                {"form-register"},
            )


if __name__ == "__main__":
    unittest.main()
