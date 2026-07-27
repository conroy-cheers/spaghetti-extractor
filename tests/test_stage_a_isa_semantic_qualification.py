from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.isa_qualification import (
    build_isa_semantic_qualification,
)
from spaghetti_extractor.isa_conformance import (
    isa_conformance_corpus_sha256,
    parse_isa_conformance_corpus,
)
from spaghetti_extractor.isa_conformance_unicorn import UNICORN_BACKEND_ID
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_bytes, sha256_file, write_json
from tests.test_stage_a_isa_conformance import _case, _observation, _report


CLASSIFIER_SHA256 = "1" * 64
EXTRACTOR_SHA256 = "2" * 64
FORM_A = ("lean-x86-form-a", "fixture.binary.add.register.register")
FORM_B = ("lean-x86-form-b", "fixture.ret")
FORM_OPTIONAL = ("lean-x86-form-c", "fixture.unreachable.nop")


def _requirements(
    *,
    required_forms: tuple[tuple[str, str], ...] = (FORM_A, FORM_B),
    control_closed: bool = True,
) -> dict[str, object]:
    required_ids = {form_id for form_id, _ in required_forms}
    forms = (FORM_A, FORM_B, FORM_OPTIONAL)
    occurrences = []
    form_rows = []
    for index, (form_id, semantic_form) in enumerate(forms):
        required = form_id in required_ids
        occurrence_count = 2
        form_rows.append(
            {
                "id": form_id,
                "format": "stage-a-lean-x86-semantic-form-v1",
                "model": "x86-pe32-relational-v3",
                "classifier_sha256": CLASSIFIER_SHA256,
                "semantic_form": semantic_form,
                "capstone_display_forms": [],
                "counts": {
                    "canonical_occurrences": occurrence_count,
                    "represented_rooted_occurrences": (
                        occurrence_count if required else 0
                    ),
                    "conservative_required_occurrences": (
                        occurrence_count if required else 0
                    ),
                },
                "capstone_preflight_status": "accepted",
            }
        )
        for side in ("candidate", "original"):
            occurrences.append(
                {
                    "id": f"occurrence-{index}-{side}",
                    "side": side,
                    "node_id": 0 if required else 1,
                    "region_id": "required" if required else "unreachable",
                    "rva": 0x1000 + index,
                    "size": 1,
                    "bytes": "90",
                    "form_id": form_id,
                    "capstone_display_form_id": f"display-{index}",
                    "capstone_preflight_status": "accepted",
                }
            )
    occurrences.sort(key=lambda row: str(row["id"]))
    required_occurrences = 2 * len(required_forms)
    return {
        "format": "stage-a-isa-requirement-inventory-v1",
        "status": "complete",
        "model": "x86-pe32-relational-v3",
        "inputs": {
            "original_sha256": "3" * 64,
            "candidate_sha256": "4" * 64,
            "relation_contract_sha256": "5" * 64,
            "product_graph_sha256": "6" * 64,
            "lean_form_source_sha256": CLASSIFIER_SHA256,
            "lean_form_extractor_sha256": EXTRACTOR_SHA256,
        },
        "scope": {
            "canonical_node_ids": [0, 1],
            "represented_rooted_node_ids": [0],
            "conservative_required_node_ids": [0],
            "root_node_ids": [0],
            "control_closed": control_closed,
            "control_frontier_node_ids": [] if control_closed else [1],
        },
        "formal_binding": {
            "status": "lean_decoder_extracted_replay_pending",
            "classifier_module": "StageA.ISAQualification",
            "span_decoder_module": "StageA.RelationalISAQualification",
            "classifier_sha256": CLASSIFIER_SHA256,
            "extractor_sha256": EXTRACTOR_SHA256,
            "instruction_spans_and_bytes_match_capstone": True,
            "acceptance_certificate_checked": False,
        },
        "forms": form_rows,
        "occurrences": occurrences,
        "gaps": [],
        "counts": {
            "canonical_nodes": 2,
            "represented_rooted_nodes": 1,
            "conservative_required_nodes": 1,
            "canonical_forms": len(forms),
            "represented_rooted_forms": len(required_forms),
            "conservative_required_forms": len(required_forms),
            "canonical_occurrences": len(occurrences),
            "represented_rooted_occurrences": required_occurrences,
            "conservative_required_occurrences": required_occurrences,
            "unsupported_occurrences": 0,
            "conservative_required_unsupported_occurrences": 0,
        },
        "trust": {
            "role": "untrusted_exact_pe_requirement_and_coverage_proposal",
            "proof_authority": False,
            "closes_stage_a_proof": False,
            "lean_checks_required": [],
            "conformance_rule": "mismatches veto; matches are evidence only",
        },
    }


def _set_report_status(report: dict[str, object], status: str) -> None:
    observation = report["observations"][0]
    counts = report["counts"]
    assert isinstance(observation, dict)
    assert isinstance(counts, dict)
    if status == "mismatch":
        final_state = observation["final_state"]
        assert isinstance(final_state, dict)
        gprs = final_state["gprs"]
        assert isinstance(gprs, dict)
        gprs["eax"] = 3
        report["qualification"] = "vetoed"
    else:
        observation.update(
            final_state=None,
            memory=None,
            actual=None,
            detail=f"synthetic {status}",
        )
        report["qualification"] = "unqualified"
    observation["status"] = status
    counts.update(
        matched=0,
        mismatched=int(status == "mismatch"),
        unsupported=int(status == "unsupported"),
        errors=int(status == "error"),
    )


def _write_evidence(
    root: Path,
    cases: tuple[tuple[str, str], ...],
    *,
    report_status: str = "match",
    classifier_sha256: str = CLASSIFIER_SHA256,
) -> Path:
    evidence = root / "evidence"
    evidence.mkdir()
    corpus_id = "synthetic-pe32-corpus-v1"
    corpus = {
        "format": "stage-a-isa-conformance-corpus-v1",
        "id": corpus_id,
        "cases": [_case(case_id) for case_id, _ in cases],
    }
    report = _report()
    report["corpus_id"] = corpus_id
    report["input_sha256"] = isa_conformance_corpus_sha256(
        parse_isa_conformance_corpus(corpus)
    )
    report["backend"] = {
        "id": "bochs-x86-32-batch-v1",
        "kind": "emulator",
        "version": "3.0",
    }
    report["observations"] = [_observation(case_id) for case_id, _ in cases]
    report["counts"].update(cases=len(cases), matched=len(cases))
    if report_status != "match":
        if len(cases) != 1:
            raise AssertionError("non-match fixtures must contain exactly one case")
        _set_report_status(report, report_status)
    lean_report = copy.deepcopy(report)
    lean_report["backend"] = {
        "id": "stage-a-lean-machine-semantics",
        "kind": "semantic_model",
        "version": "formal-default-v1",
    }
    unicorn_report = copy.deepcopy(report)
    unicorn_report["backend"] = {
        "id": UNICORN_BACKEND_ID,
        "kind": "emulator",
        "version": "synthetic-v1",
    }
    lean_forms = {
        "format": "stage-a-lean-isa-semantic-forms-v1",
        "corpus_id": corpus_id,
        "classifier_sha256": classifier_sha256,
        "cases": [
            {"case_id": case_id, "semantic_form": semantic_form}
            for case_id, semantic_form in cases
        ],
        "trust": {
            "role": "isa_conformance_evidence_only",
            "proof_authority": False,
            "closes_stage_a_proof": False,
        },
    }
    paths = {
        "corpus": evidence / "corpus.json",
        "import_manifest": evidence / "manifest.json",
        "report": evidence / "report.json",
        "lean_report": evidence / "lean-report.json",
        "unicorn_report": evidence / "unicorn-report.json",
        "lean_forms": evidence / "lean-forms.json",
    }
    write_json(paths["corpus"], corpus)
    write_json(
        paths["import_manifest"],
        {
            "format": "stage-a-isa-conformance-80386-import-v1",
            "corpus": {
                "id": corpus_id,
                "sha256": sha256_bytes(
                    json.dumps(
                        corpus, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ),
                "case_count": len(cases),
            },
            "trust": {
                "role": "isa_conformance_evidence_only",
                "proof_authority": False,
                "closes_stage_a_proof": False,
            },
        },
    )
    (evidence / "import-manifest.json").symlink_to(paths["import_manifest"].name)
    runner = evidence / "bin" / "spaghetti-bochs-conformance-runner"
    guest = (
        evidence
        / "libexec"
        / "spaghetti-extractor"
        / "bochs-conformance"
        / "guest.img"
    )
    bochs_raw = guest.with_name("bochs-raw")
    package_metadata = (
        evidence
        / "share"
        / "spaghetti-extractor"
        / "bochs-conformance"
        / "package-metadata.json"
    )
    runner.parent.mkdir(parents=True)
    guest.parent.mkdir(parents=True)
    package_metadata.parent.mkdir(parents=True)
    runner.write_bytes(b"synthetic runner")
    guest.write_bytes(b"synthetic guest")
    bochs_raw.write_bytes(b"synthetic bochs")
    package = {
        "format": "spaghetti-extractor-bochs-conformance-package-v1",
        "bochs": {"version": "3.0", "sourceHash": "synthetic"},
        "instrumentation": {},
        "runner": {},
        "execution": {"displayLibrary": "nogui", "headless": True},
        "cpu": {
            "architecture": "x86",
            "executionMode": "protected-32",
        },
    }
    write_json(package_metadata, package)
    write_json(paths["report"], report)
    write_json(paths["lean_report"], lean_report)
    write_json(paths["unicorn_report"], unicorn_report)
    write_json(paths["lean_forms"], lean_forms)
    write_json(
        evidence / "execution-manifest.json",
        {
            "format": "stage-a-bochs-conformance-execution-v1",
            "source": {
                "opcode": "synthetic",
                "shard_index": 0,
                "shard_count": 1,
                "corpus_store_path": str(evidence),
                "corpus_sha256": sha256_file(paths["corpus"]),
                "import_manifest_sha256": sha256_file(
                    paths["import_manifest"]
                ),
            },
            "backend": {
                "store_path": str(evidence),
                "runner_sha256": sha256_file(runner),
                "guest_sha256": sha256_file(guest),
                "bochs_binary_sha256": sha256_file(bochs_raw),
                "package": package,
            },
            "report": {
                "path": paths["report"].name,
                "sha256": sha256_file(paths["report"]),
            },
            "lean_report": {
                "path": paths["lean_report"].name,
                "sha256": sha256_file(paths["lean_report"]),
            },
            "unicorn_report": {
                "path": paths["unicorn_report"].name,
                "sha256": sha256_file(paths["unicorn_report"]),
            },
            "lean_forms": {
                "path": paths["lean_forms"].name,
                "sha256": sha256_file(paths["lean_forms"]),
            },
            "trust": {
                "role": "isa_conformance_evidence_only",
                "proof_authority": False,
                "closes_stage_a_proof": False,
            },
        },
    )
    return evidence


def _forms_by_id(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    forms = payload["forms"]
    assert isinstance(forms, list)
    return {str(row["form_id"]): row for row in forms}


class StageAISASemanticQualificationTests(unittest.TestCase):
    def test_required_forms_qualify_without_claiming_proof_or_control_closure(self):
        requirements = _requirements(control_closed=False)
        with tempfile.TemporaryDirectory() as temporary:
            evidence = _write_evidence(
                Path(temporary),
                (("case-a", FORM_A[1]), ("case-b", FORM_B[1])),
            )

            result = build_isa_semantic_qualification(
                requirements, [evidence]
            ).to_payload()

        self.assertEqual(result["format"], "stage-a-isa-semantic-qualification-v1")
        self.assertEqual(result["status"], "qualified")
        forms = _forms_by_id(result)
        self.assertEqual(set(forms), {FORM_A[0], FORM_B[0]})
        self.assertEqual(
            {row["status"] for row in forms.values()}, {"qualified"}
        )
        self.assertFalse(result["scope"]["control_closed"])
        self.assertEqual(result["scope"]["control_frontier_node_ids"], [1])
        self.assertFalse(result["trust"]["proof_authority"])
        self.assertFalse(result["trust"]["closes_stage_a_proof"])

    def test_any_mismatch_vetoes_its_required_semantic_form(self):
        requirements = _requirements(required_forms=(FORM_A,))
        with tempfile.TemporaryDirectory() as temporary:
            evidence = _write_evidence(
                Path(temporary),
                (("case-a", FORM_A[1]),),
                report_status="mismatch",
            )

            result = build_isa_semantic_qualification(
                requirements, [evidence]
            ).to_payload()

        self.assertEqual(result["status"], "vetoed")
        self.assertEqual(_forms_by_id(result)[FORM_A[0]]["status"], "vetoed")

    def test_placeholder_x87_model_cannot_be_qualified_by_emulator_agreement(self):
        semantic_form = "StageA.Formal.InstructionSemanticForm.x87Initialize"
        requirements = _requirements(required_forms=(FORM_A,))
        for row in requirements["forms"]:
            if row["id"] == FORM_A[0]:
                row["semantic_form"] = semantic_form
        with tempfile.TemporaryDirectory() as temporary:
            evidence = _write_evidence(
                Path(temporary), (("case-x87", semantic_form),)
            )
            result = build_isa_semantic_qualification(
                requirements, [evidence]
            ).to_payload()

        form = _forms_by_id(result)[FORM_A[0]]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(form["status"], "incomplete")
        self.assertIn("formal_x87_semantics_placeholder", form["blockers"])

    def test_unsupported_error_and_missing_evidence_remain_incomplete(self):
        for evidence_status in ("unsupported", "error"):
            with self.subTest(evidence_status=evidence_status):
                requirements = _requirements(required_forms=(FORM_A,))
                with tempfile.TemporaryDirectory() as temporary:
                    evidence = _write_evidence(
                        Path(temporary),
                        (("case-a", FORM_A[1]),),
                        report_status=evidence_status,
                    )
                    result = build_isa_semantic_qualification(
                        requirements, [evidence]
                    ).to_payload()

                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(
                    _forms_by_id(result)[FORM_A[0]]["status"], "incomplete"
                )

        requirements = _requirements()
        with tempfile.TemporaryDirectory() as temporary:
            evidence = _write_evidence(
                Path(temporary), (("case-a", FORM_A[1]),)
            )
            result = build_isa_semantic_qualification(
                requirements, [evidence]
            ).to_payload()

        forms = _forms_by_id(result)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(forms[FORM_A[0]]["status"], "qualified")
        self.assertEqual(forms[FORM_B[0]]["status"], "incomplete")
        self.assertNotIn(FORM_OPTIONAL[0], forms)

    def test_classifier_corpus_and_report_hash_mismatches_are_rejected(self):
        requirements = _requirements(required_forms=(FORM_A,))
        for mismatch in ("classifier", "corpus", "report"):
            with self.subTest(mismatch=mismatch):
                with tempfile.TemporaryDirectory() as temporary:
                    evidence = _write_evidence(
                        Path(temporary),
                        (("case-a", FORM_A[1]),),
                        classifier_sha256=(
                            "f" * 64 if mismatch == "classifier" else CLASSIFIER_SHA256
                        ),
                    )
                    manifest_path = evidence / "execution-manifest.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    if mismatch == "corpus":
                        manifest["source"]["corpus_sha256"] = "0" * 64
                    elif mismatch == "report":
                        manifest["report"]["sha256"] = "0" * 64
                    write_json(manifest_path, manifest)

                    with self.assertRaises(StageAInputError):
                        build_isa_semantic_qualification(requirements, [evidence])


if __name__ == "__main__":
    unittest.main()
