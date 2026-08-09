from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace
from typing import Any

from spaghetti_extractor.analysis.isa_requirements import (
    _lean_side_form_extraction_source,
)
from spaghetti_extractor.machine_ir_isa_requirements_v2 import (
    MACHINE_IR_FALLBACK_CAPABILITY_V2,
    MachineIRISARequirementsV2Error,
    build_machine_ir_isa_extraction_request_v2,
    build_machine_ir_isa_requirements_v2,
    build_machine_ir_isa_semantic_requirements_v2,
    compare_selection_to_machine_ir_requirements_v2,
    parse_machine_ir_isa_requirements_v2,
    parse_machine_ir_isa_semantic_requirements_v2,
)


PE_SHA = "a" * 64
MACHINE_SHA = "b" * 64
CLASSIFIER_SHA = "c" * 64
EXTRACTOR_SHA = "d" * 64
SOURCE_SHA = "e" * 64


def _unit(
    *,
    reachable: bool = True,
    identity: str = "unit-1000",
) -> dict[str, Any]:
    return {
        "id": identity,
        "reachable": reachable,
        "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1003}},
        "instructions": [
            {"rva_start": 0x1000, "rva_end": 0x1001},
            {"rva_start": 0x1001, "rva_end": 0x1003},
        ],
    }


def _evidence() -> dict[str, str]:
    return {
        "status": "lean_extracted_untrusted",
        "classifier_sha256": CLASSIFIER_SHA,
        "extractor_sha256": EXTRACTOR_SHA,
        "source_sha256": SOURCE_SHA,
    }


def _rows() -> dict[tuple[str, int], tuple[dict[str, Any], ...]]:
    return {
        ("original", 0): (
            {"rva": 0x1000, "size": 1, "bytes": "53", "form": "push-r32"},
        ),
        ("original", 1): (
            {"rva": 0x1001, "size": 2, "bytes": "31c0", "form": "xor-r32-r32"},
        ),
    }


class MachineIRISARequirementsV2Tests(unittest.TestCase):
    def test_generated_lean_qualifies_ambiguous_inventory_types(self) -> None:
        source = _lean_side_form_extraction_source(
            "original",
            [{"span": {"rva_start": 0x1000, "size": 1}}],
        )

        self.assertIn("span : ISAInventory.Span", source)
        self.assertIn("let bytes : ISAInventory.Bytes", source)
        partial = _lean_side_form_extraction_source(
            "original",
            [{"span": {"rva_start": 0x1000, "size": 1}}],
            allow_decode_gaps=True,
        )
        self.assertIn("unsupported_instruction_form", partial)

    def test_exact_lean_rows_bind_forms_locations_and_fallbacks(self) -> None:
        request = build_machine_ir_isa_extraction_request_v2(
            units=[_unit(), _unit(reachable=False)], binary_sha256=PE_SHA
        )
        payload = build_machine_ir_isa_requirements_v2(
            request=request,
            machine_ir_sha256=MACHINE_SHA,
            lean_rows=_rows(),
            lean_evidence=_evidence(),
        )
        parsed = parse_machine_ir_isa_requirements_v2(payload)

        self.assertEqual(parsed.status, "complete")
        self.assertEqual(payload["counts"], {
            "regions": 2,
            "forms": 2,
            "occurrences": 2,
        })
        self.assertEqual(
            {row[1] for row in parsed.fallback_capability_ids},
            {MACHINE_IR_FALLBACK_CAPABILITY_V2},
        )
        authority: Any = SimpleNamespace(
            requirements=SimpleNamespace(
                binary_sha256=PE_SHA,
                forms=parsed.forms,
            ),
            fallback_capability_ids=tuple(
                SimpleNamespace(form_id=form_id, capability_id=capability_id)
                for form_id, capability_id in parsed.fallback_capability_ids
            ),
        )
        self.assertEqual(
            compare_selection_to_machine_ir_requirements_v2(parsed, authority),
            [],
        )

    def test_semantic_projection_excludes_machine_ir_profile_and_provenance(self) -> None:
        first_request = build_machine_ir_isa_extraction_request_v2(
            units=[_unit(identity="profile-a-unit")], binary_sha256=PE_SHA
        )
        changed_unit = _unit(identity="profile-b-renamed-unit")
        changed_unit["profile"] = {"id": "profile-b", "provenance": "reviewed"}
        changed_unit["instructions"][0]["mnemonic"] = "diagnostic-push"
        second_request = build_machine_ir_isa_extraction_request_v2(
            units=[changed_unit], binary_sha256=PE_SHA
        )
        first = build_machine_ir_isa_requirements_v2(
            request=first_request,
            machine_ir_sha256=MACHINE_SHA,
            lean_rows=_rows(),
            lean_evidence=_evidence(),
        )
        second = build_machine_ir_isa_requirements_v2(
            request=second_request,
            machine_ir_sha256="f" * 64,
            lean_rows=_rows(),
            lean_evidence=_evidence(),
        )

        self.assertNotEqual(first["requirements_sha256"], second["requirements_sha256"])
        self.assertEqual(
            build_machine_ir_isa_semantic_requirements_v2(first),
            build_machine_ir_isa_semantic_requirements_v2(second),
        )

    def test_semantic_projection_changes_with_bytes_forms_and_checker(self) -> None:
        request = build_machine_ir_isa_extraction_request_v2(
            units=[_unit()], binary_sha256=PE_SHA
        )

        def project(*, rows=None, evidence=None):
            return build_machine_ir_isa_semantic_requirements_v2(
                build_machine_ir_isa_requirements_v2(
                    request=request,
                    machine_ir_sha256=MACHINE_SHA,
                    lean_rows=_rows() if rows is None else rows,
                    lean_evidence=_evidence() if evidence is None else evidence,
                )
            )["semantic_requirements_sha256"]

        changed_bytes = _rows()
        changed_bytes[("original", 0)][0]["bytes"] = "51"
        changed_form = _rows()
        changed_form[("original", 0)][0]["form"] = "push-register-alias"
        changed_checker = _evidence()
        changed_checker["extractor_sha256"] = "0" * 64

        baseline = project()
        self.assertNotEqual(baseline, project(rows=changed_bytes))
        self.assertNotEqual(baseline, project(rows=changed_form))
        self.assertNotEqual(baseline, project(evidence=changed_checker))

    def test_corrupted_authority_and_semantic_bindings_fail_closed(self) -> None:
        request = build_machine_ir_isa_extraction_request_v2(
            units=[_unit()], binary_sha256=PE_SHA
        )
        requirements = build_machine_ir_isa_requirements_v2(
            request=request,
            machine_ir_sha256=MACHINE_SHA,
            lean_rows=_rows(),
            lean_evidence=_evidence(),
        )
        corrupted_authority = copy.deepcopy(requirements)
        corrupted_authority["binding"]["machine_ir_sha256"] = "0" * 64
        with self.assertRaisesRegex(MachineIRISARequirementsV2Error, "self-hash"):
            parse_machine_ir_isa_requirements_v2(corrupted_authority)

        projection = build_machine_ir_isa_semantic_requirements_v2(requirements)
        projection["binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            MachineIRISARequirementsV2Error, "projection hash"
        ):
            parse_machine_ir_isa_semantic_requirements_v2(projection)

    def test_identical_instruction_locations_are_checked_once(self) -> None:
        request = build_machine_ir_isa_extraction_request_v2(
            units=[_unit(identity="path-a"), _unit(identity="path-b")],
            binary_sha256=PE_SHA,
        )

        self.assertEqual(len(request["regions"]), 2)
        self.assertEqual(
            [owner["unit_id"] for owner in request["regions"][0]["owners"]],
            ["path-a", "path-b"],
        )

    def test_different_overlapping_instruction_boundaries_are_rejected(self) -> None:
        first = {
            "id": "first",
            "reachable": True,
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1002}},
            "instructions": [{"rva_start": 0x1000, "rva_end": 0x1002}],
        }
        second = {
            "id": "second",
            "reachable": True,
            "source": {"original": {"rva_start": 0x1001, "rva_end": 0x1003}},
            "instructions": [{"rva_start": 0x1001, "rva_end": 0x1003}],
        }

        with self.assertRaisesRegex(
            MachineIRISARequirementsV2Error, "boundaries overlap"
        ):
            build_machine_ir_isa_extraction_request_v2(
                units=[first, second], binary_sha256=PE_SHA
            )

    def test_machine_ir_and_lean_location_disagreement_is_rejected(self) -> None:
        request = build_machine_ir_isa_extraction_request_v2(
            units=[_unit()], binary_sha256=PE_SHA
        )
        rows = _rows()
        rows[("original", 1)][0]["rva"] = 0x1002

        with self.assertRaisesRegex(
            MachineIRISARequirementsV2Error, "contradict"
        ):
            build_machine_ir_isa_requirements_v2(
                request=request,
                machine_ir_sha256=MACHINE_SHA,
                lean_rows=rows,
                lean_evidence=_evidence(),
            )

    def test_unsupported_form_is_localized_without_losing_supported_forms(self) -> None:
        request = build_machine_ir_isa_extraction_request_v2(
            units=[_unit()], binary_sha256=PE_SHA
        )
        rows = _rows()
        del rows[("original", 1)]

        payload = build_machine_ir_isa_requirements_v2(
            request=request,
            machine_ir_sha256=MACHINE_SHA,
            lean_rows=rows,
            lean_evidence=_evidence(),
            lean_gaps=[{
                "side": "original",
                "node_id": 1,
                "rva": 0x1001,
                "size": 2,
                "code": "unsupported_instruction_form",
            }],
        )

        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(payload["counts"]["forms"], 1)
        self.assertEqual(payload["issues"], [{
            "status": "incomplete",
            "code": "lean_semantic_form_unsupported",
            "unit_id": "unit-1000",
            "instruction_index": 1,
            "rva": 0x1001,
            "byte_length": 2,
            "decoder_code": "unsupported_instruction_form",
            "diagnostic_proposal": {
                "mnemonic": None,
                "operands": None,
            },
        }])

    def test_stale_self_hash_is_rejected(self) -> None:
        request = build_machine_ir_isa_extraction_request_v2(
            units=[_unit()], binary_sha256=PE_SHA
        )
        payload = build_machine_ir_isa_requirements_v2(
            request=request,
            machine_ir_sha256=MACHINE_SHA,
            lean_rows=_rows(),
            lean_evidence=_evidence(),
        )
        stale = copy.deepcopy(payload)
        stale["counts"]["forms"] += 1

        with self.assertRaisesRegex(
            MachineIRISARequirementsV2Error, "self-hash"
        ):
            parse_machine_ir_isa_requirements_v2(stale)


if __name__ == "__main__":
    unittest.main()
