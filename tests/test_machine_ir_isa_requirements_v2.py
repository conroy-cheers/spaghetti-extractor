from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace

from spaghetti_extractor.analysis.isa_requirements import (
    _lean_side_form_extraction_source,
)
from spaghetti_extractor.machine_ir_isa_requirements_v2 import (
    MACHINE_IR_FALLBACK_CAPABILITY_V2,
    MachineIRISARequirementsV2Error,
    build_machine_ir_isa_extraction_request_v2,
    build_machine_ir_isa_requirements_v2,
    compare_selection_to_machine_ir_requirements_v2,
    parse_machine_ir_isa_requirements_v2,
)


PE_SHA = "a" * 64
MACHINE_SHA = "b" * 64
CLASSIFIER_SHA = "c" * 64
EXTRACTOR_SHA = "d" * 64
SOURCE_SHA = "e" * 64


def _unit(*, reachable: bool = True) -> dict[str, object]:
    return {
        "id": "unit-1000",
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


def _rows() -> dict[tuple[str, int], tuple[dict[str, object], ...]]:
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
        authority = SimpleNamespace(
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
