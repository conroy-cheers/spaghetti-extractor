from __future__ import annotations

import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.calls.dialects.ia32 import (
    IA32_DIALECT_CALLING_CONVENTIONS,
)
from spaghetti_extractor.qualified_platform.native_catalog import (
    abi_profile_catalog_payload_v1,
    native_primitive_catalog_payload_v1,
)
from spaghetti_extractor.qualified_platform.selection import (
    _form_selection_v1,
    _native_x87_exact_replay_issues_v1,
    _native_x87_exact_replay_qualification,
)


class QualifiedPlatformNativeCatalogTests(unittest.TestCase):
    def test_x87_exact_replay_is_a_distinct_checked_implementation(self) -> None:
        qualification = _native_x87_exact_replay_qualification({
            "native_primitives": native_primitive_catalog_payload_v1(),
        })
        self.assertIsNotNone(qualification)
        assert qualification is not None
        certified = {
            "oracle_status": "incomplete",
            "structural_status": "complete",
            "qualification_sha256": "a" * 64,
        }
        self.assertEqual(
            _form_selection_v1(
                semantic_form=(
                    "SpaghettiExtractor.ISA.Formal."
                    "InstructionSemanticForm.x87Unary cosine"
                ),
                certified=certified,
                native_x87_replay=qualification,
            ),
            (
                "qualified",
                "native_exact_replay",
                qualification["qualification_sha256"],
                "incomplete",
            ),
        )
        self.assertEqual(
            _form_selection_v1(
                semantic_form=(
                    "SpaghettiExtractor.ISA.Formal."
                    "InstructionSemanticForm.x87Unary cosine"
                ),
                certified={**certified, "oracle_status": "qualified"},
                native_x87_replay=qualification,
            )[1],
            "lean_semantics",
        )

        occurrence = {
            "form_id": "lean-x86-form:fixture",
            "unit_id": "semantic-transfer:fixture-x87",
            "rva_start": 0x1234,
            "rva_end": 0x1236,
            "instruction_bytes_sha256": "b" * 64,
        }
        plan = {"transfers": [{
            "identity": occurrence["unit_id"],
            "source": {
                "rva_start": occurrence["rva_start"],
                "rva_end": occurrence["rva_end"],
                "instruction_bytes_sha256": occurrence[
                    "instruction_bytes_sha256"
                ],
            },
            "effects": [{"op": "typed_x87", "operands": [0]}],
            "x87_intrinsics": [{
                "id": 0,
                "rva_start": occurrence["rva_start"],
                "rva_end": occurrence["rva_end"],
                "checked_decoder": (
                    "SpaghettiExtractor.ISA.Formal.decodeInstructionExact"
                ),
                "checked_executor": (
                    "SpaghettiExtractor.ISA.Formal.executeInstruction"
                ),
                "operation": {"source_size": 2},
            }],
        }]}
        self.assertEqual(
            _native_x87_exact_replay_issues_v1(
                transfer_plan=plan, occurrences=[occurrence]
            ),
            [],
        )
        plan["transfers"][0]["effects"] = []
        self.assertEqual(
            _native_x87_exact_replay_issues_v1(
                transfer_plan=plan, occurrences=[occurrence]
            )[0]["code"],
            "qualified_platform_exact_x87_replay_unbound",
        )

    def test_abi_catalog_is_closed_over_the_independent_checker(self) -> None:
        rows = abi_profile_catalog_payload_v1()
        self.assertEqual(
            [(row["profile_id"], row["abi_dialect"]) for row in rows],
            [
                ("pe32-i686-mingw32", "pe32-i386-gnu-v1"),
                ("pe32-i686-msvc", "pe32-i386-ms-v1"),
            ],
        )
        for row in rows:
            self.assertEqual(
                {item["id"] for item in row["calling_conventions"]},
                IA32_DIALECT_CALLING_CONVENTIONS[row["abi_dialect"]],
            )
            self.assertEqual(row["unsupported_calling_conventions"], ["custom"])
            self.assertEqual(row["data_layout"]["pointer_width_bits"], 32)
            self.assertEqual(
                row["physical_frame"]["format"],
                "spaghetti-extractor-physical-call-frame-v3",
            )

    def test_native_catalog_declares_stable_contracts_without_test_authority(self) -> None:
        rows = native_primitive_catalog_payload_v1()
        ids = [row["provider_id"] for row in rows]
        self.assertEqual(ids, sorted(set(ids)))
        self.assertEqual(len(rows), 8)
        for row in rows:
            core = {
                key: value
                for key, value in row.items()
                if key not in {"declaration_sha256", "qualification"}
            }
            self.assertEqual(
                row["declaration_sha256"], canonical_sha256_v3(core)
            )
            self.assertTrue(row["features"])
            self.assertEqual(row["features"], sorted(set(row["features"])))
            self.assertTrue(row["required_veto_gates"])
            self.assertEqual(
                row["required_veto_gates"],
                sorted(set(row["required_veto_gates"])),
            )
            self.assertEqual(
                row["qualification"]["authority"],
                "reviewed_native_primitive_contract",
            )
            self.assertEqual(row["qualification"]["status"], "complete")
            self.assertFalse(
                row["qualification"]["test_results_authorizing"]
            )
            review_core = {
                key: value for key, value in row["qualification"].items()
                if key not in {"status", "review_sha256"}
            }
            self.assertEqual(
                row["qualification"]["review_sha256"],
                canonical_sha256_v3(review_core),
            )


if __name__ == "__main__":
    unittest.main()
