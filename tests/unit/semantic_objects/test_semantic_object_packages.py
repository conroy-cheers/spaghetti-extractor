"""Package loading, Behavioral-C, and corruption cases for semantic objects."""

from __future__ import annotations

import unittest

from . import test_semantic_object as support
from .test_semantic_object import (
    Path,
    SemanticObjectV1,
    canonical_sha256_v3,
    json,
    tempfile,
    write_spx_behavioral_c_package,
    write_spx_behavioral_c_package_from_semantic_object,
)


class SemanticObjectPackageTests(unittest.TestCase):
    def _fixture(self, *args, **kwargs):
        return support.SemanticObjectV1Tests._fixture(self, *args, **kwargs)
    def test_loaded_object_exposes_only_checked_member_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transfer, interface, output = self._fixture(root)
            semantic = SemanticObjectV1.load(output)
            self.assertEqual(
                semantic.transfer_plan_path.read_bytes(), transfer.read_bytes()
            )
            self.assertEqual(
                semantic.module_interface_path.read_bytes(), interface.read_bytes()
            )
            self.assertEqual(
                semantic.machine_object_authority_path,
                output.parent / "machine-object-authority.json",
            )
            self.assertIsNone(semantic.resolved_external_environment)

    def test_behavioral_c_bytes_match_through_object_reader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transfer, _, output = self._fixture(root)
            direct_root = root / "direct-c"
            object_root = root / "object-c"
            direct = write_spx_behavioral_c_package(
                transfer_plan=transfer, out=direct_root, entry_rvas=(0x1000,)
            )
            through_object = write_spx_behavioral_c_package_from_semantic_object(
                semantic_object=output, out=object_root, entry_rvas=(0x1000,)
            )
            self.assertEqual(direct["counts"], through_object["counts"])
            self.assertEqual(through_object["input_mode"], "semantic_object_v1")
            self.assertEqual(
                through_object["semantic_object"]["semantic_object_sha256"],
                SemanticObjectV1.load(output).identity,
            )
            direct_files = {
                path.name: path.read_bytes()
                for path in direct_root.iterdir()
                if path.name != "behavioral-c-package.json"
            }
            object_files = {
                path.name: path.read_bytes()
                for path in object_root.iterdir()
                if path.name != "behavioral-c-package.json"
            }
            self.assertEqual(object_files, direct_files)

    def test_incomplete_behavioral_review_keeps_mapped_source_but_cannot_qualify(self) -> None:
        from spaghetti_extractor.semantic_providers.generated_c import _materialize_generated_functions

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = support.transfer_row()
            missing = support.transfer_row()
            missing.update({"id": "semantic-transfer:missing", "status": "incomplete",
                            "original": {"rva_start": 0x1003, "rva_end": 0x1004, "size": 1}})
            _, _, semantic = self._fixture(root, image=support.pe32_image(b"\x40\x40\xc3\xc3"),
                                           transfer=[first, missing])
            review = root / "review"
            package = write_spx_behavioral_c_package_from_semantic_object(
                semantic_object=semantic, out=review, entry_rvas=(0x1000,))
            self.assertEqual(package["status"], "incomplete")
            self.assertEqual(package["counts"]["required_units"], 2)
            self.assertEqual(package["counts"]["lowered_units"], 1)
            source_map = json.loads((review / "behavioral-c-source-map.json").read_text())
            self.assertEqual([row["unit_id"] for row in source_map["units"]], [first["id"]])
            self.assertTrue((review / source_map["units"][0]["file"]).is_file())
            with self.assertRaisesRegex(ValueError, "generated Behavioral-C inputs are incomplete"):
                _materialize_generated_functions(behavioral_c_package=review,
                    compiler=root / "compiler-must-not-run", out=root / "provider", expected_symbols=set())
            self.assertFalse((root / "provider").exists())

    def test_corruption_matrix_fails_closed_after_rehashing_outer_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output = self._fixture(root)
            original = json.loads(output.read_text(encoding="utf-8"))
            plan = json.loads(
                (output.parent / "executable-transfer-plan.json").read_text(
                    encoding="utf-8"
                )
            )
            interface = json.loads(
                (output.parent / "module-interface.json").read_text(
                    encoding="utf-8"
                )
            )
            authority = json.loads(
                (output.parent / "machine-object-authority.json").read_text(
                    encoding="utf-8"
                )
            )

            cases: list[tuple[str, object]] = []
            stale_transfer = json.loads(json.dumps(original))
            stale_transfer["members"]["transfer_plan"]["identity"] = "0" * 64
            cases.append(("member", stale_transfer))
            stale_definition = json.loads(json.dumps(original))
            stale_definition["definitions"][0]["body"]["transfer_id"] += ":bad"
            cases.append(("declaration", stale_definition))
            stale_evidence_dependency = json.loads(json.dumps(original))
            stale_evidence_dependency["definitions"][0][
                "evidence_dependencies"
            ] = [0]
            cases.append(("definition-evidence", stale_evidence_dependency))
            stale_root = json.loads(json.dumps(original))
            stale_root["roots"][0]["target_symbol"] = None
            cases.append(("roots", stale_root))
            missing_hole = json.loads(json.dumps(original))
            missing_hole["holes"].pop()
            missing_hole["counts"]["holes"] -= 1
            cases.append(("holes", missing_hole))
            stale_binding = json.loads(json.dumps(original))
            stale_binding["bindings"]["exact_universe_sha256"] = "0" * 64
            cases.append(("bindings", stale_binding))

            for name, malformed in cases:
                with self.subTest(name=name):
                    malformed["semantic_object_sha256"] = canonical_sha256_v3({
                        key: value
                        for key, value in malformed.items()
                        if key != "semantic_object_sha256"
                    })
                    with self.assertRaises(Exception):
                        SemanticObjectV1.parse(
                            malformed,
                            transfer_plan=plan,
                            module_interface=interface,
                            machine_object_authority=authority,
                        )
