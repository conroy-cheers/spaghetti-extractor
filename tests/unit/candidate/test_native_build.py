from __future__ import annotations

import inspect
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.build_objects import _payload_symbol_rvas
from spaghetti_extractor.candidate.build_workflow import (
    _native_realization_object_sources,
    _prepare_portable_dispatch_registry,
    _retired_generated_function_symbols,
    _stage_provider_objects,
    build_native_realization_payload,
)
from spaghetti_extractor.candidate.build_model import CandidateNativeBuildError
from spaghetti_extractor.candidate.native_build import _link_flags
from spaghetti_extractor.semantic_providers.qualification_v2 import SemanticProviderQualificationV2
from spaghetti_extractor.util import sha256_file, write_json


class NativeModuleBuildContractTests(unittest.TestCase):
    def test_only_wholly_portable_absent_generated_functions_get_guards(self):
        def qualification(kind, rows):
            return SemanticProviderQualificationV2({
                "provider_kind": kind,
                "definition_materializations": [
                    {"definition_id": definition, "native_symbol": symbol}
                    for definition, symbol in rows],
            })
        generated = qualification("generated_behavioral_c", [
            ("entry", "whole"), ("tail", "whole"),
            ("other-entry", "partial"), ("other-tail", "partial"),
            ("kept", "retained"),
        ])
        portable = qualification("qualified_portable_c", [("entry", "overlay")])
        self.assertEqual(_retired_generated_function_symbols(
            qualifications=[generated, portable],
            portable_definition_ids={"entry", "tail", "other-entry", "kept"},
            linked_symbols={"retained"}), ("whole",))
        self.assertEqual(_retired_generated_function_symbols(
            qualifications=[generated], portable_definition_ids={"entry"},
            linked_symbols=set()), ())
        # A second generated qualification must not hide an unselected tail.
        self.assertEqual(_retired_generated_function_symbols(
            qualifications=[generated, qualification("generated_behavioral_c", [("extra", "whole")])],
            portable_definition_ids={"entry", "tail"}, linked_symbols=set()), ())

    def test_public_build_is_ingress_plan_and_module_name_driven(self) -> None:
        parameters = inspect.signature(
            build_native_realization_payload
        ).parameters
        self.assertIn("native_ingress_plan", parameters)
        self.assertIn("candidate_filename", parameters)
        self.assertIn("native_realization_object_manifest", parameters)
        self.assertIn("linked_semantic_module", parameters)
        self.assertIn("implementation_selection", parameters)
        self.assertNotIn("behavioral_c_package", parameters)
        self.assertNotIn("shared_module_runtime_package", parameters)
        self.assertNotIn("execution_closure", parameters)
        self.assertNotIn("resolved_external_environment", parameters)
        self.assertNotIn("structural_execution_receipt", parameters)
        self.assertNotIn("supplemental_object_packages", parameters)
        self.assertNotIn("activation_plan", parameters)
        self.assertNotIn("anchor_manifest", parameters)
        self.assertNotIn("entry_symbol", parameters)
        self.assertNotIn("machine_ir", parameters)
        self.assertNotIn("machine_ir_manifest", parameters)

    def test_linker_map_is_the_symbol_rva_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            linker_map = Path(temporary) / "module.map"
            linker_map.write_text(
                "                0x00405000                _spx_ingress_0000\n"
                "                0x00406120                _spx_native_tls_index_cell_pointer\n",
                encoding="ascii",
            )
            self.assertEqual(
                _payload_symbol_rvas(linker_map, image_base=0x400000),
                {
                    "spx_ingress_0000": 0x5000,
                    "spx_native_tls_index_cell_pointer": 0x6120,
                },
            )

    def test_linker_entry_is_generic_ingress(self) -> None:
        flags = _link_flags(
            entry_symbol="spx_ingress_0000",
            image_base=0x400000,
            payload_rva=0x5000,
            section_alignment=0x1000,
            file_alignment=0x200,
            linker_map=Path("module.map"),
        )
        self.assertIn("-Wl,--entry,_spx_ingress_0000", flags)
        self.assertFalse(any("spx_payload_entry" in item for item in flags))

    def test_realization_objects_are_content_bound_by_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            objects = root / "objects"
            objects.mkdir()
            native_object = objects / "000.o"
            native_object.write_bytes(b"realization-object")
            core = {
                "objects": [{
                    "path": "objects/000.o",
                    "source": "runtime.c",
                    "source_sha256": "1" * 64,
                    "object_sha256": sha256_file(native_object),
                }],
                "compiler_sha256": "2" * 64,
            }
            manifest = root / "provider-object-manifest.json"
            write_json(manifest, {
                **core,
                "receipt_sha256": canonical_sha256_v3(core),
            })

            by_source, object_hashes, identity = (
                _native_realization_object_sources(manifest)
            )
            self.assertEqual(set(by_source), {"1" * 64})
            self.assertEqual(object_hashes, {sha256_file(native_object)})
            self.assertEqual(identity, canonical_sha256_v3(core))

            native_object.write_bytes(b"mutated")
            with self.assertRaisesRegex(
                CandidateNativeBuildError,
                "native realization object binding is stale",
            ):
                _native_realization_object_sources(manifest)

    def test_portable_provider_objects_link_directly_from_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "provider"
            output = root / "output"
            objects = output / "objects"
            package.mkdir()
            objects.mkdir(parents=True)
            source_object = package / "portable.o"
            source_object.write_bytes(b"portable-object")
            digest = sha256_file(source_object)
            binding = {
                "object_sha256": digest,
                "object_path": source_object,
                "provider_ids": ["portable.main"],
                "provider_kinds": ["qualified_portable_c"],
                "symbol_ids": ["original:function:portable"],
                "qualification_sha256s": ["3" * 64],
            }

            paths, rows = _stage_provider_objects(
                selected_objects_by_source={"4" * 64: binding},
                expected_selected_object_hashes={digest},
                realization_objects_by_source={},
                expected_realization_object_hashes=set(),
                objects=objects,
                output=output,
            )

            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0].name, "000-provider.o")
            self.assertEqual(paths[0].read_bytes(), b"portable-object")
            self.assertEqual(rows[0]["cache"], "selected_provider_object_package")
            self.assertEqual(rows[0]["source"]["owner"], "component")
            self.assertEqual(
                rows[0]["selected_provider"]["symbol_ids"],
                ["original:function:portable"],
            )

    def test_nonportable_link_skips_dispatch_registry_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = _prepare_portable_dispatch_registry(
                portable_inputs=[],
                transfer_plan=root / "not-needed.json",
                provider_qualifications=[],
                compiler=root / "not-needed-cc",
                nm=root / "not-needed-nm",
                object_paths=[],
                object_rows=[],
                objects=root,
                output=root,
                environment={},
            )
            self.assertEqual(result, {"entries": [], "registry": None})

    def test_realization_provider_objects_link_without_source_packages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            objects = output / "objects"
            objects.mkdir(parents=True)
            source_object = root / "ingress.o"
            source_object.write_bytes(b"intrinsic-object")
            digest = sha256_file(source_object)
            paths, rows = _stage_provider_objects(
                selected_objects_by_source={},
                expected_selected_object_hashes=set(),
                realization_objects_by_source={
                    "5" * 64: {
                        "object_sha256": digest,
                        "object_path": source_object,
                        "source": "ingress.S",
                        "source_owner": "shared_module_runtime",
                        "source_role": "native_ingress_bridge_assembly",
                        "language": "assembler-with-cpp",
                        "flags": ["-m32"],
                    }
                },
                expected_realization_object_hashes={digest},
                objects=objects,
                output=output,
            )
            self.assertEqual([path.name for path in paths], ["000-provider.o"])
            self.assertEqual(rows[0]["source"]["sha256"], "5" * 64)
            self.assertEqual(
                rows[0]["cache"], "native_realization_object_package"
            )


if __name__ == "__main__":
    unittest.main()
