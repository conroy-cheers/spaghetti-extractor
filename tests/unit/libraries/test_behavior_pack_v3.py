from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.libraries.behavior_pack_v3 import (
    ReusableLibraryBehaviorPackV3Error,
    ReusableLibrarySourceQualificationV1,
    build_reusable_library_behavior_pack_v3,
    load_reusable_library_behavior_pack_v3,
)
from spaghetti_extractor.libraries.v4_adoption_records import (
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1,
    LibraryOperationSourceMappingV1,
    ReusableLibraryImplementationV1,
)
from spaghetti_extractor.libraries.v4_behavior_manifest import (
    read_library_behavior_pack_declaration,
)
from spaghetti_extractor.util import write_json

TESTKIT = {
    "resources": (
        "targets/gnu-hello/intent/interfaces-v5/ascii-to-lower.json",
    )
}


def build_behavior_pack_v3_fixture(root: Path) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    repository = Path(__file__).resolve().parents[3]
    intent_payload = json.loads(
        (
            repository
            / "targets/gnu-hello/intent/interfaces-v5/ascii-to-lower.json"
        ).read_text(encoding="utf-8")
    )
    intent = ComponentInterfaceIntentV1.parse(intent_payload)
    interface = compile_component_interface_v5(intent).interface
    intent_path = root / "interface-intent.json"
    write_json(intent_path, intent.to_payload())

    source_path = root / "ascii-to-lower.c"
    source_path.write_text(
        '#include "portable-component-implementation.h"\n'
        "uint32_t spx_ascii_to_lower(\n"
        "    spx_ascii_to_lower_context_v5 *context, uint32_t value) {\n"
        "  (void)context;\n"
        "  return value >= 'A' && value <= 'Z' ? value + 32u : value;\n"
        "}\n",
        encoding="ascii",
    )
    source_root = root / "source"
    source = build_component_source_package(
        lift_unit_id=interface.identity,
        files={"ascii-to-lower.c": source_path},
        shared_inputs={},
        operation_symbols={"convert": "spx_ascii_to_lower"},
        out_dir=source_root,
    )

    qualification = ReusableLibrarySourceQualificationV1.create(
        component_id=interface.identity,
        interface_sha256=interface.interface_sha256,
        source_package_sha256=str(source["implementation_sha256"]),
        proof_receipt_sha256s=["a" * 64],
        checks=[
            {
                "code": "portable_source_refines_library_behavior",
                "status": "checked",
            }
        ],
    )
    qualification_path = root / "qualification.json"
    write_json(qualification_path, qualification.to_payload())

    mapping = LibraryOperationSourceMappingV1.create(
        operation_id="convert",
        source_id=interface.identity,
        source_symbol="spx_ascii_to_lower",
        source_sha256=str(source["implementation_sha256"]),
    )
    implementation = ReusableLibraryImplementationV1.create(
        family_id="fixture-runtime",
        recipe_id="recipe.fixture.ascii-to-lower-v1",
        compatible_release_ids=["fixture-runtime-1.0"],
        operation_source_mappings=[mapping],
        interface_contract_ids=[interface.identity],
        effect_contract_ids=[],
        compile_profile_id="pe32-c11-v1",
        qualification_checker_id="static-refinement-v1",
        qualification_receipt_sha256=qualification.receipt_sha256,
    )
    implementation_path = root / "implementation.json"
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.write(
        implementation_path, implementation
    )
    pack_root = root / "pack"
    build_reusable_library_behavior_pack_v3(
        implementation=implementation_path,
        interface_intent=intent_path,
        source_package=source_root,
        qualification=qualification_path,
        out_dir=pack_root,
    )
    return {
        "implementation": implementation_path,
        "intent": intent_path,
        "source": source_root,
        "qualification": qualification_path,
        "pack": pack_root,
    }


class ReusableLibraryBehaviorPackV3Tests(unittest.TestCase):

    def test_pack_binds_v5_interface_source_symbols_and_static_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = build_behavior_pack_v3_fixture(root)
            pack = load_reusable_library_behavior_pack_v3(fixture["pack"])
            loaded = load_reusable_library_behavior_pack_v3(root / "pack")
            self.assertEqual(loaded.pack_sha256, pack.pack_sha256)
            self.assertEqual(
                loaded.manifest["operation_symbols"],
                {"convert": "spx_ascii_to_lower"},
            )
            self.assertFalse(loaded.manifest["policy"]["recognition_authorizes"])
            self.assertFalse(
                loaded.manifest["policy"]["legacy_component_adapters_allowed"]
            )
            declaration = read_library_behavior_pack_declaration(fixture["pack"])
            self.assertEqual(
                declaration.implementation.implementation_id,
                loaded.implementation.implementation_id,
            )

    def test_pack_rejects_tampered_source_even_with_unchanged_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = build_behavior_pack_v3_fixture(root)
            source = root / "pack/source-package/sources/ascii-to-lower.c"
            source.write_text("/* stale */\n", encoding="ascii")
            with self.assertRaises(ReusableLibraryBehaviorPackV3Error):
                load_reusable_library_behavior_pack_v3(root / "pack")

    def test_qualification_cannot_be_created_from_tests_without_static_proof(self) -> None:
        with self.assertRaises(ReusableLibraryBehaviorPackV3Error):
            ReusableLibrarySourceQualificationV1.create(
                component_id="component",
                interface_sha256="a" * 64,
                source_package_sha256="b" * 64,
                proof_receipt_sha256s=[],
                checks=[{"code": "test_passed", "status": "checked"}],
            )


if __name__ == "__main__":
    unittest.main()
