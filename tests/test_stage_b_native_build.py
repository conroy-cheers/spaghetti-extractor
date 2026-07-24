from __future__ import annotations

import copy
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any

import pefile

from tests.pe_fixtures import pe32_image

from spaghetti_extractor.roundtrip_fuzz.image_contract import (
    write_stage_a_load_image_contract,
)
from spaghetti_extractor.stage_b_engine_layout import (
    EngineLayoutFeature,
    render_stage_b_engine_layout_c,
)
from spaghetti_extractor.stage_b_native_build import (
    BUILD_MANIFEST_FILENAME,
    COMPILE_MANIFEST_FILENAME,
    ENGINE_LAYOUT_FILENAME,
    NATIVE_BUILD_COMPILE_FORMAT,
    NATIVE_BUILD_MANIFEST_FORMAT,
    NATIVE_BUILD_PREPARE_FORMAT,
    PAYLOAD_FILENAME,
    PAYLOAD_RELOCATION_INVENTORY_FILENAME,
    PREPARE_MANIFEST_FILENAME,
    StageBNativeBuildError,
    build_stage_b_native_candidate,
    compile_stage_b_native_payload,
    compose_stage_b_native_candidate,
    prepare_stage_b_native_build,
)
from spaghetti_extractor.stage_b_pe_composer import (
    EXECUTABLE_ANCHOR_MANIFEST_FORMAT,
)
from spaghetti_extractor.util import sha256_file


PE_OFFSET = 0x80
FILE_HEADER_OFFSET = PE_OFFSET + 4
OPTIONAL_OFFSET = FILE_HEADER_OFFSET + 20
SECTION_TABLE_OFFSET = OPTIONAL_OFFSET + 224
STATE_MACHINE_SHA256 = "5" * 64


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _expanded_header_pe() -> bytes:
    source = bytearray(pe32_image(b"\x90" * 8 + b"\xc3"))
    source[0x200:0x200] = bytes(0x200)
    struct.pack_into("<I", source, OPTIONAL_OFFSET + 60, 0x400)
    struct.pack_into("<I", source, SECTION_TABLE_OFFSET + 20, 0x400)
    return bytes(source)


def _runtime_header(*, include_tags: bool = True) -> str:
    tag = "  uint8_t tag;\n" if include_tags else ""
    return f"""#ifndef STAGE_B_STATE_MACHINE_RUNTIME_H
#define STAGE_B_STATE_MACHINE_RUNTIME_H
#include <stdint.h>
typedef struct stage_b_x87_value {{
  uint8_t value_bytes[10];
  uint32_t empty;
{tag}}} stage_b_x87_value;
typedef struct stage_b_machine_state {{
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
  uint32_t cf, zf, sf, of, pf, df;
  stage_b_x87_value x87_stack[8];
  uint16_t x87_control;
  uint16_t x87_status;
  uint8_t x87_pending_exception;
  uint16_t x87_last_opcode;
  uint32_t x87_instruction_pointer;
  uint16_t x87_code_selector;
  uint32_t x87_data_pointer;
  uint16_t x87_data_selector;
  uint32_t eflags;
  uint32_t fs_base;
  uint32_t original_rva;
}} stage_b_machine_state;
#endif
"""


class _Packages:
    def __init__(self, root: Path, *, include_tags: bool = True) -> None:
        self.root = root
        self.semantic = root / "semantic"
        self.native = root / "native"
        self.semantic.mkdir(parents=True)
        self.native.mkdir(parents=True)
        self.original = root / "original.exe"
        self.contract = root / "load-image-contract.json"
        self.anchors = root / "anchors.json"
        self.original.write_bytes(_expanded_header_pe())
        contract = write_stage_a_load_image_contract(
            original_pe=self.original, out=self.contract
        )
        payload_rva = contract.identity.image_size
        displacement = payload_rva - (contract.identity.entry_rva + 5)
        _write_json(
            self.anchors,
            {
                "format": EXECUTABLE_ANCHOR_MANIFEST_FORMAT,
                "image_base": contract.identity.preferred_base,
                "entry_anchor_rva": contract.identity.entry_rva,
                "tls_callback_anchor_rvas": [],
                "callback_anchor_rvas": [],
                "anchors": [
                    {
                        "rva": contract.identity.entry_rva,
                        "bytes_hex": (b"\xe9" + struct.pack("<i", displacement)).hex(),
                    }
                ],
            },
        )
        self._write_semantic(include_tags=include_tags)
        self._write_native()

    def _write_semantic(self, *, include_tags: bool) -> None:
        files = {
            "state-machine-runtime.h": _runtime_header(include_tags=include_tags),
            "state-machine-transfers.h": "#include \"state-machine-runtime.h\"\n",
            "state-machine-transfers.c": (
                "#include \"state-machine-transfers.h\"\n"
                "uint32_t stage_b_generated_transfer(void) { return 7U; }\n"
            ),
            "state-machine-repairs.c": "#include \"state-machine-transfers.h\"\n",
            "state-machine-dispatch.h": "#include \"state-machine-runtime.h\"\n",
            "state-machine-dispatch.c": (
                "#include \"state-machine-dispatch.h\"\n"
                "uint32_t stage_b_generated_dispatch(void) { return 11U; }\n"
            ),
            "state-machine-engine.h": "#include \"state-machine-runtime.h\"\n",
            "state-machine-engine.c": (
                "#include \"state-machine-engine.h\"\n"
                "uint32_t stage_b_generated_engine(void) { return 13U; }\n"
            ),
            "state-machine-api-adapters.h": "#include \"state-machine-runtime.h\"\n",
            "state-machine-api-adapters.c": (
                "#include \"state-machine-api-adapters.h\"\n"
            ),
        }
        for name, content in files.items():
            (self.semantic / name).write_text(content, encoding="ascii")
        _write_json(self.semantic / "state-machine-api-adapters.json", {})
        _write_json(self.semantic / "state-machine-source-map.json", {})
        obligations = {
            "format": "stage-b-runtime-call-obligations-v1",
            "status": "complete",
            "authority": "stage-a-semantic-transfer-contracts",
            "state_machine": {
                "path": "state-machine.jsonl",
                "sha256": STATE_MACHINE_SHA256,
            },
            "machine_call_catalog": None,
            "counts": {
                "call_boundaries": 0,
                "unbound_obligations": 0,
                "by_status": {},
                "unbound_by_kind": {},
            },
            "call_boundaries": [],
            "acceptance": "candidate generation remains subject to Stage A",
        }
        _write_json(
            self.semantic / "state-machine-runtime-obligations.json", obligations
        )
        artifact_names = {
            "runtime_header": "state-machine-runtime.h",
            "transfers_header": "state-machine-transfers.h",
            "generated_source": "state-machine-transfers.c",
            "repair_source": "state-machine-repairs.c",
            "dispatch_header": "state-machine-dispatch.h",
            "dispatch_source": "state-machine-dispatch.c",
            "engine_header": "state-machine-engine.h",
            "engine_source": "state-machine-engine.c",
            "api_adapters_header": "state-machine-api-adapters.h",
            "api_adapters_source": "state-machine-api-adapters.c",
            "api_adapters_report": "state-machine-api-adapters.json",
            "source_map": "state-machine-source-map.json",
            "runtime_obligations": "state-machine-runtime-obligations.json",
        }
        artifacts = {
            key: {"path": name, "sha256": sha256_file(self.semantic / name)}
            for key, name in artifact_names.items()
        }
        _write_json(
            self.semantic / "state-machine-implementation.json",
            {
                "format": "stage-b-semantic-c-implementation-v1",
                "authority": "stage-a-semantic-transfer-contracts",
                "status": "complete",
                "state_machine": {
                    "path": "state-machine.jsonl",
                    "sha256": STATE_MACHINE_SHA256,
                },
                "machine_call_catalog": None,
                "transfer_inventory": [
                    {
                        "id": "semantic-transfer:entry",
                        "contract_sha256": "6" * 64,
                        "rva_start": 0x1000,
                        "symbol": "stage_b_generated_transfer",
                        "implementation": "generated_semantic_c",
                    }
                ],
                "artifacts": artifacts,
                "strict_candidate": {
                    "status": "ready",
                    "blockers": [],
                    "policy": "strict",
                },
                "acceptance": "Stage A proof required",
            },
        )

    def _write_native(self, *, bridge_source: str | None = None) -> None:
        (self.native / "native-engine-wrapper.h").write_text(
            "#include \"state-machine-runtime.h\"\n", encoding="ascii"
        )
        (self.native / "native-engine-wrapper.c").write_text(
            "#include \"native-engine-wrapper.h\"\n"
            "uint32_t stage_b_native_marker(void) { return 17U; }\n",
            encoding="ascii",
        )
        (self.native / "native-engine-bridges.S").write_text(
            bridge_source
            if bridge_source is not None
            else (
                ".intel_syntax noprefix\n"
                ".text\n"
                ".globl _stage_b_payload_entry\n"
                "_stage_b_payload_entry:\n"
                "  jmp _stage_b_payload_entry\n"
            ),
            encoding="ascii",
        )
        (self.native / "native-engine-layout.c").write_text(
            render_stage_b_engine_layout_c(
                flag_storage="split-and-packed",
                include_fs_base=True,
                include_original_rva=True,
            ),
            encoding="ascii",
        )
        plan = {
            "format": "stage-b-native-engine-plan-v1",
            "status": "ready",
            "state_machine_sha256": STATE_MACHINE_SHA256,
            "entry_rva": 0x1000,
            "counts": {
                "transfers": 1,
                "external_sites": 0,
                "indirect_calls": 0,
                "callback_targets": 0,
                "blockers": 0,
            },
            "external_sites": [],
            "callback_targets": [],
            "blockers": [],
            "authority": "candidate generation only",
        }
        _write_json(self.native / "native-engine-plan.json", plan)
        sources = [
            "native-engine-wrapper.h",
            "native-engine-wrapper.c",
            "native-engine-bridges.S",
            "native-engine-layout.c",
        ]
        _write_json(
            self.native / "native-engine-package.json",
            {
                "format": "stage-b-native-engine-package-v1",
                "status": "ready",
                "plan": {
                    "path": "native-engine-plan.json",
                    "sha256": sha256_file(self.native / "native-engine-plan.json"),
                },
                "sources": [
                    {"path": name, "sha256": sha256_file(self.native / name)}
                    for name in sources
                ],
                "counts": plan["counts"],
                "blockers": [],
                "authority": "candidate generation only; Stage A proof required",
            },
        )

    def rewrite_native(self, bridge_source: str) -> None:
        self._write_native(bridge_source=bridge_source)


@unittest.skipUnless(
    shutil.which("i686-w64-mingw32-gcc"), "i686 MinGW compiler unavailable"
)
class StageBNativeBuildTests(unittest.TestCase):
    def test_prepare_is_deterministic_and_has_no_acceptance_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            packages = _Packages(Path(temporary) / "inputs")
            first = prepare_stage_b_native_build(
                semantic_c_package=packages.semantic,
                native_engine_package=packages.native,
                load_image_contract=packages.contract,
                anchor_manifest=packages.anchors,
                out_dir=Path(temporary) / "first",
            )
            second = prepare_stage_b_native_build(
                semantic_c_package=packages.semantic,
                native_engine_package=packages.native,
                load_image_contract=packages.contract,
                anchor_manifest=packages.anchors,
                out_dir=Path(temporary) / "second",
            )

            self.assertEqual(first, second)
            self.assertEqual(first["format"], NATIVE_BUILD_PREPARE_FORMAT)
            self.assertEqual(first["status"], "ready")
            self.assertEqual(first["acceptance_authority"], "none")
            self.assertEqual(first["runtime_binding"]["status"], "ready")
            self.assertNotIn(str(packages.root), json.dumps(first))

    def test_prepare_rejects_placeholder_bridge_and_missing_entry(self) -> None:
        cases = (
            (
                ".intel_syntax noprefix\n.text\n"
                ".globl _stage_b_payload_entry\n_stage_b_payload_entry:\n int3\n",
                "placeholder INT3 bridge source",
            ),
            (".intel_syntax noprefix\n.text\n nop\n", "does not define payload entry"),
        )
        for bridge, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                packages = _Packages(Path(temporary) / "inputs")
                packages.rewrite_native(bridge)
                with self.assertRaisesRegex(StageBNativeBuildError, message):
                    prepare_stage_b_native_build(
                        semantic_c_package=packages.semantic,
                        native_engine_package=packages.native,
                        load_image_contract=packages.contract,
                        anchor_manifest=packages.anchors,
                        out_dir=Path(temporary) / "prepare",
                    )

    def test_compile_rechecks_package_hashes_after_prepare(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            prepare_stage_b_native_build(
                semantic_c_package=packages.semantic,
                native_engine_package=packages.native,
                load_image_contract=packages.contract,
                anchor_manifest=packages.anchors,
                out_dir=root / "prepare",
            )
            source = packages.semantic / "state-machine-engine.c"
            source.write_text(source.read_text(encoding="ascii") + "\n", encoding="ascii")

            with self.assertRaisesRegex(StageBNativeBuildError, "changed after preparation"):
                compile_stage_b_native_payload(
                    prepare_manifest=root / "prepare" / PREPARE_MANIFEST_FILENAME,
                    semantic_c_package=packages.semantic,
                    native_engine_package=packages.native,
                    out_dir=root / "compile",
                )

    def test_compile_rejects_compiler_materialized_layout_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs", include_tags=False)
            prepare_stage_b_native_build(
                semantic_c_package=packages.semantic,
                native_engine_package=packages.native,
                load_image_contract=packages.contract,
                anchor_manifest=packages.anchors,
                out_dir=root / "prepare",
            )
            with self.assertRaisesRegex(
                StageBNativeBuildError, "compile native:source_.*failed"
            ):
                compile_stage_b_native_payload(
                    prepare_manifest=root / "prepare" / PREPARE_MANIFEST_FILENAME,
                    semantic_c_package=packages.semantic,
                    native_engine_package=packages.native,
                    out_dir=root / "compile",
                )

    def test_end_to_end_build_is_deterministic_and_payload_is_qualified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            first = build_stage_b_native_candidate(
                semantic_c_package=packages.semantic,
                native_engine_package=packages.native,
                load_image_contract=packages.contract,
                anchor_manifest=packages.anchors,
                out_dir=root / "first",
            )
            second = build_stage_b_native_candidate(
                semantic_c_package=packages.semantic,
                native_engine_package=packages.native,
                load_image_contract=packages.contract,
                anchor_manifest=packages.anchors,
                out_dir=root / "second",
            )

            self.assertEqual(first, second)
            self.assertEqual(first["format"], NATIVE_BUILD_MANIFEST_FORMAT)
            self.assertEqual(first["acceptance_authority"], "none")
            self.assertEqual(
                (root / "first" / "candidate.exe").read_bytes(),
                (root / "second" / "candidate.exe").read_bytes(),
            )
            first_compile = json.loads(
                (root / "first" / "compile" / COMPILE_MANIFEST_FILENAME).read_text()
            )
            second_compile = json.loads(
                (root / "second" / "compile" / COMPILE_MANIFEST_FILENAME).read_text()
            )
            self.assertEqual(first_compile, second_compile)
            self.assertEqual(first_compile["format"], NATIVE_BUILD_COMPILE_FORMAT)
            self.assertEqual(first_compile["qualification"]["imports"], 0)
            self.assertFalse(first_compile["qualification"]["fixed_base"])
            self.assertTrue(first_compile["qualification"]["dynamic_base"])
            self.assertGreaterEqual(
                first_compile["qualification"]["base_relocations"], 1
            )
            self.assertFalse(
                first_compile["qualification"]["relocations_stripped"]
            )
            self.assertTrue(
                first_compile["qualification"]["relocation_inventory_complete"]
            )
            self.assertEqual(
                first_compile["outputs"]["engine_layout"]["features"],
                int(
                    EngineLayoutFeature.SPLIT_FLAGS
                    | EngineLayoutFeature.PACKED_EFLAGS
                    | EngineLayoutFeature.FS_BASE
                    | EngineLayoutFeature.ORIGINAL_RVA
                ),
            )
            self.assertTrue((root / "first" / BUILD_MANIFEST_FILENAME).is_file())
            self.assertTrue((root / "first" / "compile" / ENGINE_LAYOUT_FILENAME).is_file())
            relocation_inventory_path = (
                root
                / "first"
                / "compile"
                / PAYLOAD_RELOCATION_INVENTORY_FILENAME
            )
            self.assertTrue(relocation_inventory_path.is_file())
            relocation_inventory = json.loads(
                relocation_inventory_path.read_text(encoding="utf-8")
            )
            self.assertTrue(relocation_inventory["complete"])
            self.assertEqual(
                relocation_inventory["payload_sha256"],
                first_compile["outputs"]["payload"]["sha256"],
            )
            self.assertGreaterEqual(len(relocation_inventory["relocations"]), 1)
            self.assertTrue(
                all(
                    (item["type"], item["kind"], item["width"])
                    == (3, "highlow", 4)
                    for item in relocation_inventory["relocations"]
                )
            )

            payload = pefile.PE(str(root / "first" / "compile" / PAYLOAD_FILENAME))
            file_header: Any = payload.FILE_HEADER
            optional: Any = payload.OPTIONAL_HEADER
            self.assertEqual(int(file_header.Machine), 0x14C)
            self.assertEqual(int(optional.Magic), 0x10B)
            self.assertFalse(int(file_header.Characteristics) & 0x0001)
            self.assertTrue(int(optional.DllCharacteristics) & 0x0040)
            for index in (1, 9, 12, 13):
                directory = optional.DATA_DIRECTORY[index]
                self.assertEqual((int(directory.VirtualAddress), int(directory.Size)), (0, 0))
            relocation_directory = optional.DATA_DIRECTORY[5]
            self.assertGreater(int(relocation_directory.VirtualAddress), 0)
            self.assertGreater(int(relocation_directory.Size), 0)
            payload.close()

    def test_composition_rejects_changed_payload_relocation_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            prepare_stage_b_native_build(
                semantic_c_package=packages.semantic,
                native_engine_package=packages.native,
                load_image_contract=packages.contract,
                anchor_manifest=packages.anchors,
                out_dir=root / "prepare",
            )
            compile_stage_b_native_payload(
                prepare_manifest=root / "prepare" / PREPARE_MANIFEST_FILENAME,
                semantic_c_package=packages.semantic,
                native_engine_package=packages.native,
                out_dir=root / "compile",
            )
            inventory_path = root / "compile" / PAYLOAD_RELOCATION_INVENTORY_FILENAME
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            inventory["relocations"][0]["preferred_value"] ^= 4
            _write_json(inventory_path, inventory)

            with self.assertRaisesRegex(
                StageBNativeBuildError,
                "relocation inventory changed after qualification",
            ):
                compose_stage_b_native_candidate(
                    prepare_manifest=root / "prepare" / PREPARE_MANIFEST_FILENAME,
                    compile_manifest=root / "compile" / COMPILE_MANIFEST_FILENAME,
                    load_image_contract=packages.contract,
                    anchor_manifest=packages.anchors,
                    out_dir=root / "candidate",
                )

    def test_composition_rejects_anchor_not_targeting_payload_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            anchors = json.loads(packages.anchors.read_text(encoding="utf-8"))
            bad = copy.deepcopy(anchors)
            bad["anchors"][0]["bytes_hex"] = "e900000000"
            _write_json(packages.anchors, bad)
            with self.assertRaisesRegex(StageBNativeBuildError, "entry anchor"):
                build_stage_b_native_candidate(
                    semantic_c_package=packages.semantic,
                    native_engine_package=packages.native,
                    load_image_contract=packages.contract,
                    anchor_manifest=packages.anchors,
                    out_dir=root / "out",
                )


if __name__ == "__main__":
    unittest.main()
