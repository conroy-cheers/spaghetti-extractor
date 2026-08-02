from __future__ import annotations

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
from spaghetti_extractor.stage_b_interpreter_backend import (
    write_stage_b_interpreter_package,
)
from spaghetti_extractor.stage_b_interpreter_native_build import (
    INTERPRETER_NATIVE_BUILD_FORMAT,
    INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME,
    StageBInterpreterNativeBuildError,
    assemble_stage_b_interpreter_native_objects,
    build_stage_b_interpreter_native_candidate,
    compile_stage_b_interpreter_native_object,
    prepare_stage_b_interpreter_native_object_graph,
)
from spaghetti_extractor.stage_b_native_engine import (
    write_stage_b_native_engine_package,
)
from spaghetti_extractor.stage_b_native_runtime import (
    write_stage_b_native_runtime_package,
)
from spaghetti_extractor.stage_b_pe_composer import (
    EXECUTABLE_ANCHOR_MANIFEST_FORMAT,
)
from spaghetti_extractor.util import sha256_file


PE_OFFSET = 0x80
FILE_HEADER_OFFSET = PE_OFFSET + 4
OPTIONAL_OFFSET = FILE_HEADER_OFFSET + 20
SECTION_TABLE_OFFSET = OPTIONAL_OFFSET + 224


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


def _transfer(rva: int = 0x1000) -> dict[str, object]:
    return {
        "id": f"semantic-transfer:{rva:08x}",
        "contract_sha256": "a" * 64,
        "instruction_bytes_sha256": "b" * 64,
        "original": {"rva_start": rva, "rva_end": rva + 1, "size": 1},
        "instructions": [],
        "ordered_events": [],
        "register_writes": [],
        "flag_writes": [],
        "fpu_state": None,
        "outcome": {"kind": "return", "value": {"op": "reg", "name": "eax"}},
    }


class _Packages:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.interpreter = root / "interpreter"
        self.engine = root / "engine"
        self.runtime = root / "runtime"
        self.original = root / "original.exe"
        self.contract = root / "load-image-contract.json"
        self.anchors = root / "anchors.json"
        root.mkdir(parents=True)

        state_machine = root / "state-machine.jsonl"
        state_machine.write_text(
            json.dumps(_transfer(), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        write_stage_b_interpreter_package(
            state_machine=state_machine, out=self.interpreter
        )
        write_stage_b_native_engine_package(
            state_machine=state_machine, entry_rva=0x1000, out=self.engine
        )
        write_stage_b_native_runtime_package(
            interpreter_package=self.interpreter,
            native_engine_package=self.engine,
            out=self.runtime,
        )

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
                        "bytes_hex": (
                            b"\xe9" + struct.pack("<i", displacement)
                        ).hex(),
                    }
                ],
            },
        )


class StageBInterpreterNativeBuildValidationTests(unittest.TestCase):
    def test_rejects_stale_runtime_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            packages = _Packages(Path(temporary) / "inputs")
            source = packages.runtime / "native-runtime.c"
            source.write_text(
                source.read_text(encoding="ascii") + "\n", encoding="ascii"
            )

            with self.assertRaisesRegex(
                StageBInterpreterNativeBuildError,
                "native_runtime .* SHA-256 mismatch",
            ):
                build_stage_b_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    load_image_contract=packages.contract,
                    anchor_manifest=packages.anchors,
                    out_dir=Path(temporary) / "candidate",
                )

    def test_rejects_incomplete_package_before_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            packages = _Packages(Path(temporary) / "inputs")
            manifest_path = packages.interpreter / "state-machine-interpreter-package.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["status"] = "incomplete"
            _write_json(manifest_path, manifest)

            with self.assertRaisesRegex(
                StageBInterpreterNativeBuildError, "interpreter package is not ready"
            ):
                build_stage_b_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    load_image_contract=packages.contract,
                    anchor_manifest=packages.anchors,
                    out_dir=Path(temporary) / "candidate",
                    compiler="compiler-must-not-be-consulted",
                )


@unittest.skipUnless(
    shutil.which("i686-w64-mingw32-gcc"), "i686 MinGW compiler unavailable"
)
class StageBInterpreterNativeBuildIntegrationTests(unittest.TestCase):
    def test_builds_content_bound_relocatable_candidate_and_linker_map(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            manifest = build_stage_b_interpreter_native_candidate(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                load_image_contract=packages.contract,
                out_dir=root / "candidate",
            )
            repeated = build_stage_b_interpreter_native_candidate(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                load_image_contract=packages.contract,
                out_dir=root / "candidate-repeated",
            )
            graph_dir = root / "object-graph"
            graph = prepare_stage_b_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                out_dir=graph_dir,
            )
            object_packages = []
            for unit in graph["units"]:
                object_dir = root / "cached-objects" / unit["id"]
                compile_stage_b_interpreter_native_object(
                    graph=graph_dir, unit_id=unit["id"], out_dir=object_dir
                )
                object_packages.append(object_dir)
            object_package = root / "object-package"
            assemble_stage_b_interpreter_native_objects(
                graph=graph_dir,
                object_packages=object_packages,
                out_dir=object_package,
            )
            cached = build_stage_b_interpreter_native_candidate(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                load_image_contract=packages.contract,
                precompiled_objects=object_package,
                out_dir=root / "candidate-cached",
            )

            output = root / "candidate"
            repeated_output = root / "candidate-repeated"
            self.assertEqual(manifest, repeated)
            self.assertEqual(
                (output / "candidate.exe").read_bytes(),
                (repeated_output / "candidate.exe").read_bytes(),
            )
            self.assertEqual(
                (output / "payload.map").read_bytes(),
                (repeated_output / "payload.map").read_bytes(),
            )
            self.assertEqual(
                (output / "candidate.exe").read_bytes(),
                (root / "candidate-cached" / "candidate.exe").read_bytes(),
            )
            self.assertEqual(
                cached["policy"]["object_compilation"],
                "content-addressed-per-source",
            )
            self.assertEqual(manifest["format"], INTERPRETER_NATIVE_BUILD_FORMAT)
            self.assertEqual(manifest["status"], "candidate-generated")
            self.assertEqual(manifest["acceptance_authority"], "none")
            self.assertEqual(manifest["qualification"]["payload_imports"], 0)
            self.assertTrue(manifest["qualification"]["dynamic_base"])
            self.assertTrue(
                manifest["qualification"]["relocation_inventory_complete"]
            )
            self.assertGreaterEqual(
                manifest["qualification"]["base_relocations"], 1
            )
            self.assertTrue((output / "candidate.exe").is_file())
            self.assertTrue((output / "payload.map").is_file())
            self.assertTrue(
                (output / "executable-anchor-manifest.json").is_file()
            )
            self.assertTrue(
                (output / INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME).is_file()
            )
            self.assertEqual(
                manifest["outputs"]["linker_map"]["sha256"],
                sha256_file(output / "payload.map"),
            )
            for name in (
                "interpreter_package",
                "native_engine_package",
                "native_runtime_package",
            ):
                binding = manifest["inputs"][name]
                self.assertRegex(binding["manifest_sha256"], r"^[0-9a-f]{64}$")
                self.assertTrue(binding["artifacts"])

            payload = pefile.PE(str(output / "payload.exe"))
            file_header: Any = payload.FILE_HEADER
            optional: Any = payload.OPTIONAL_HEADER
            self.assertEqual(int(file_header.Machine), 0x14C)
            self.assertEqual(int(optional.Magic), 0x10B)
            self.assertFalse(int(file_header.Characteristics) & 0x0001)
            self.assertTrue(int(optional.DllCharacteristics) & 0x0040)
            self.assertGreater(int(optional.DATA_DIRECTORY[5].Size), 0)
            for index in (1, 9, 12, 13):
                directory = optional.DATA_DIRECTORY[index]
                self.assertEqual(
                    (int(directory.VirtualAddress), int(directory.Size)), (0, 0)
                )
            payload.close()

            cached_manifest = json.loads(
                (object_package / "native-object-package.json").read_text(
                    encoding="utf-8"
                )
            )
            cached_object = object_package / cached_manifest["objects"][0]["path"]
            cached_object.write_bytes(cached_object.read_bytes() + b"\x00")
            with self.assertRaisesRegex(
                StageBInterpreterNativeBuildError,
                "native object package artifact is stale",
            ):
                build_stage_b_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    load_image_contract=packages.contract,
                    precompiled_objects=object_package,
                    out_dir=root / "candidate-tampered-cache",
                )


if __name__ == "__main__":
    unittest.main()
