from __future__ import annotations

import copy
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_image

from spaghetti_extractor.native_source_equivalence import (
    NativeSourceEquivalenceError,
    build_native_source_bundle_manifest,
    build_native_source_compilation_attestation,
    validate_native_source_bundle_manifest,
    validate_native_source_compilation_attestation,
)
from spaghetti_extractor.roundtrip_fuzz.image_contract import (
    write_stage_a_load_image_contract,
)
from spaghetti_extractor.stage_b_interpreter_backend import (
    write_stage_b_interpreter_package,
)
from spaghetti_extractor.stage_b_native_engine import (
    write_stage_b_native_engine_package,
)
from spaghetti_extractor.stage_b_native_runtime import (
    plan_stage_b_native_runtime,
    write_stage_b_native_runtime_package,
)
from spaghetti_extractor.stage_b_pe_composer import (
    PAYLOAD_RELOCATION_INVENTORY_FORMAT,
    PE_COMPOSITION_MANIFEST_FORMAT,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file


PE_OFFSET = 0x80
FILE_HEADER_OFFSET = PE_OFFSET + 4
OPTIONAL_OFFSET = FILE_HEADER_OFFSET + 20
SECTION_TABLE_OFFSET = OPTIONAL_OFFSET + 224


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _canonical_sha256(value: object) -> str:
    return sha256_bytes(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    )


def _closed(core: dict[str, object], field: str = "manifest_core_sha256") -> dict[str, object]:
    return {
        **core,
        "hashes": {"algorithm": "sha256", field: _canonical_sha256(core)},
    }


def _expanded_header_pe() -> bytes:
    source = bytearray(pe32_image(b"\x90" * 8 + b"\xc3"))
    source[0x200:0x200] = bytes(0x200)
    struct.pack_into("<I", source, OPTIONAL_OFFSET + 60, 0x400)
    struct.pack_into("<I", source, SECTION_TABLE_OFFSET + 20, 0x400)
    return bytes(source)


def _transfer(rva: int) -> dict[str, object]:
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


def _x87_transfer(rva: int = 0x1000) -> dict[str, object]:
    encoded = bytes.fromhex("d9e8")
    digest = sha256_bytes(encoded)
    row = _transfer(rva)
    row.update({
        "instruction_bytes_sha256": digest,
        "original": {"rva_start": rva, "rva_end": rva + 2, "size": 2},
        "instructions": [{
            "rva": rva,
            "size": 2,
            "bytes": encoded.hex(),
            "mnemonic": "fld1",
            "op_str": "",
        }],
        "outcome": {"kind": "fallthrough", "target_rva": rva + 2},
        "fpu_state": {
            "model": "native_exact_x87_command_replay_obligation_v1",
            "status": "required",
            "authoritative_state_type": "StageA.X87.PhysicalState",
            "required_fields": [
                "stack", "tags", "control", "status", "pending_exception",
                "last_opcode", "instruction_pointer", "code_selector",
                "data_pointer", "data_selector",
            ],
            "missing_or_invalid_fields": [
                "tags", "pending_exception", "last_opcode",
                "instruction_pointer", "code_selector", "data_pointer",
                "data_selector",
            ],
            "logical_state_guidance": {},
            "replay": {
                "format": "stage-a-native-exact-x87-command-replay-obligation-v1",
                "checked_decoder": "StageA.Relational.X87.decodeSingletonCommand",
                "checked_executor": "StageA.Relational.X87.executeSingletonCommand",
                "architecture": "x86",
                "bitness": 32,
                "image_base": 0x400000,
                "rva_start": rva,
                "rva_end": rva + 2,
                "bytes": encoded.hex(),
                "bytes_sha256": digest,
                "instructions": [{"rva": rva, "size": 2, "bytes": encoded.hex()}],
            },
        },
    })
    return row


class _SourceFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True)
        self.state_machine = root / "state-machine.jsonl"
        rows = [_x87_transfer(), _transfer(0x1002)]
        self.state_machine.write_text(
            "".join(
                json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                for row in rows
            ),
            encoding="utf-8",
        )
        self.interpreter = root / "interpreter"
        self.engine = root / "engine"
        self.runtime = root / "runtime"
        write_stage_b_interpreter_package(
            state_machine=self.state_machine, out=self.interpreter
        )
        write_stage_b_native_engine_package(
            state_machine=self.state_machine, entry_rva=0x1000, out=self.engine
        )
        write_stage_b_native_runtime_package(
            interpreter_package=self.interpreter,
            native_engine_package=self.engine,
            out=self.runtime,
        )
        self.original = root / "original.exe"
        self.original.write_bytes(_expanded_header_pe())
        self.contract = root / "load-image-contract.json"
        write_stage_a_load_image_contract(
            original_pe=self.original, out=self.contract
        )
        self.bundle = build_native_source_bundle_manifest(
            state_machine=self.state_machine,
            interpreter_package=self.interpreter,
            native_engine_package=self.engine,
            native_runtime_package=self.runtime,
            load_image_contract=self.contract,
        )
        self.bundle_path = root / "native-source-bundle.json"
        _write_json(self.bundle_path, self.bundle)


def _package_build_binding(source_binding: dict[str, object]) -> dict[str, object]:
    manifest = source_binding["manifest"]
    assert isinstance(manifest, dict)
    artifacts = source_binding["artifacts"]
    assert isinstance(artifacts, list)
    return {
        "manifest": manifest["path"],
        "manifest_sha256": manifest["sha256"],
        "artifacts": [
            {key: row[key] for key in ("owner", "role", "path", "sha256")}
            for row in artifacts
        ],
    }


def _build_fixture(
    root: Path, source: _SourceFixture
) -> tuple[Path, dict[str, str], Path]:
    store = root / "nix-store"
    store.mkdir()
    output = store / ("0" * 32 + "-native-source-candidate")
    output.mkdir()
    derivation = store / ("1" * 32 + "-native-source-candidate.drv")
    derivation.write_text("fixture derivation\n", encoding="ascii")

    candidate = output / "candidate.exe"
    payload = output / "payload.exe"
    candidate.write_bytes(pe32_image(b"\xc3"))
    payload.write_bytes(pe32_image(b"\xc3"))
    relocation_payload = {
        "format": PAYLOAD_RELOCATION_INVENTORY_FORMAT,
        "complete": True,
        "payload_sha256": sha256_file(payload),
        "image_base": 0x400000,
        "relocations": [],
    }
    relocation_path = output / "payload-relocations.json"
    _write_json(relocation_path, relocation_payload)

    load = source.bundle["load_image_contract"]
    assert isinstance(load, dict)
    composition_core = {
        "format": PE_COMPOSITION_MANIFEST_FORMAT,
        "status": "composed",
        "acceptance_authority": "none",
        "acceptance": "fixture; independent Stage A proof required",
        "inputs": {
            "load_image_contract": {
                "format": "stage-a-load-image-contract-v1",
                "artifact_sha256": load["canonical_sha256"],
                "contract_sha256": load["contract_sha256"],
                "bound_original_pe_sha256": load["bound_original_pe_sha256"],
            },
            "payload_pe": {"sha256": sha256_file(payload)},
            "payload_relocation_inventory": {
                "format": PAYLOAD_RELOCATION_INVENTORY_FORMAT,
                "sha256": _canonical_sha256(relocation_payload),
                "complete": True,
            },
            "executable_anchor_manifest": {
                "format": "stage-b-pe-executable-anchor-manifest-v1",
                "sha256": "2" * 64,
            },
        },
        "policy": {},
        "outputs": None,
        "qualification": None,
    }
    composition = _closed(composition_core)
    composition_path = output / "composition-manifest.json"
    _write_json(composition_path, composition)

    compiler = root / "compiler"
    assembler = root / "assembler"
    linker = root / "linker"
    nm = root / "nm"
    runtime = root / "libgcc.a"
    for path, content in (
        (compiler, "compiler\n"),
        (assembler, "assembler\n"),
        (linker, "linker\n"),
        (nm, "nm\n"),
        (runtime, "runtime\n"),
    ):
        path.write_text(content, encoding="ascii")
    object_path = output / "interpreter.o"
    object_path.write_bytes(b"object")
    packages = source.bundle["packages"]
    assert isinstance(packages, dict)
    interpreter_artifacts = packages["interpreter"]["artifacts"]
    source_artifact = next(
        row for row in interpreter_artifacts if row["role"] == "interpreter_source"
    )
    runtime_plan = plan_stage_b_native_runtime(
        interpreter_package=source.interpreter,
        native_engine_package=source.engine,
    ).payload()

    def output_binding(path: Path) -> dict[str, object]:
        return {
            "path": path.relative_to(output).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }

    build_core = {
        "format": "stage-b-interpreter-native-build-v1",
        "status": "candidate-generated",
        "acceptance_authority": "none",
        "acceptance": "Stage A whole-program theorem required",
        "inputs": {
            "interpreter_package": _package_build_binding(packages["interpreter"]),
            "native_engine_package": _package_build_binding(packages["native_engine"]),
            "native_runtime_package": _package_build_binding(packages["native_runtime"]),
            "runtime_plan": runtime_plan,
            "load_image_contract": {
                "artifact_sha256": load["artifact_sha256"],
                "contract_sha256": load["contract_sha256"],
                "bound_original_pe_sha256": load["bound_original_pe_sha256"],
            },
            "executable_anchor_manifest": {
                "artifact_sha256": "3" * 64,
                "canonical_sha256": "2" * 64,
            },
        },
        "toolchain": {
            "compiler": str(compiler),
            "compiler_sha256": sha256_file(compiler),
            "compiler_version": "fixture",
            "assembler": str(assembler),
            "assembler_sha256": sha256_file(assembler),
            "linker": str(linker),
            "linker_sha256": sha256_file(linker),
            "linker_version": "fixture",
            "nm": str(nm),
            "nm_sha256": sha256_file(nm),
            "target": "i686-w64-mingw32",
            "compiler_runtime": {
                "path": str(runtime),
                "sha256": sha256_file(runtime),
            },
        },
        "policy": {
            "architecture": "i686-pe32",
            "entry_symbol": "stage_b_payload_entry",
            "image_base": load["preferred_base"],
            "payload_rva": 0x2000,
            "section_alignment": 0x1000,
            "file_alignment": 0x200,
            "freestanding": True,
            "dynamic_base": True,
            "imports": "forbidden-in-payload",
            "unresolved_symbols": "forbidden",
            "base_relocations": "complete-pe32-highlow-inventory-required",
        },
        "objects": [{
            "source": {
                key: source_artifact[key]
                for key in ("owner", "role", "path", "sha256")
            },
            "language": "c",
            "object": object_path.name,
            "object_sha256": sha256_file(object_path),
            "flags": ["-O0"],
        }],
        "commands": {
            "compile_flags_policy": "deterministic-freestanding-proof-o0-v1",
            "link_flags": ["-nostdlib"],
        },
        "outputs": {
            "candidate": output_binding(candidate),
            "payload": output_binding(payload),
            "payload_relocation_inventory": {
                **output_binding(relocation_path),
                "payload_sha256": sha256_file(payload),
                "count": 0,
                "complete": True,
            },
            "composition_manifest": {
                **output_binding(composition_path),
                "manifest_core_sha256": composition["hashes"][
                    "manifest_core_sha256"
                ],
            },
        },
        "qualification": {
            "machine": "i386",
            "bitness": 32,
            "dynamic_base": True,
            "relocations_stripped": False,
            "base_relocations": 0,
            "relocation_inventory_complete": True,
            "payload_imports": 0,
            "unresolved_symbols": [],
            "compiler_materialized_layout_parsed": True,
            "package_closure_revalidated_after_compile": True,
        },
    }
    build = _closed(build_core)
    build_path = output / "interpreter-native-build-manifest.json"
    _write_json(build_path, build)
    provenance = {
        "output": str(output),
        "derivation": str(derivation),
        "registered_deriver": str(derivation),
        "nar_hash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    }
    return build_path, provenance, store


class NativeSourceBundleTests(unittest.TestCase):
    def test_binds_complete_transfer_and_x87_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _SourceFixture(Path(temporary) / "source")
            inventory = fixture.bundle["transfer_inventory"]
            self.assertEqual(inventory["count"], 2)
            self.assertEqual(inventory["x87_transfer_count"], 1)
            self.assertEqual(inventory["x87_replay_count"], 1)
            self.assertEqual(
                validate_native_source_bundle_manifest(fixture.bundle_path),
                fixture.bundle,
            )

    def test_rejects_stale_source_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _SourceFixture(Path(temporary) / "source")
            source = fixture.interpreter / "state-machine-interpreter.c"
            source.write_text(source.read_text(encoding="ascii") + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                NativeSourceEquivalenceError, "artifact SHA-256 mismatch"
            ):
                validate_native_source_bundle_manifest(fixture.bundle_path)

    def test_rejects_corrupted_x87_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _SourceFixture(Path(temporary) / "source")
            corrupted = copy.deepcopy(fixture.bundle)
            corrupted["transfer_inventory"]["x87_replay_count"] = 0
            core = {key: value for key, value in corrupted.items() if key != "hashes"}
            corrupted = _closed(core, "source_bundle_sha256")
            with self.assertRaisesRegex(
                NativeSourceEquivalenceError, "differs from its revalidated"
            ):
                validate_native_source_bundle_manifest(corrupted)


class NativeSourceCompilationAttestationTests(unittest.TestCase):
    def test_builds_and_revalidates_complete_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _SourceFixture(root / "source")
            build, provenance, store = _build_fixture(root, fixture)
            attestation = build_native_source_compilation_attestation(
                source_bundle_manifest=fixture.bundle_path,
                native_build_manifest=build,
                nix_provenance=provenance,
                nix_store_root=store,
            )
            attestation_path = root / "attestation.json"
            _write_json(attestation_path, attestation)
            self.assertEqual(
                attestation["candidate"]["sha256"],
                sha256_file(build.parent / "candidate.exe"),
            )
            self.assertEqual(
                validate_native_source_compilation_attestation(
                    attestation_path, nix_store_root=store
                ),
                attestation,
            )

    def test_rejects_candidate_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _SourceFixture(root / "source")
            build, provenance, store = _build_fixture(root, fixture)
            (build.parent / "candidate.exe").write_bytes(b"not a candidate")
            with self.assertRaisesRegex(
                NativeSourceEquivalenceError, "artifact differs from its binding"
            ):
                build_native_source_compilation_attestation(
                    source_bundle_manifest=fixture.bundle_path,
                    native_build_manifest=build,
                    nix_provenance=provenance,
                    nix_store_root=store,
                )

    def test_rejects_relocation_artifact_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _SourceFixture(root / "source")
            build, provenance, store = _build_fixture(root, fixture)
            relocation = build.parent / "payload-relocations.json"
            relocation.write_text(
                relocation.read_text(encoding="utf-8") + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                NativeSourceEquivalenceError, "artifact differs from its binding"
            ):
                build_native_source_compilation_attestation(
                    source_bundle_manifest=fixture.bundle_path,
                    native_build_manifest=build,
                    nix_provenance=provenance,
                    nix_store_root=store,
                )

    def test_rejects_missing_nix_derivation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _SourceFixture(root / "source")
            build, provenance, store = _build_fixture(root, fixture)
            Path(provenance["derivation"]).unlink()
            with self.assertRaisesRegex(
                NativeSourceEquivalenceError, "Nix derivation is not realized"
            ):
                build_native_source_compilation_attestation(
                    source_bundle_manifest=fixture.bundle_path,
                    native_build_manifest=build,
                    nix_provenance=provenance,
                    nix_store_root=store,
                )

    def test_rejects_stale_tool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _SourceFixture(root / "source")
            build, provenance, store = _build_fixture(root, fixture)
            manifest = json.loads(build.read_text(encoding="utf-8"))
            Path(manifest["toolchain"]["compiler"]).write_text(
                "changed\n", encoding="ascii"
            )
            with self.assertRaisesRegex(
                NativeSourceEquivalenceError, "compiler tool hash mismatch"
            ):
                build_native_source_compilation_attestation(
                    source_bundle_manifest=fixture.bundle_path,
                    native_build_manifest=build,
                    nix_provenance=provenance,
                    nix_store_root=store,
                )


if __name__ == "__main__":
    unittest.main()
