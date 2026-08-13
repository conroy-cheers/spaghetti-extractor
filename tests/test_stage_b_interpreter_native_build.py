from __future__ import annotations

import json
import hashlib
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any, TypedDict

import pefile

from tests.pe_fixtures import pe32_image

from spaghetti_extractor.roundtrip_fuzz.image_contract import (
    write_stage_a_load_image_contract,
)
from spaghetti_extractor.hybrid_authority_builder_v2 import (
    build_machine_ir_authority_bindings,
)
from spaghetti_extractor.analysis_v3._schema import stable_id
from spaghetti_extractor.analysis_v3.final_authority import (
    FINAL_AUTHORITY_ARTIFACT_KIND_V3,
    FINAL_AUTHORITY_CODEC_V3,
    FINAL_AUTHORITY_SCOPE_V3,
    AuthorityFamilyBindingV3,
    FinalAuthorityRecordV3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactSetWriterV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
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
    _machine_ir_internal_call_preservation,
    write_stage_b_native_engine_package,
)
from spaghetti_extractor.stage_b_native_runtime import (
    write_stage_b_native_runtime_package,
)
from spaghetti_extractor.stage_b_pe_composer import (
    EXECUTABLE_ANCHOR_MANIFEST_FORMAT,
)
from spaghetti_extractor.stage_b_candidate_authority_v3 import (
    build_stage_b_candidate_authority_v3,
)
from spaghetti_extractor.stage_b_candidate_modes import (
    STATIC_CLOSED_CANDIDATE_MODE,
    STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
)
from spaghetti_extractor.stage_b_fallback_coverage import (
    FALLBACK_COVERAGE_RECEIPT_FORMAT,
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
    return canonical_sha256_v3(value)


def _expanded_header_pe() -> bytes:
    source = bytearray(pe32_image(b"\x90" * 8 + b"\xc3"))
    source[0x200:0x200] = bytes(0x200)
    struct.pack_into("<I", source, OPTIONAL_OFFSET + 60, 0x400)
    struct.pack_into("<I", source, SECTION_TABLE_OFFSET + 20, 0x400)
    return bytes(source)


def _refresh_source_binding(manifest_path: Path, source_path: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    matches = [
        row
        for row in manifest["sources"]
        if row.get("path") == source_path.name
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one source binding for {source_path.name}")
    matches[0]["sha256"] = sha256_file(source_path)
    _write_json(manifest_path, manifest)


class StageBNativeSummarySelectionTests(unittest.TestCase):
    def test_complete_rows_survive_unrelated_global_incompleteness(self) -> None:
        payload = {
            "control": {
                "internal_call_preservation": {
                    "format": "stage-a-internal-call-preservation-v1",
                    "status": "incomplete",
                    "fixed_point_complete": False,
                    "summaries": [
                        {
                            "status": "complete",
                            "target_rva": 0x1000,
                            "preserved_registers": ["ebx", "esi"],
                        },
                        {
                            "status": "incomplete",
                            "target_rva": 0x2000,
                            "preserved_registers": [],
                        },
                    ],
                }
            }
        }

        self.assertEqual(
            _machine_ir_internal_call_preservation(payload),
            {0x1000: frozenset({"ebx", "esi"})},
        )


def _transfer(rva: int = 0x1000) -> dict[str, Any]:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": f"semantic-transfer:{rva:08x}",
        "status": "qualified",
        "reachable": True,
        "reachability": "reachable",
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 1, "size": 1},
            "contract_sha256": "a" * 64,
            "instruction_bytes_sha256": "b" * 64,
            "semantic_export": None,
        },
        "instructions": [{
            "rva_start": rva,
            "rva_end": rva + 1,
            "size": 1,
            "instruction_sha256": sha256_bytes(b"ret"),
            "mnemonic": "ret",
            "operands": [],
            "registers_read": ["esp"],
            "registers_written": ["esp", "eip"],
            "groups": ["ret"],
        }],
        "x87_micro_ops": [],
        "control": {
            "kind": "return",
            "direct_targets": [],
            "has_indirect_target": False,
        },
        "semantics": {
            "pre_state": {},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {
                "kind": "return",
                "value": {"op": "reg", "name": "eax", "width": 32},
            },
            "stack_delta": 4,
            "counts": {"instructions": 1},
            "fpu_state": None,
            "instruction_effect_schedule": None,
        },
    }


class _ReleaseInputs(TypedDict):
    candidate_authority: Path
    final_authority: Path
    machine_ir: Path
    machine_ir_manifest: Path
    fallback_coverage_receipt: Path
    load_image_contract: Path


class _Packages:
    def __init__(
        self,
        root: Path,
        *,
        candidate_mode: str = STATIC_CLOSED_CANDIDATE_MODE,
    ) -> None:
        self.root = root
        self.interpreter = root / "interpreter"
        self.engine = root / "engine"
        self.runtime = root / "runtime"
        self.original = root / "original.exe"
        self.contract = root / "load-image-contract.json"
        self.anchors = root / "anchors.json"
        self.machine_ir = root / "machine-ir.jsonl"
        self.machine_ir_manifest = root / "machine-ir-manifest.json"
        self.profile = root / "profile.json"
        self.final_authority = root / "final-authority-v3"
        self.fallback_receipt = root / "fallback-coverage-receipt.json"
        self.candidate_authority = root / "candidate-authority-v3.json"
        root.mkdir(parents=True)

        unit = _transfer()
        self.machine_ir.write_text(
            json.dumps(_transfer(), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        self.original.write_bytes(_expanded_header_pe())
        original_sha256 = sha256_file(self.original)
        machine_ir_sha256 = sha256_file(self.machine_ir)
        _write_json(self.machine_ir_manifest, {
            "format": "stage-a-machine-ir-v2",
            "status": "qualified",
            "inputs": {"original_pe": {"sha256": original_sha256}},
            "binary": {"sha256": original_sha256},
            "counts": {"units": 1},
            "artifacts": {
                "machine_ir": {
                    "format": "stage-a-machine-ir-v2",
                    "path": self.machine_ir.name,
                    "sha256": machine_ir_sha256,
                }
            },
            "authority_bindings": build_machine_ir_authority_bindings(
                [unit], pe_sha256=original_sha256
            ),
            "coverage": {"counts": {"unknown_bytes": 0}},
            "issues": [],
            "external": {"events": []},
            "control": {
                "reachability": {
                    "status": "complete",
                    "roots": [unit["id"]],
                    "reachable_units": [unit["id"]],
                    "potential_units": [],
                    "confirmed_unreachable_units": [],
                    "frontiers": [],
                },
                "callback_cutpoint_proposals": [],
                "internal_call_preservation": {
                    "format": "stage-a-internal-call-preservation-v1",
                    "status": "complete",
                    "fixed_point_complete": True,
                    "summaries": [{
                        "status": "complete",
                        "target_unit_id": unit["id"],
                        "target_rva": 0x1000,
                        "root_kind": "behavioral_root",
                        "return_behavior": {
                            "status": "complete",
                            "may_return": True,
                            "may_not_return": False,
                        },
                        "return_nodes": 1,
                        "return_unit_ids": [unit["id"]],
                        "reached_units": 1,
                        "stack_cleanup": {
                            "status": "complete",
                            "stack_delta": 0,
                            "return_stack_offset": 4,
                        },
                        "preserved_registers": [],
                        "blocker_codes": [],
                    }],
                },
                "external_interface_provenance": {
                    "format": "stage-a-external-interface-provenance-v1",
                    "status": "complete",
                    "resolutions": [],
                    "issues": [],
                    "callback_registrations": [],
                },
            },
        })
        _write_json(self.profile, {
            "format": "stage-a-static-machine-import-profile-v1",
            "id": "test-static-runtime-v1",
            "includes": [],
            "machine_import_signatures": [],
        })
        write_stage_b_interpreter_package(
            machine_ir=self.machine_ir, out=self.interpreter
        )
        write_stage_b_native_engine_package(
            machine_ir=self.machine_ir,
            machine_ir_manifest=self.machine_ir_manifest,
            entry_rva=0x1000,
            candidate_mode=candidate_mode,
            out=self.engine,
        )
        write_stage_b_native_runtime_package(
            interpreter_package=self.interpreter,
            native_engine_package=self.engine,
            external_profile=self.profile,
            out=self.runtime,
        )

        contract = write_stage_a_load_image_contract(
            original_pe=self.original, out=self.contract
        )
        family_names = (
            "callbacks",
            "exceptional_transitions",
            "external_sites",
            "fallback_coverage",
            "inductive_authority",
            "isa_qualification",
            "root_closure",
            "semantic_index",
        )
        families = tuple(
            AuthorityFamilyBindingV3(
                input_name=name,
                artifact_kind=f"{name}-v3",
                artifact_id=(
                    "artifact-set-v3:"
                    + hashlib.sha256(name.encode("ascii")).hexdigest()
                ),
                manifest_sha256=hashlib.sha256(
                    f"manifest:{name}".encode("ascii")
                ).hexdigest(),
                record_count=1,
                record_inventory_sha256=hashlib.sha256(
                    f"inventory:{name}".encode("ascii")
                ).hexdigest(),
            )
            for name in family_names
        )
        unit_id = str(unit["id"])
        unit_ir_sha256 = _canonical_sha256(unit)
        inventory_sha256 = canonical_sha256_v3([unit_id])
        universe_sha256 = canonical_sha256_v3(
            {
                "pe_sha256": original_sha256,
                "units": [
                    {"id": unit_id, "unit_ir_sha256": unit_ir_sha256}
                ],
            }
        )
        identity = {
            "scope": FINAL_AUTHORITY_SCOPE_V3,
            "families": [row.to_payload() for row in families],
            "exact_unit_count": 1,
            "exact_unit_inventory_sha256": inventory_sha256,
        }
        final = FinalAuthorityRecordV3(
            record_id=stable_id("final-authority-v3", identity),
            scope=FINAL_AUTHORITY_SCOPE_V3,
            status="complete",
            authorizing=True,
            pe_sha256=original_sha256,
            exact_universe_sha256=universe_sha256,
            exact_unit_count=1,
            exact_unit_inventory_sha256=inventory_sha256,
            families=families,
            primary_blocker=None,
            dependencies=(),
        )
        ArtifactSetWriterV3(
            artifact_kind=FINAL_AUTHORITY_ARTIFACT_KIND_V3,
            bindings=(
                ArtifactBindingV3(
                    "binary", "pe32", "original.exe", original_sha256
                ),
            ),
            status="complete",
        ).write(
            self.final_authority,
            (FINAL_AUTHORITY_CODEC_V3.write(final.record_id, final),),
        )
        fallback_entry_core = {
            "unit_id": unit["id"],
            "rva": 0x1000,
            "unit_contract_sha256": unit["source"]["contract_sha256"],
            "source_span_sha256": unit["source"][
                "instruction_bytes_sha256"
            ],
            "machine_ir_record_sha256": _canonical_sha256(unit),
            "lowering_transfer_sha256": hashlib.sha256(b"lowering").hexdigest(),
            "implementation_kind": "machine_ir_fallback",
            "dispatch_lookup": "stage_b_program_lookup",
            "portable_replacement": None,
        }
        fallback_entry = {
            **fallback_entry_core,
            "entry_sha256": _canonical_sha256(fallback_entry_core),
        }
        fallback_body = {
            "format": FALLBACK_COVERAGE_RECEIPT_FORMAT,
            "status": "complete",
            "authority": "implementation coverage only",
            "checker": {"id": "native-build-fixture", "version": 2},
            "schemas": {},
            "policy": {
                "potential_transfers_may_be_deferred": False,
                "structural_units_require_lowering": True,
                "one_implementation_kind_per_structural_unit": True,
                "rooted_containment_authority": False,
                "portable_replacements_must_be_explicit": True,
                "portable_fallback_on_unimplemented": False,
                "candidate_generation_fails_closed": True,
            },
            "inputs": {
                "machine_ir": {"sha256": machine_ir_sha256},
                "machine_ir_manifest": {
                    "sha256": sha256_file(self.machine_ir_manifest)
                },
            },
            "counts": {
                "structural_units": 1,
                "implementation_entries": 1,
                "machine_ir_fallback": 1,
                "portable_replacement": 0,
                "blockers": 0,
            },
            "entries": [fallback_entry],
            "blockers": [],
        }
        _write_json(
            self.fallback_receipt,
            {
                **fallback_body,
                "receipt_sha256": _canonical_sha256(fallback_body),
            },
        )
        candidate_authority = build_stage_b_candidate_authority_v3(
            final_authority=self.final_authority,
            machine_ir=self.machine_ir,
            machine_ir_manifest=self.machine_ir_manifest,
            fallback_coverage_receipt=self.fallback_receipt,
        )
        if not candidate_authority.authorizes:
            raise AssertionError(candidate_authority.to_payload())
        self.candidate_authority.write_text(
            candidate_authority.to_json(), encoding="ascii"
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

    def release_inputs(self) -> _ReleaseInputs:
        return {
            "candidate_authority": self.candidate_authority,
            "final_authority": self.final_authority,
            "machine_ir": self.machine_ir,
            "machine_ir_manifest": self.machine_ir_manifest,
            "fallback_coverage_receipt": self.fallback_receipt,
            "load_image_contract": self.contract,
        }


class StageBInterpreterNativeBuildValidationTests(unittest.TestCase):
    def test_structural_mode_requires_failure_trap_before_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            packages = _Packages(
                Path(temporary) / "inputs",
                candidate_mode=STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
            )
            with self.assertRaisesRegex(
                StageBInterpreterNativeBuildError, "require the failure trap"
            ):
                build_stage_b_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    candidate_authority=None,
                    final_authority=None,
                    machine_ir=packages.machine_ir,
                    machine_ir_manifest=packages.machine_ir_manifest,
                    fallback_coverage_receipt=None,
                    load_image_contract=packages.contract,
                    candidate_mode=STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
                    out_dir=Path(temporary) / "candidate",
                    compiler="compiler-must-not-be-consulted",
                )

    def test_structural_mode_rejects_acceptance_authority_before_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            packages = _Packages(
                Path(temporary) / "inputs",
                candidate_mode=STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
            )
            with self.assertRaisesRegex(
                StageBInterpreterNativeBuildError,
                "must not consume acceptance authority",
            ):
                build_stage_b_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    **packages.release_inputs(),
                    candidate_mode=STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
                    diagnostic_failure_trap=True,
                    out_dir=Path(temporary) / "candidate",
                    compiler="compiler-must-not-be-consulted",
                )

    def test_rejects_v1_receipt_before_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            packages = _Packages(Path(temporary) / "inputs")
            packages.candidate_authority.write_bytes(
                canonical_json_bytes_v3(
                    {
                        "format": "stage-b-static-hybrid-closure-receipt-v1",
                        "status": "complete",
                        "authorizes": True,
                    }
                )
            )

            with self.assertRaisesRegex(
                StageBInterpreterNativeBuildError, "candidate receipt"
            ):
                build_stage_b_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    **packages.release_inputs(),
                    out_dir=Path(temporary) / "candidate",
                    compiler="compiler-must-not-be-consulted",
                )

    def test_rejects_stale_fallback_receipt_before_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            packages = _Packages(Path(temporary) / "inputs")
            fallback = json.loads(
                packages.fallback_receipt.read_text(encoding="utf-8")
            )
            fallback["authority"] = "stale-after-candidate-authorization"
            fallback_body = {
                key: value
                for key, value in fallback.items()
                if key != "receipt_sha256"
            }
            fallback["receipt_sha256"] = _canonical_sha256(fallback_body)
            _write_json(packages.fallback_receipt, fallback)

            with self.assertRaisesRegex(
                StageBInterpreterNativeBuildError, "stale|different inputs"
            ):
                build_stage_b_interpreter_native_candidate(
                    interpreter_package=packages.interpreter,
                    native_engine_package=packages.engine,
                    native_runtime_package=packages.runtime,
                    **packages.release_inputs(),
                    out_dir=Path(temporary) / "candidate",
                    compiler="compiler-must-not-be-consulted",
                )

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
                    **packages.release_inputs(),
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
                    **packages.release_inputs(),
                    anchor_manifest=packages.anchors,
                    out_dir=Path(temporary) / "candidate",
                    compiler="compiler-must-not-be-consulted",
                )


@unittest.skipUnless(
    shutil.which("i686-w64-mingw32-gcc"), "i686 MinGW compiler unavailable"
)
class StageBInterpreterNativeBuildIntegrationTests(unittest.TestCase):
    def test_builds_non_authorizing_structural_diagnostic_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(
                root / "inputs",
                candidate_mode=STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
            )
            manifest = build_stage_b_interpreter_native_candidate(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                candidate_authority=None,
                final_authority=None,
                machine_ir=packages.machine_ir,
                machine_ir_manifest=packages.machine_ir_manifest,
                fallback_coverage_receipt=None,
                load_image_contract=packages.contract,
                candidate_mode=STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
                diagnostic_failure_trap=True,
                out_dir=root / "candidate",
            )

            self.assertIsNone(manifest["inputs"]["candidate_authority"])
            scope = manifest["inputs"]["execution_scope"]
            self.assertEqual(scope["candidate_mode"], "structural-diagnostic")
            self.assertEqual(scope["acceptance_authority"], "none")
            self.assertEqual(
                scope["runtime_unknown_target_disposition"],
                "fail-closed-as-unimplemented",
            )
            self.assertEqual(
                manifest["policy"]["candidate_class"],
                "structural-diagnostic",
            )
            self.assertTrue(manifest["policy"]["diagnostic_failure_trap"])
            self.assertTrue((root / "candidate" / "candidate.exe").is_file())

    def test_compile_keys_track_only_transitive_source_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            baseline = prepare_stage_b_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                out_dir=root / "baseline-graph",
            )
            runtime_source = packages.runtime / "native-runtime.c"
            runtime_source.write_text(
                runtime_source.read_text(encoding="ascii") + "\n",
                encoding="ascii",
            )
            _refresh_source_binding(
                packages.runtime / "native-runtime-package.json", runtime_source
            )
            changed = prepare_stage_b_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                out_dir=root / "changed-graph",
            )

            baseline_keys = {
                row["id"]: row["compile_key_sha256"] for row in baseline["units"]
            }
            changed_keys = {
                row["id"]: row["compile_key_sha256"] for row in changed["units"]
            }
            changed_ids = {
                unit_id
                for unit_id in baseline_keys
                if baseline_keys[unit_id] != changed_keys[unit_id]
            }
            self.assertEqual(changed_ids, {"native_runtime-native_runtime_source"})

    def test_diagnostic_mode_invalidates_only_macro_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            normal = prepare_stage_b_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                out_dir=root / "normal-graph",
            )
            diagnostic = prepare_stage_b_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                diagnostic_failure_trap=True,
                out_dir=root / "diagnostic-graph",
            )

            normal_rows = {row["id"]: row for row in normal["units"]}
            diagnostic_rows = {row["id"]: row for row in diagnostic["units"]}
            changed_ids = {
                unit_id
                for unit_id, row in normal_rows.items()
                if row["compile_key_sha256"]
                != diagnostic_rows[unit_id]["compile_key_sha256"]
            }
            sensitive_ids = {
                row["id"] for row in diagnostic["units"] if row["diagnostic_sensitive"]
            }
            self.assertEqual(changed_ids, sensitive_ids)
            self.assertTrue(sensitive_ids)
            self.assertLess(len(sensitive_ids), len(diagnostic["units"]))

    def test_compile_graph_records_exact_quoted_include_closures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            graph = prepare_stage_b_interpreter_native_object_graph(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                out_dir=root / "graph",
            )
            rows = {row["id"]: row for row in graph["units"]}
            interpreter_headers = {
                item["path"]
                for item in rows["interpreter-interpreter_source"]["dependencies"]
            }
            self.assertEqual(
                interpreter_headers,
                {
                    "state-machine-interpreter-internal.h",
                    "state-machine-interpreter.h",
                    "state-machine-runtime.h",
                },
            )
            runtime_headers = {
                (item["owner"], item["path"])
                for item in rows["native_runtime-native_runtime_source"][
                    "dependencies"
                ]
            }
            self.assertEqual(
                runtime_headers,
                {
                    ("native_runtime", "native-runtime.h"),
                    ("interpreter", "state-machine-interpreter.h"),
                    ("interpreter", "state-machine-runtime.h"),
                },
            )

    def test_builds_content_bound_relocatable_candidate_and_linker_map(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = _Packages(root / "inputs")
            manifest = build_stage_b_interpreter_native_candidate(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                **packages.release_inputs(),
                out_dir=root / "candidate",
            )
            repeated = build_stage_b_interpreter_native_candidate(
                interpreter_package=packages.interpreter,
                native_engine_package=packages.engine,
                native_runtime_package=packages.runtime,
                **packages.release_inputs(),
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
                **packages.release_inputs(),
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
            self.assertEqual(
                manifest["inputs"]["candidate_authority"]["format"],
                "spaghetti-extractor-stage-b-candidate-authority-receipt-v3",
            )
            self.assertTrue(
                manifest["inputs"]["candidate_authority"]["authorizes"]
            )
            self.assertEqual(
                manifest["inputs"]["candidate_authority"][
                    "machine_ir_sha256"
                ],
                sha256_file(packages.machine_ir),
            )
            self.assertEqual(
                manifest["inputs"]["candidate_authority"][
                    "fallback_coverage_receipt_sha256"
                ],
                sha256_file(packages.fallback_receipt),
            )
            self.assertEqual(manifest["qualification"]["payload_imports"], 0)
            self.assertFalse(manifest["qualification"]["dynamic_base"])
            self.assertTrue(manifest["qualification"]["relocations_stripped"])
            self.assertTrue(
                manifest["qualification"]["relocation_inventory_complete"]
            )
            self.assertEqual(manifest["qualification"]["base_relocations"], 0)
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

            candidate: Any = pefile.PE(str(output / "candidate.exe"))
            self.assertTrue(int(candidate.FILE_HEADER.Characteristics) & 0x0001)
            self.assertFalse(int(candidate.OPTIONAL_HEADER.DllCharacteristics) & 0x0040)
            self.assertEqual(int(candidate.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size), 0)
            candidate.close()

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
                    **packages.release_inputs(),
                    precompiled_objects=object_package,
                    out_dir=root / "candidate-tampered-cache",
                )


if __name__ == "__main__":
    unittest.main()
