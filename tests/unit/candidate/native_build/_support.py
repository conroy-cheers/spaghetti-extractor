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

from spaghetti_extractor.roundtrip_fuzz.image_io import (
    write_spx_load_image_contract,
)
from spaghetti_extractor.authority_inputs.machine_ir_authority import (
    build_machine_ir_authority_bindings,
)
from spaghetti_extractor.authority._schema import stable_id
from spaghetti_extractor.authority.final_authority import (
    FINAL_AUTHORITY_ARTIFACT_KIND_V3,
    FINAL_AUTHORITY_CODEC_V3,
    FINAL_AUTHORITY_SCOPE_V3,
    AuthorityFamilyBindingV3,
    FinalAuthorityRecordV3,
)
from spaghetti_extractor.authority.external_site_records import (
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
)
from spaghetti_extractor.artifacts.artifact_set import (
    ArtifactBindingV3,
    ArtifactSetWriterV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
)
from spaghetti_extractor.candidate.interpreter import (
    write_spx_interpreter_package,
)
from spaghetti_extractor.candidate.build import (
    INTERPRETER_NATIVE_BUILD_FORMAT,
    INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME,
    CandidateNativeBuildError,
    assemble_spx_interpreter_native_objects,
    build_spx_interpreter_native_candidate,
    compile_spx_interpreter_native_object,
    compile_spx_interpreter_native_source_bundle,
    prepare_spx_interpreter_native_object_graph,
)
from spaghetti_extractor.candidate.engine import write_spx_native_engine_package
from spaghetti_extractor.candidate.runtime import (
    CandidateRuntimeError,
    write_spx_native_runtime_package,
)
from spaghetti_extractor.candidate.pe import (
    EXECUTABLE_ANCHOR_MANIFEST_FORMAT,
)
from spaghetti_extractor.candidate.authority import (
    build_candidate_authority,
)
from spaghetti_extractor.machine_ir.coverage import (
    FALLBACK_COVERAGE_RECEIPT_FORMAT,
)
from spaghetti_extractor.components.formats import (
    COMPONENT_RUNTIME_COMPLETION_V3_FORMAT,
    COMPONENT_RUNTIME_PACKAGE_V3_FORMAT,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file
from tests.unit.candidate.native_engine._support import (
    _candidate_execution_artifacts,
)


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




def _transfer(rva: int = 0x1000) -> dict[str, Any]:
    return {
        "format": "spaghetti-extractor-machine-ir-v2",
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
    component_runtime_package: Path
    load_image_contract: Path


class _Packages:
    def __init__(
        self,
        root: Path,
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
        self.canonical_external_sites = root / "canonical-external-sites"
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
            "format": "spaghetti-extractor-machine-ir-v2",
            "status": "qualified",
            "inputs": {"original_pe": {"sha256": original_sha256}},
            "binary": {"sha256": original_sha256},
            "counts": {"units": 1},
            "artifacts": {
                "machine_ir": {
                    "format": "spaghetti-extractor-machine-ir-v2",
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
        })
        _write_json(self.profile, {
            "format": "spaghetti-extractor-static-machine-import-profile-v1",
            "id": "test-static-runtime-v1",
            "includes": [],
            "machine_import_signatures": [],
        })
        write_spx_interpreter_package(
            machine_ir=self.machine_ir, out=self.interpreter
        )
        ArtifactSetWriterV3(
            artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
            bindings=(),
        ).write(self.canonical_external_sites, [])
        execution_authority = _candidate_execution_artifacts(
            root, units=[unit]
        )
        write_spx_native_engine_package(
            machine_ir=self.machine_ir,
            machine_ir_manifest=self.machine_ir_manifest,
            entry_rva=0x1000,
            canonical_external_sites=self.canonical_external_sites,
            root_closure=execution_authority[0],
            target_certificates=execution_authority[1],
            parametric_summaries=execution_authority[2],
            out=self.engine,
        )
        write_spx_native_runtime_package(
            interpreter_package=self.interpreter,
            native_engine_package=self.engine,
            external_profile=self.profile,
            out=self.runtime,
        )

        contract = write_spx_load_image_contract(
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
            "dispatch_lookup": "spx_program_lookup",
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
                "portable_replacements": {
                    "artifact": {
                        "path": "portable-component-selection.json",
                        "sha256": "0" * 64,
                    }
                },
            },
            "counts": {
                "structural_units": 1,
                "implementation_entries": 1,
                "machine_ir_fallback": 1,
                "portable_replacement": 0,
                "portable_component_member": 0,
                "blockers": 0,
            },
            "entries": [fallback_entry],
            "blockers": [],
        }
        self.component_runtime = self.root / "component-runtime"
        self.component_runtime.mkdir()
        selection = self.component_runtime / "portable-component-selection.json"
        _write_json(selection, {"format": "fixture-selection", "entries": []})
        selection_sha256 = sha256_file(selection)
        fallback_body["inputs"]["portable_replacements"]["artifact"]["sha256"] = selection_sha256
        runtime_core = {
            "format": COMPONENT_RUNTIME_PACKAGE_V3_FORMAT,
            "status": "ready",
            "executes_original_binary": False,
            "bindings": {"machine_ir_sha256": machine_ir_sha256},
            "policy": {
                "runtime_package_is_sole_candidate_authority": True,
                "enabled_components_must_have_checked_activation_authority": True,
                "subsumed_members_may_not_fallback": True,
                "fallback_on_unimplemented": False,
                "original_execution_forbidden": True,
            },
            "components": [],
            "counts": {"portable_components": 0, "portable_units": 0, "override_entries": 0},
            "artifacts": {
                "portable_selection": {"path": selection.name, "sha256": selection_sha256},
                "region_overrides": None,
            },
        }
        runtime_sha256 = _canonical_sha256(runtime_core)
        _write_json(
            self.component_runtime / "component-runtime-package.json",
            {**runtime_core, "runtime_package_sha256": runtime_sha256},
        )
        completion_core = {
            "format": COMPONENT_RUNTIME_COMPLETION_V3_FORMAT,
            "status": "complete",
            "runtime_package_sha256": runtime_sha256,
            "activation_plan_sha256": "0" * 64,
            "structural_units": 1,
            "portable_units": 0,
            "fallback_units": 1,
            "ownership_complete": True,
            "ownership_exclusive": True,
            "executes_original_binary": False,
        }
        _write_json(
            self.component_runtime / "component-runtime-completion.json",
            {**completion_core, "completion_sha256": _canonical_sha256(completion_core)},
        )
        _write_json(
            self.fallback_receipt,
            {
                **fallback_body,
                "receipt_sha256": _canonical_sha256(fallback_body),
            },
        )
        candidate_authority = build_candidate_authority(
            final_authority=self.final_authority,
            machine_ir=self.machine_ir,
            machine_ir_manifest=self.machine_ir_manifest,
            fallback_coverage_receipt=self.fallback_receipt,
            component_runtime_package=self.component_runtime,
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
            "component_runtime_package": self.component_runtime,
            "load_image_contract": self.contract,
        }


__all__ = tuple(name for name in globals() if not name.startswith("__"))
