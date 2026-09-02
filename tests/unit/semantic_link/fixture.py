"""Reusable checked semantic-link fixture construction."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

from tests.pe_fixtures import pe32_image_with_writable_data, pe32_import_image

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.project import write_pe32_module_interface
from spaghetti_extractor.external.resolved import bind_launch_policy_v1
from spaghetti_extractor.pe32.behavioral_roots import generate_behavioral_roots
from spaghetti_extractor.semantic_objects.object_authority import (
    derive_pe32_machine_object_authority_v2,
)
from spaghetti_extractor.roundtrip_fuzz.image_io import (
    write_spx_load_image_contract,
)
from spaghetti_extractor.semantic_link.module import (
    _semantic_link_kernel_input_v1,
    build_semantic_link_worklist_facts,
)
from spaghetti_extractor.semantic_objects.semantic_object import (
    SemanticObjectV1,
    write_semantic_object_v1,
)
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit,
    transfer_row,
    write_fixture_transfer_plan,
)
from spaghetti_extractor.transfer.closure import (
    _native_semantic_link_kernel_v1,
    build_module_execution_closure_v1,
    check_python_reference_closure_parity_v1,
    derive_execution_closure_context_v1,
)
from spaghetti_extractor.util import json_dumps, sha256_file, write_json


class SemanticLinkFixture:
    def linked_facts(
        self, root: Path, *, environment_blockers: tuple[dict[str, object], ...] = (),
        with_edge: bool = False, native_provenance: bool = False,
        corrupt_native_facts: bool = False,
        corrupt_native_effects: bool = False,
        corrupt_native_objects: bool = False,
        corrupt_native_references: bool = False,
        corrupt_runtime_dependencies: bool = False,
        corrupt_transfer_relocations: bool = False,
        corrupt_external_declaration: bool = False,
        extra_checked_external: bool = False,
        aliased_root: bool = False,
    ) -> dict[str, object]:
        original = root / "fixture.exe"
        original.write_bytes(
            pe32_import_image(
                b"\x40\x40\xc3", symbol="GetProcAddress",
                dll="KERNEL32.dll",
            )
            if corrupt_external_declaration
            else pe32_image_with_writable_data(
                b"\x40\x40\xc3", relocation_offsets=[]
            )
        )
        write_json(
            root / "behavioral-roots.json",
            generate_behavioral_roots(original),
        )
        contract = root / "load-image-contract.json"
        write_spx_load_image_contract(original_pe=original, out=contract)
        interface_root = root / "interface"
        write_pe32_module_interface(
            image_id="fixture.exe",
            original_pe=original,
            load_image_contract=contract,
            out=interface_root,
        )
        interface_path = interface_root / "module-interface.json"
        interface = json.loads(interface_path.read_text(encoding="utf-8"))

        machine_ir = root / "machine-ir.jsonl"
        first = transfer_row()
        if corrupt_external_declaration:
            call = {
                "family": "external",
                "kind": "external_call",
                "instruction_rva": 0x1000,
                "target_rva": 0,
                "return_rva": 0x1003,
                "dll": "kernel32.dll",
                "symbol": "GetProcAddress",
                "ordinal": None,
                "register_inputs": {
                    name: {"op": "reg", "name": name, "width": 32}
                    for name in (
                        "eax", "ebx", "ecx", "edx",
                        "esi", "edi", "ebp", "esp",
                    )
                },
                "flag_inputs": {
                    name: {"op": "flag", "name": name}
                    for name in ("cf", "zf", "sf", "of", "pf", "df")
                },
                "arguments": [],
                "stack_inputs": [],
            }
            first["external_events"] = [call]
            first["ordered_events"] = [call]
        rows = [first]
        if with_edge:
            target = transfer_row()
            target["id"] = "semantic-transfer:target"
            target["original"] = {
                "rva_start": 0x1003, "rva_end": 0x1004, "size": 1,
            }
            target["outcome"] = {
                "kind": "return",
                "value": {"op": "const", "value": 0, "width": 32},
            }
            rows.append(target)
        machine_ir.write_text(
            "".join(
                json_dumps(as_machine_ir_unit(row)) + "\n" for row in rows
            ),
            encoding="utf-8",
        )
        transfer_path = write_fixture_transfer_plan(
            machine_ir, pe_sha256=sha256_file(original)
        )
        authority = derive_pe32_machine_object_authority_v2(
            module_interface=interface,
            module_interface_sha256=sha256_file(interface_path),
        )
        authority_payload = authority.to_payload()
        authority_path = root / "machine-object-authority.json"
        write_json(authority_path, authority_payload)
        machine_import_contracts: list[dict[str, object]] = []
        original_semantic_imports: list[dict[str, object]] = []
        if corrupt_external_declaration:
            contract_row: dict[str, object] = {
                "dll": "kernel32.dll",
                "identity": {
                    "dll": "kernel32.dll",
                    "symbol": "GetProcAddress",
                    "ordinal": None,
                },
                "import_kind": "ordinary",
                "cell_index": 0,
                "iat_rva": interface["imports"][0]["iat_rva"],
                "boundary": {
                    "schema": {"schema_sha256": "1" * 64},
                    "physical_call_frame_v3": {"id": "fixture-frame"},
                },
                "contract": {"payload": {}},
            }
            machine_import_contracts.append(contract_row)
            original_semantic_imports.append(contract_row)
            if extra_checked_external:
                unused_contract: dict[str, object] = {
                    "dll": "kernel32.dll",
                    "identity": {
                        "dll": "kernel32.dll",
                        "symbol": "TlsGetValue",
                        "ordinal": None,
                    },
                    "import_kind": "ordinary",
                    "cell_index": 1,
                    "iat_rva": interface["imports"][0]["iat_rva"] + 4,
                    "boundary": {
                        "schema": {"schema_sha256": "2" * 64},
                        "physical_call_frame_v3": {
                            "id": "fixture-unused-frame",
                            "transport": {"outcomes": ["normal"]},
                        },
                    },
                    "contract": {"payload": {}},
                }
                machine_import_contracts.append(unused_contract)
                original_semantic_imports.append(unused_contract)
        environment_core = {
            "format": "spaghetti-extractor-resolved-external-environment-v1",
            "status": "incomplete" if environment_blockers else "complete",
            "bindings": {
                "module_interface_sha256": interface["interface_sha256"],
                "module_pe_sha256": interface["identity"]["pe_sha256"],
                "environment_intent_sha256": "1" * 64,
                "runtime_profile_pack_sha256s": ["2" * 64],
                "interface_profile_pack_sha256s": [],
            },
            "target": {
                "abi": "pe32-i686-mingw32",
                "data_layout": "pe32-ilp32-v1",
            },
            "launch_policy": bind_launch_policy_v1(
                {
                    "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
                    "schema_version": 1,
                },
                source_sha256="0" * 64,
                filename="fixture-launch.json",
            ),
            "canonical_boundaries": [],
            "interface_method_catalogs": [],
            "machine_import_contracts": machine_import_contracts,
            "original_semantic_imports": original_semantic_imports,
            "generated_runtime_support_imports": [],
            "loader_service_contracts": [],
            "static_authority_bindings": [],
            "checked_exception_protocols": [],
            "blockers": list(environment_blockers),
            "authority": (
                "none" if environment_blockers else "checked_static_environment"
            ),
        }
        environment = {
            **environment_core,
            "resolved_environment_sha256": canonical_sha256_v3(environment_core),
        }
        environment_path = root / "resolved-external-environment.json"
        write_json(environment_path, environment)
        semantic_path = root / "semantic-object.json"
        write_semantic_object_v1(
            transfer_plan=transfer_path,
            module_interface=interface_path,
            machine_object_authority=authority_path,
            resolved_external_environment=environment_path,
            out=semantic_path,
        )
        semantic = SemanticObjectV1.load(semantic_path)
        if aliased_root:
            semantic_payload = copy.deepcopy(semantic.payload)
            alias = copy.deepcopy(semantic_payload["roots"][0])
            alias.update({
                "root_id": "export:ordinal:2",
                "kind": "export",
                "export_names": ["FixtureAlias"],
                "ordinal": 2,
            })
            semantic_payload["roots"].append(alias)
            semantic_payload["roots"].sort(key=lambda row: row["root_id"])
            semantic = replace(semantic, payload=semantic_payload)
        transfer_payload = semantic.transfer_plan
        context = derive_execution_closure_context_v1(
            transfer_payload=transfer_payload,
            behavioral_roots=root / "behavioral-roots.json",
            original_pe=original,
            module_interface=interface_path,
            object_authority=authority_path,
            resolved_external_environment=environment_path,
        )
        diagnostic_edge_roots: dict[tuple[int, int, str], set[int]] = {}
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256=semantic.payload["members"]["transfer_plan"][
                "content_sha256"
            ],
            transfers=semantic.transfers,
            context=context,
            diagnostic_edge_roots=diagnostic_edge_roots,
        )
        edge_root_provenance = [
            {
                "source_rva": source_rva,
                "target_rva": target_rva,
                "kind": kind,
                "root_rvas": sorted(diagnostic_edge_roots[
                    (source_rva, target_rva, kind)
                ]),
            }
            for source_rva, target_rva, kind in sorted(diagnostic_edge_roots)
        ]
        native_link_facts = None
        if native_provenance:
            semantic_link_input = _semantic_link_kernel_input_v1(semantic)
            expected_fields = {
                "version", "symbols", "relocations", "objects",
                "runtime_primitive_dependencies",
            }
            if set(semantic_link_input) != expected_fields:
                raise AssertionError("semantic-link kernel input fields drifted")
            if semantic_link_input["version"] != 2:
                raise AssertionError("semantic-link kernel version drifted")
            if not semantic_link_input["runtime_primitive_dependencies"]:
                raise AssertionError("fixture lost runtime dependencies")
            expected_objects = [
                {
                    "object_id": row["object_id"],
                    "semantic_symbol_id": row["target_symbol"],
                }
                for row in semantic.payload["effect_index"][
                    "object_symbol_bindings"
                ]
            ]
            if semantic_link_input["objects"] != expected_objects:
                raise AssertionError("semantic-link object projection drifted")
            if corrupt_runtime_dependencies:
                semantic_link_input["runtime_primitive_dependencies"].pop()
            if corrupt_transfer_relocations:
                relocation = next(
                    row for row in semantic_link_input["relocations"]
                    if row["relocation_id"].startswith("transfer:")
                )
                relocation["target_rva"] += 1
            if corrupt_external_declaration:
                external_symbol = next(
                    row for row in semantic_link_input["symbols"]
                    if row["kind"] == "external_function"
                )
                external_symbol["checked_contract_sha256"] = "f" * 64
            closure, edge_root_provenance, native_link_facts = (
                _native_semantic_link_kernel_v1(
                    transfer_plan=transfer_path,
                    context=context,
                    semantic_link_input=semantic_link_input,
                )
            )
            check_python_reference_closure_parity_v1(
                transfer_plan=transfer_path,
                context=context,
                native_receipt=closure,
                native_edge_root_provenance=edge_root_provenance,
                native_reference_facts=native_link_facts["references"],
            )
            if corrupt_native_facts:
                native_link_facts["symbols"][0]["reachable"] = not (
                    native_link_facts["symbols"][0]["reachable"]
                )
            if corrupt_native_effects:
                native_link_facts["effects"]["runtime_providers"][0][
                    "root_rvas"
                ] = []
            if corrupt_native_objects:
                native_link_facts["objects"][0]["reachable"] = not (
                    native_link_facts["objects"][0]["reachable"]
                )
            if corrupt_native_references:
                native_link_facts["references"]["facts"][0][
                    "state_contexts"
                ] = 0
        facts = build_semantic_link_worklist_facts(
            semantic=semantic,
            closure=closure,
            native_link_facts=native_link_facts,
        )
        write_json(root / "module-execution-closure.json", closure)
        write_json(root / "resolved-external-environment.json", environment)
        return facts



__all__ = ["SemanticLinkFixture"]
