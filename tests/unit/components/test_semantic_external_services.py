from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import (
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    canonical_sha256_v3,
)
from spaghetti_extractor.authority.external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    CanonicalExternalSiteRecordV3,
    CanonicalExternalSiteV3,
    ExternalContractV3,
    external_site_id_v3,
)
from spaghetti_extractor.components.machine_binding import (
    create_component_machine_binding_v1,
)
from spaghetti_extractor.components.semantic_contract import (
    ComponentSemanticContractError,
    _checked_external_result_projection,
    build_component_semantic_contract,
)
from spaghetti_extractor.components.semantic_services import service_event_index
from spaghetti_extractor.components.semantic_paths import (
    _nonnull_minimum_remaining,
)


SHA = hashlib.sha256(b"semantic-external-service").hexdigest()


def _reference_projection(register: str = "eax") -> dict[str, object]:
    return {
        "kind": "reference",
        "source": {
            "kind": "register",
            "register": register,
            "width": 32,
            "at": "call",
        },
        "requested_extent": {"kind": "constant", "value": 1, "width": 32},
        "authority": {
            "id": "input_string",
            "kind": "external",
            "lifetime": "invocation",
        },
        "at": "call",
    }


class SemanticExternalServiceTests(unittest.TestCase):
    def test_checked_nonzero_search_result_preserves_one_following_byte(self) -> None:
        site = "service:find:unit:0"

        def logical(direction: str, port: str) -> dict[str, object]:
            return {
                "op": "logical",
                "sort": {"kind": "reference"},
                "args": [],
                "attributes": {
                    "path": {
                        "root": "interaction",
                        "id": site,
                        "fields": [direction, port],
                    }
                },
            }

        result = logical("output", "result")
        needle = logical("input", "argument.1")
        def constant(value: int, width: int) -> dict[str, object]:
            return {
                "op": "const",
                "sort": {"kind": "bitvector", "width": width},
                "args": [],
                "attributes": {"value": value},
            }

        ensures = [{
            "op": "or", "sort": {"kind": "bool"}, "attributes": {},
            "args": [
                {
                    "op": "ref_is_null",
                    "sort": {"kind": "bool"},
                    "attributes": {},
                    "args": [result],
                },
                {
                    "op": "or", "sort": {"kind": "bool"}, "attributes": {},
                    "args": [
                        {
                            "op": "eq",
                            "sort": {"kind": "bool"},
                            "attributes": {},
                            "args": [needle, constant(0, 8)],
                        },
                        {
                            "op": "ult", "sort": {"kind": "bool"}, "attributes": {},
                            "args": [
                                constant(1, 64),
                                {
                                    "op": "ref_remaining",
                                    "sort": {"kind": "bitvector", "width": 64},
                                    "attributes": {},
                                    "args": [result],
                                },
                            ],
                        },
                    ],
                },
            ],
        }]
        self.assertEqual(_nonnull_minimum_remaining(ensures, site), (1, 2))

    def test_checked_result_adapter_only_wraps_authorized_register(self) -> None:
        projection = _reference_projection()
        self.assertEqual(
            _checked_external_result_projection(
                projection,
                logical_kind="reference",
                machine_register="eax",
            ),
            projection,
        )
        with self.assertRaisesRegex(
            ComponentSemanticContractError, "disagrees with its ABI contract"
        ):
            _checked_external_result_projection(
                _reference_projection("edx"),
                logical_kind="reference",
                machine_register="eax",
            )

    def test_external_contract_supplies_abi_boundary_and_typed_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unit_id = "unit:select"
            event = {
                "kind": "external_call",
                "target": {
                    "kind": "import",
                    "dll": "msvcrt.dll",
                    "symbol": "strrchr",
                },
                "register_inputs": {
                    register: {"op": "reg", "name": register, "width": 32}
                    for register in (
                        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                    )
                },
                "stack_inputs": [],
            }
            unit = {
                "format": "spaghetti-extractor-machine-ir-v3",
                "record_kind": "unit",
                "id": unit_id,
                "status": "qualified",
                "source": {
                    "original": {"rva_start": 0x1000, "rva_end": 0x1010},
                    "contract_sha256": "b" * 64,
                    "instruction_bytes_sha256": "c" * 64,
                },
                "semantics": {
                    "outcome": {"kind": "return"},
                    "external_events": [event],
                    "memory_events": [],
                    "register_writes": [],
                    "flag_writes": [],
                    "faults": [],
                },
            }
            machine = root / "machine-ir.jsonl"
            machine.write_text(json.dumps(unit, sort_keys=True) + "\n", encoding="ascii")
            machine_sha256 = hashlib.sha256(machine.read_bytes()).hexdigest()
            manifest = root / "machine-ir-manifest.json"
            manifest.write_text(
                json.dumps({
                    "format": "spaghetti-extractor-machine-ir-v3",
                    "binary": {"sha256": "a" * 64},
                    "artifacts": {"machine_ir": {"sha256": machine_sha256}},
                }),
                encoding="ascii",
            )
            interface = {
                "format": "spaghetti-extractor-component-interface-ir-v4",
                "id": "external_reference",
                "types": [
                    {"id": "u8", "kind": "scalar", "c_type": "uint8_t"},
                    {
                        "id": "input",
                        "kind": "view",
                        "element_type_id": "u8",
                        "access": "read",
                        "extent": {"kind": "nul_terminated"},
                        "ownership": "borrowed",
                    },
                    {
                        "id": "character",
                        "kind": "reference",
                        "element_type_id": "u8",
                        "access": "read",
                        "nullable": True,
                        "allow_one_past": False,
                        "lifetime": "origin",
                    },
                ],
                "state": [],
                "operations": [{
                    "id": "select",
                    "kind": "operation",
                    "parameters": [{"id": "input", "type_id": "input"}],
                    "results": [],
                    "effect_ids": [],
                    "allowed_service_ids": ["find"],
                    "pre_states": ["ready"],
                    "post_states": ["ready"],
                }],
                "effects": [],
                "services": [{
                    "id": "find",
                    "parameter_type_ids": ["input"],
                    "result_type_id": "character",
                    "effect_ids": [],
                }],
                "protocol": {"states": ["ready"], "initial_state": "ready"},
            }
            identity = {
                "kind": "import",
                "dll": "msvcrt.dll",
                "symbol": "strrchr",
            }
            contract = ExternalContractV3.create(
                identity=identity,
                transfer_kind="call",
                disposition="returns",
                profile_id="pe32-msvcrt-lockstep-v1",
                profile_sha256=SHA,
                argument_words=1,
                arguments=[{"kind": "stack", "offset": 0}],
                memory_effect="readOnly",
                world_effect="none",
                callback_effect="none",
                machine_contract={
                    "abi_template": "pe32-cdecl-v1",
                    "result_register_relations": [
                        {"register": "eax", "relation": "related_word"}
                    ],
                    "memory_footprints": [],
                    "out_pointer_relations": [],
                    "out_interface_relations": [],
                },
            )
            event_sha256 = canonical_sha256_v3(event)
            site_id = external_site_id_v3(unit_id, 0, 0, identity)
            site = CanonicalExternalSiteV3(
                site_id=site_id,
                unit_id=unit_id,
                event_index=0,
                alternative_index=0,
                event_sha256=event_sha256,
                target_sha256=canonical_sha256_v3(identity),
                identity=CanonicalValueV3.of(identity),
                status="complete",
                authorizing=True,
                contract=contract,
                primary_blocker=None,
            )
            record = CanonicalExternalSiteRecordV3(
                record_id=unit_id,
                unit_sha256=SHA,
                status="complete",
                authorizing=True,
                sites=(site,),
                primary_blocker=None,
                dependencies=(),
            )
            sites = root / "external-sites"
            ArtifactSetWriterV3(
                artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
                bindings=(),
                status="complete",
            ).write(
                sites,
                [ArtifactRecordV3.create(
                    unit_id, CANONICAL_EXTERNAL_SITE_CODEC_V3.encode(record)
                )],
            )
            binding = create_component_machine_binding_v1(
                id="external-reference",
                binary={
                    "pe_sha256": "a" * 64,
                    "machine_ir_sha256": machine_sha256,
                },
                interface={
                    "id": "external_reference",
                    "sha256": canonical_sha256_v3(interface),
                },
                unit_ids=[unit_id],
                operations=[{
                    "operation_id": "select",
                    "entry_unit_ids": [unit_id],
                    "exit_unit_ids": [unit_id],
                    "parameters": [{
                        "id": "input",
                        "projection": {
                            "kind": "view",
                            "base": {
                                "kind": "register", "register": "ebx",
                                "width": 32, "at": "entry",
                            },
                            "extent": {"kind": "origin_remainder"},
                            "requested_extent": {
                                "kind": "constant", "value": 1, "width": 32,
                            },
                            "authority": {
                                "id": "input_string", "kind": "external",
                                "lifetime": "invocation",
                            },
                            "at": "entry",
                        },
                    }],
                    "results": [],
                    "state": [],
                    "preserved_state_ids": [],
                    "effects": [],
                    "callback_operation_ids": [],
                    "continuation_unit_ids": [],
                }],
                services=[{
                    "service_id": "find",
                    "provider": {
                        "kind": "external_site",
                        "site_id": site_id,
                        "result_projection": _reference_projection(),
                    },
                    "mediation": "direct",
                }],
            )
            semantic = build_component_semantic_contract(
                interface=interface,
                binding=binding,
                machine_ir=machine,
                machine_ir_manifest=manifest,
                canonical_external_sites=sites,
            )

        self.assertEqual(semantic["status"], "satisfied")
        provider = semantic["services"][0]["provider"]
        self.assertEqual(
            provider["call_boundary"],
            {
                "contract_id": contract.contract_id,
                "abi_template": "pe32-cdecl-v1",
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "stack_pointer_adjustment": 0,
            },
        )
        self.assertEqual(provider["events"][0]["result"], _reference_projection())
        bound = next(iter(service_event_index(semantic["services"], {"find": {}}).values()))
        self.assertEqual(bound.preserved_registers, ("ebp", "ebx", "edi", "esi"))
        self.assertEqual(bound.stack_pointer_adjustment, 0)
        self.assertEqual(bound.result.kind, "reference")


if __name__ == "__main__":
    unittest.main()
