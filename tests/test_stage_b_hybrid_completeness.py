from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.behavioral_roots import generate_behavioral_roots
from spaghetti_extractor.stage_b_hybrid_completeness import (
    StaticHybridCompletenessError,
    write_static_hybrid_completeness_report,
)
from spaghetti_extractor.external_interface_profiles import (
    EXTERNAL_INTERFACE_PROFILE_FORMAT,
    InterfaceCallerMemoryFrame,
    InterfaceMemoryArgument,
    load_external_interface_profile,
    same_library_callback_call_through_effect_json,
    same_library_call_through_effect_json,
)
from spaghetti_extractor.machine_abi import resolve_machine_call_abi
from spaghetti_extractor.roundtrip_fuzz.image_contract import (
    write_stage_a_load_image_contract,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file

from tests.pe_fixtures import pe32_image
from tests.test_stage_a_pe_entry_surface import _pe32_export_surface_image


class StaticHybridCompletenessTests(unittest.TestCase):
    def _bind_instruction_schedule(self, unit: dict) -> None:
        """Build one exact one-instruction schedule for the synthetic RET unit."""

        source = unit.setdefault("source", {}).setdefault("original", {})
        start = source["rva_start"]
        end = source["rva_end"]
        source["size"] = end - start
        instruction_digest = sha256_bytes(b"\xc3")
        unit["source"]["instruction_bytes_sha256"] = instruction_digest
        unit["instructions"] = [{
            "instruction_sha256": instruction_digest,
            "mnemonic": "ret",
            "operands": [],
            "registers_read": ["esp"],
            "registers_written": ["esp"],
            "rva_start": start,
            "rva_end": end,
            "size": end - start,
        }]
        semantics = unit.setdefault("semantics", {})
        external_events = semantics.setdefault("external_events", [])
        faults = semantics.setdefault("faults", [])
        semantics.setdefault("edge_conditions", [])
        semantics.setdefault("flag_writes", [])
        semantics.setdefault("memory_events", [])
        semantics.setdefault("register_writes", [])
        ordered_events = [
            {**event, "family": "external", "instruction_rva": start}
            for event in external_events
        ]
        semantics["ordered_events"] = ordered_events
        semantics["counts"] = {
            field: len(semantics[field])
            for field in (
                "edge_conditions",
                "external_events",
                "faults",
                "flag_writes",
                "memory_events",
                "ordered_events",
                "register_writes",
            )
        }
        effects = {
            "call_effects": list(external_events),
            "control": dict(semantics.get("outcome") or {"kind": "return"}),
            "defined_flag_writes": [],
            "faults": list(faults),
            "memory_events": [],
            "ordered_events": ordered_events,
            "register_writes": [],
            "undefined_flag_writes": [],
            "undefined_flags": [],
        }
        effects["counts"] = {
            field: len(effects[field])
            for field in (
                "call_effects",
                "defined_flag_writes",
                "faults",
                "memory_events",
                "ordered_events",
                "register_writes",
                "undefined_flag_writes",
                "undefined_flags",
            )
        }
        record = {
            "index": 0,
            "rva_start": start,
            "rva_end": end,
            "bytes_sha256": instruction_digest,
            "transfer_bytes_sha256": instruction_digest,
            "instruction_class": "ordinary_symbolic_instruction",
            "classification": {
                "status": "proposal_requires_lean_exact_byte_replay",
                "proof_authority": False,
                "checked_decoder": "StageA.Formal.decodeInstructionExact",
                "checked_executor": "StageA.Formal.executeInstruction",
            },
            "symbolic_pre_state_sha256": sha256_bytes(b"pre-state"),
            "symbolic_post_state_sha256": sha256_bytes(b"post-state"),
            "effects": effects,
        }
        record["source_record_sha256"] = sha256_bytes(b"source-record")
        record["record_sha256"] = sha256_bytes(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        schedule = {
            "format": "stage-a-instruction-ordered-effect-schedule-v1",
            "status": "complete",
            "proof_authority": False,
            "ordering": "strict_contiguous_rva_order",
            "rva_start": start,
            "rva_end": end,
            "transfer_bytes_sha256": instruction_digest,
            "records": [record],
            "blockers": [],
            "counts": {
                "instructions": 1,
                "ordinary_instructions": 1,
                "x87_singletons": 0,
                "blockers": 0,
            },
        }
        schedule["source_schedule_sha256"] = sha256_bytes(
            b"source-schedule"
        )
        schedule["schedule_sha256"] = sha256_bytes(
            json.dumps(schedule, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        semantics["instruction_effect_schedule"] = schedule

    def _rewrite_units(
        self,
        machine_ir: Path,
        manifest_path: Path,
        units: list[dict],
    ) -> dict:
        machine_ir.write_text(
            "".join(json.dumps(unit, sort_keys=True) + "\n" for unit in units),
            encoding="utf-8",
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["counts"]["units"] = len(units)
        manifest["counts"]["instructions"] = sum(
            len(unit.get("instructions", [])) for unit in units
        )
        manifest["artifacts"]["machine_ir"]["sha256"] = sha256_file(machine_ir)
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        return manifest

    def _write_manifest(self, manifest_path: Path, manifest: dict) -> None:
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )

    def _report(
        self,
        root: Path,
        machine_ir: Path,
        manifest: Path,
        load_image: Path,
        profile: Path,
        interface_profiles: tuple[Path, ...] = (),
    ) -> dict:
        return write_static_hybrid_completeness_report(
            machine_ir=machine_ir,
            machine_ir_manifest=manifest,
            load_image_contract=load_image,
            machine_import_profiles=[profile],
            external_interface_profiles=interface_profiles,
            out=root / "report.json",
        )

    def _set_behavioral_root_nonreturning(self, manifest: dict) -> None:
        summary = manifest["control"]["internal_call_preservation"]["summaries"][0]
        summary["return_behavior"] = {
            "status": "complete",
            "may_return": False,
            "may_not_return": True,
        }
        summary["return_nodes"] = 0
        summary["return_unit_ids"] = []

    def _fixture(
        self,
        root: Path,
        *,
        unit: dict | None = None,
        issues: list[dict] | None = None,
        potential_units: list[str] | None = None,
        external_events: list[dict] | None = None,
        original_pe: bytes | None = None,
    ) -> tuple[Path, Path, Path, Path]:
        unit = unit or {
            "format": "stage-a-machine-ir-v2",
            "id": "unit:entry",
            "status": "qualified",
            "reachable": True,
            "reachability": "reachable",
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1001}},
            "control": {
                "kind": "return",
                "direct_targets": [],
                "has_indirect_target": False,
            },
            "semantics": {
                "external_events": [],
                "faults": [],
                "edge_conditions": [],
                "outcome": {"kind": "return"},
                "counts": {"instructions": 1},
            },
        }
        unit = json.loads(json.dumps(unit))
        if external_events is not None:
            unit.setdefault("semantics", {})["external_events"] = [
                dict(item["event"]) for item in external_events
            ]
        self._bind_instruction_schedule(unit)
        machine_ir = root / "machine-ir.jsonl"
        machine_ir.write_text(json.dumps(unit, sort_keys=True) + "\n", encoding="utf-8")
        original_path = root / "original.exe"
        original_path.write_bytes(original_pe or pe32_image(b"\xc3"))
        load_image = root / "load-image-contract.json"
        load_contract = write_stage_a_load_image_contract(
            original_pe=original_path, out=load_image
        )
        (root / "behavioral-roots.json").write_text(
            json.dumps(generate_behavioral_roots(original_path), sort_keys=True),
            encoding="utf-8",
        )
        potential_units = potential_units or []
        reachable = [] if unit["id"] in potential_units else [unit["id"]]
        manifest = {
            "format": "stage-a-machine-ir-v2",
            "status": "qualified",
            "counts": {"units": 1, "instructions": 1},
            "inputs": {
                "original_pe": {
                    "path": original_path.name,
                    "sha256": load_contract.identity.pe_sha256,
                }
            },
            "binary": {
                "sha256": load_contract.identity.pe_sha256,
                "machine": load_contract.identity.machine,
                "bitness": load_contract.identity.bitness,
                "image_base": load_contract.identity.preferred_base,
                "entrypoint_rva": load_contract.identity.entry_rva,
                "size_of_image": load_contract.identity.image_size,
            },
            "artifacts": {
                "machine_ir": {
                    "format": "stage-a-machine-ir-v2",
                    "path": "machine-ir.jsonl",
                    "sha256": sha256_file(machine_ir),
                }
            },
            "coverage": {"counts": {"unknown_bytes": 0}},
            "issues": issues or [],
            "external": {"events": external_events or []},
            "control": {
                "analysis_fixed_point": {
                    "status": "complete",
                    "rounds": 2,
                    "cold_replay_validated": True,
                },
                "direct_targets": [],
                "indirect_exits": [],
                "exceptional_control": {
                    "format": "stage-a-exceptional-control-v1",
                    "transitions": [],
                },
                "reachability": {
                    "status": "complete" if not potential_units else "incomplete",
                    "roots": reachable,
                    "reachable_units": reachable,
                    "potential_units": potential_units,
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
                        "target_rva": unit["source"]["original"]["rva_start"],
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
                        "blocker_codes": [],
                    }],
                },
                "external_interface_provenance": {
                    "format": "stage-a-external-interface-provenance-v1",
                    "status": "complete",
                    "proof_authority": False,
                    "fixed_point": {"rounds": 1, "converged": True},
                    "resolutions": [],
                    "issues": [],
                    "callback_registrations": [],
                },
            },
        }
        manifest_path = root / "machine-ir-manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        profile = root / "profile.json"
        profile.write_text(json.dumps({
            "format": "stage-a-static-machine-import-profile-v1",
            "id": "test-profile-v1",
            "includes": [],
            "machine_import_signatures": [],
        }), encoding="utf-8")
        return machine_ir, manifest_path, load_image, profile

    def _write_interface_profile(
        self, root: Path, *, explicit_callback: bool
    ) -> Path:
        abi = resolve_machine_call_abi("pe32-stdcall-v1")
        assert abi is not None
        effects = (
            same_library_callback_call_through_effect_json(
                source={"kind": "argument_word", "argument": 1},
                abi={
                    "kind": "generic_callback",
                    "argument_words": 2,
                    "stack_cleanup_bytes": 8,
                    "nullable": True,
                },
                lifetime="during_call",
                status="complete",
            )
            if explicit_callback
            else same_library_call_through_effect_json()
        )
        memory_arguments = [InterfaceMemoryArgument(
            argument_index=0,
            role="interface_resource",
            access="read_write",
            extent="opaque_resource",
            retention="during_call",
        )]
        if explicit_callback:
            memory_arguments.append(InterfaceMemoryArgument(
                argument_index=1,
                role="callback",
                access="read",
                extent="opaque_resource",
                retention="callback_contract",
            ))
        path = root / "interface-profile.json"
        path.write_text(json.dumps({
            "format": EXTERNAL_INTERFACE_PROFILE_FORMAT,
            "id": "fixture-interface-profile-v1",
            "model": "x86-pe32",
            "status": "complete",
            "provenance": {"kind": "fixture"},
            "effect_model": "same-library-call-through-v1",
            "factories": [],
            "interfaces": [{
                "id": "IFixture",
                "vtable": "IFixtureVtbl",
                "methods": [{
                    "name": "Visit" if explicit_callback else "Release",
                    "slot": 0,
                    "offset": 0,
                    "abi_template": "pe32-stdcall-v1",
                    "machine_abi": abi.as_json(),
                    "argument_words": 2,
                    "caller_memory_frame": InterfaceCallerMemoryFrame(
                        tuple(memory_arguments)
                    ).as_json(),
                    "out_interfaces": [],
                    **effects,
                }],
            }],
        }, sort_keys=True), encoding="utf-8")
        return path

    def _install_interface_target(
        self,
        machine_ir: Path,
        manifest_path: Path,
        interface_profile: Path,
        *,
        include_callback_registration: bool,
    ) -> tuple[dict, dict]:
        typed_profile = load_external_interface_profile(interface_profile)
        method = typed_profile.interfaces[0].methods[0]
        target = method.target_json(
            profile_id=typed_profile.profile_id,
            profile_sha256=typed_profile.sha256,
        )
        target["external_protocol"]["transfer_kind"] = "call"
        target_expression = {"op": "register", "name": "eax"}
        arguments = [
            {"op": "register", "name": "ecx"},
            {"op": "register", "name": "edx"},
        ]
        site_contract = {
            "template": target["abi"]["template"],
            "argument_words": target["argument_words"],
            "argument_base_offset": 0,
            "contract_id": f"{method.interface_id}::{method.name}",
            "profile_binding": {
                "profile_id": typed_profile.profile_id,
                "profile_sha256": typed_profile.sha256,
            },
            "disposition": "returns",
            "result_register_relations": [],
            "memory_effect": target["memory_effect"],
            "memory_footprints": target["memory_footprints"],
            "world_effect": target["world_effect"],
            "callback_effect": target["callback_effect"],
            "out_pointer_relations": [],
            "out_interface_relations": target["out_interfaces"],
        }
        for field in (
            "callback_source",
            "callback_abi",
            "callback_lifetime",
            "callback_behavior",
        ):
            if field in target:
                site_contract[field] = target[field]
        event = {
            "kind": "indirect_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1000,
            "target": target_expression,
            "arguments": arguments,
            "abi_contract": site_contract,
        }
        unit = json.loads(machine_ir.read_text(encoding="utf-8"))
        unit["semantics"]["external_events"] = [event]
        self._bind_instruction_schedule(unit)
        manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
        manifest["external"]["events"] = [{
            "unit_id": "unit:entry",
            "unit_rva": 0x1000,
            "event_index": 0,
            "kind": "indirect_call",
            "instruction_rva": 0x1000,
            "dll": None,
            "symbol": None,
            "ordinal": None,
            "event": event,
        }]
        manifest["control"]["indirect_exits"] = [{
            "source_unit_id": "unit:entry",
            "source_rva": 0x1000,
            "source_event_index": 0,
            "kind": "indirect_call",
            "target_expression": target_expression,
            "closure": "checked_finite_target_inventory",
            "target_rvas": [],
            "target_unit_ids": [],
            "external_targets": [target],
        }]
        provenance = manifest["control"]["external_interface_provenance"]
        provenance["resolutions"] = [{
            "source_unit_id": "unit:entry",
            "source_rva": 0x1000,
            "source_event_index": 0,
            "kind": "indirect_call",
            "target_expression": target_expression,
            "status": "recovered",
            "target_unit_ids": [],
            "external_targets": [target],
        }]
        if include_callback_registration:
            effect = method.effects
            assert effect is not None
            provenance["callback_registrations"] = [{
                "format": "stage-a-callback-registration-provenance-v1",
                "record_kind": "callback_registration",
                "proof_authority": False,
                "status": "complete",
                "unit_id": "unit:entry",
                "event_index": 0,
                "instruction_rva": 0x1000,
                "import": None,
                "contract_id": "interface-method-callback",
                "profile_binding": {
                    "interface_protocols": [{
                        "profile_sha256": typed_profile.sha256,
                        "interface_id": method.interface_id,
                        "method": method.name,
                        "slot": method.slot,
                        "callback_arguments": [
                            dict(argument)
                            for argument in effect.callback_arguments
                        ],
                    }],
                },
                "callback_source": effect.callback_source,
                "callback_abi": effect.callback_abi,
                "callback_lifetime": effect.callback_lifetime,
                "target_rvas": [0x1000],
                "target_unit_ids": ["unit:entry"],
                "failure": None,
            }]
            manifest["control"]["callback_cutpoint_proposals"] = [{
                "target_unit_id": "unit:entry",
                "rva": 0x1000,
            }]
        self._write_manifest(manifest_path, manifest)
        return target, manifest

    def test_complete_return_only_machine_ir_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest, load_image, profile = self._fixture(root)
            report = write_static_hybrid_completeness_report(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                load_image_contract=load_image,
                machine_import_profiles=[profile],
                out=root / "report.json",
            )
            self.assertEqual(report["status"], "complete")
            self.assertEqual(report["counts"]["reachable_units"], 1)
            self.assertEqual(report["counts"]["reachable_returns"], 1)
            self.assertEqual(report["counts"]["executable_instruction_count"], 1)
            self.assertEqual(report["blockers"], [])

    def test_control_fixed_point_requires_cold_replay_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["control"]["analysis_fixed_point"] = {
                "status": "incomplete",
                "rounds": 4,
                "cold_replay_validated": False,
            }
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "incomplete")
            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "control_fixed_point_not_cold_validated"
            )
            self.assertEqual(blocker["details"]["reported_status"], "incomplete")
            self.assertIs(blocker["details"]["cold_replay_validated"], False)

    def test_executable_pe_export_is_an_independent_mandatory_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest, load_image, profile = self._fixture(
                root, original_pe=_pe32_export_surface_image()
            )

            report = self._report(
                root, machine_ir, manifest, load_image, profile
            )

            missing = [
                item
                for item in report["blockers"]
                if item["code"] == "mandatory_root_missing"
            ]
            self.assertEqual(len(missing), 1)
            self.assertEqual(missing[0]["details"]["root_kind"], "pe_export")
            self.assertEqual(missing[0]["details"]["rva"], 0x1010)

    def test_callback_free_interface_method_needs_no_registration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            interface_profile = self._write_interface_profile(
                root, explicit_callback=False
            )
            self._install_interface_target(
                machine_ir,
                manifest_path,
                interface_profile,
                include_callback_registration=False,
            )

            report = self._report(
                root,
                machine_ir,
                manifest_path,
                load_image,
                profile,
                (interface_profile,),
            )

            self.assertEqual(report["status"], "complete", report["blockers"])
            self.assertEqual(report["counts"]["recovered_interface_calls"], 1)

    def test_interface_profile_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            interface_profile = self._write_interface_profile(
                root, explicit_callback=False
            )
            _target, manifest = self._install_interface_target(
                machine_ir,
                manifest_path,
                interface_profile,
                include_callback_registration=False,
            )
            protocol = manifest["control"]["external_interface_provenance"][
                "resolutions"
            ][0]["external_targets"][0]["external_protocol"]
            protocol["profile_sha256"] = "0" * 64
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root,
                machine_ir,
                manifest_path,
                load_image,
                profile,
                (interface_profile,),
            )

            self.assertEqual(report["status"], "incomplete")
            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "interface_method_contract_mismatch"
            )
            self.assertIn(
                "external_protocol.profile_sha256",
                blocker["details"]["mismatches"],
            )

    def test_explicit_interface_callback_requires_registration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            interface_profile = self._write_interface_profile(
                root, explicit_callback=True
            )
            self._install_interface_target(
                machine_ir,
                manifest_path,
                interface_profile,
                include_callback_registration=False,
            )

            report = self._report(
                root,
                machine_ir,
                manifest_path,
                load_image,
                profile,
                (interface_profile,),
            )

            self.assertEqual(report["status"], "incomplete")
            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "interface_callback_registration_incomplete"
            )
            self.assertIn(
                "callback_registration.missing",
                blocker["details"]["mismatches"],
            )
            self.assertIn(
                "callback_registration_missing",
                {item["code"] for item in report["blockers"]},
            )

    def test_malformed_interface_callback_contract_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            interface_profile = self._write_interface_profile(
                root, explicit_callback=True
            )
            _target, manifest = self._install_interface_target(
                machine_ir,
                manifest_path,
                interface_profile,
                include_callback_registration=True,
            )
            complete = self._report(
                root,
                machine_ir,
                manifest_path,
                load_image,
                profile,
                (interface_profile,),
            )
            self.assertEqual(
                complete["status"], "complete", complete["blockers"]
            )
            target = manifest["control"]["external_interface_provenance"][
                "resolutions"
            ][0]["external_targets"][0]
            target["callback_abi"] = {
                **target["callback_abi"],
                "argument_words": 3,
            }
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root,
                machine_ir,
                manifest_path,
                load_image,
                profile,
                (interface_profile,),
            )

            self.assertEqual(report["status"], "incomplete")
            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "interface_method_contract_mismatch"
            )
            self.assertIn("callback_abi", blocker["details"]["mismatches"])

    def test_qualified_row_with_omitted_instruction_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["instructions"] = []
            self._rewrite_units(machine_ir, manifest_path, [unit])

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "qualified_instruction_schedule_inconsistent"
            )
            self.assertIn(
                "instruction inventory is missing or empty",
                blocker["details"]["problems"],
            )

    def test_qualified_row_with_altered_instruction_span_or_hash_is_violated(
        self,
    ) -> None:
        mutations = {
            "span": lambda unit: unit["instructions"][0].__setitem__(
                "rva_end", 0x1002
            ),
            "hash": lambda unit: unit["instructions"][0].__setitem__(
                "instruction_sha256", "0" * 64
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                machine_ir, manifest_path, load_image, profile = self._fixture(root)
                unit = json.loads(machine_ir.read_text(encoding="utf-8"))
                mutate(unit)
                self._rewrite_units(machine_ir, manifest_path, [unit])

                report = self._report(
                    root, machine_ir, manifest_path, load_image, profile
                )

                self.assertEqual(report["status"], "violated")
                self.assertIn(
                    "qualified_instruction_schedule_inconsistent",
                    {item["code"] for item in report["blockers"]},
                )

    def test_qualified_row_with_missing_schedule_record_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            schedule = unit["semantics"]["instruction_effect_schedule"]
            schedule["records"] = []
            schedule["counts"]["instructions"] = 0
            schedule["counts"]["ordinary_instructions"] = 0
            self._rewrite_units(machine_ir, manifest_path, [unit])

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "qualified_instruction_schedule_inconsistent"
            )
            self.assertIn(
                "instruction-effect schedule does not contain one record per instruction",
                blocker["details"]["problems"],
            )

    def test_qualified_status_cannot_spoof_incomplete_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            schedule = unit["semantics"]["instruction_effect_schedule"]
            schedule["status"] = "incomplete"
            schedule["blockers"] = [{"code": "unsupported_instruction"}]
            schedule["counts"]["blockers"] = 1
            self._rewrite_units(machine_ir, manifest_path, [unit])

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            self.assertEqual(report["counts"]["violated_inventory_claims"], 1)
            self.assertIn(
                "qualified_instruction_schedule_inconsistent",
                {item["code"] for item in report["blockers"]},
            )

    def test_qualified_row_with_deleted_instruction_effect_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = {
                "unit_id": "unit:entry",
                "unit_rva": 0x1000,
                "event_index": 0,
                "event": {
                    "kind": "external_call",
                    "dll": "fixture.dll",
                    "symbol": "Effect",
                    "ordinal": None,
                },
            }
            machine_ir, manifest_path, load_image, profile = self._fixture(
                root, external_events=[event]
            )
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            effects = unit["semantics"]["instruction_effect_schedule"]["records"][
                0
            ]["effects"]
            effects["ordered_events"] = []
            effects["counts"]["ordered_events"] = 0
            self._rewrite_units(machine_ir, manifest_path, [unit])

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "qualified_instruction_schedule_inconsistent"
            )
            self.assertIn(
                "instruction effects and aggregate ordered-event inventory differ",
                blocker["details"]["problems"],
            )

    def test_outer_schedule_digest_cannot_hide_corrupt_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            schedule = unit["semantics"]["instruction_effect_schedule"]
            schedule["records"][0]["classification"]["checked_executor"] = (
                "StageA.Formal.corruptExecutor"
            )
            schedule.pop("schedule_sha256")
            schedule["schedule_sha256"] = sha256_bytes(
                json.dumps(
                    schedule, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            )
            self._rewrite_units(machine_ir, manifest_path, [unit])

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "qualified_instruction_schedule_inconsistent"
            )
            self.assertIn(
                "schedule record 0 digest does not match its contents",
                blocker["details"]["problems"],
            )

    def test_resealed_unknown_semantic_executor_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            schedule = unit["semantics"]["instruction_effect_schedule"]
            record = schedule["records"][0]
            record["classification"]["checked_executor"] = (
                "StageA.Formal.unknownExecutor"
            )
            record.pop("record_sha256")
            record["record_sha256"] = sha256_bytes(
                json.dumps(
                    record, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            )
            schedule.pop("schedule_sha256")
            schedule["schedule_sha256"] = sha256_bytes(
                json.dumps(
                    schedule, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            )
            self._rewrite_units(machine_ir, manifest_path, [unit])

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            blocker = next(
                item
                for item in report["blockers"]
                if item["code"] == "qualified_instruction_schedule_inconsistent"
            )
            self.assertIn(
                "schedule record 0 lacks a checked semantic classification",
                blocker["details"]["problems"],
            )

    def test_potential_unsupported_transfer_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            potential = {
                "format": "stage-a-machine-ir-v2",
                "id": "unit:potential",
                "status": "incomplete",
                "reachable": False,
                "reachability": "potential",
                "source": {"original": {"rva_start": 0x2000, "rva_end": 0x2001}},
                "control": {"kind": "unknown", "direct_targets": []},
            }
            issue = {
                "id": "issue:unsupported",
                "status": "incomplete",
                "category": "unsupported_semantics",
                "message": "instruction form is unsupported",
                "next_action": "implement the instruction form",
                "location": {"unit_id": "unit:potential", "rva_start": 0x2000},
            }
            with machine_ir.open("a", encoding="utf-8") as destination:
                destination.write(json.dumps(potential, sort_keys=True) + "\n")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["counts"]["units"] = 2
            manifest["artifacts"]["machine_ir"]["sha256"] = sha256_file(machine_ir)
            manifest["issues"] = [issue]
            manifest["control"]["reachability"]["status"] = "incomplete"
            manifest["control"]["reachability"]["potential_units"] = [
                "unit:potential"
            ]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            report = write_static_hybrid_completeness_report(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest_path,
                load_image_contract=load_image,
                machine_import_profiles=[profile],
                out=root / "report.json",
            )
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(
                report["families"]["deferred_transfers"]["status"], "incomplete"
            )
            self.assertIn(
                "potential_transfer_semantics_incomplete",
                {item["code"] for item in report["blockers"]},
            )

    def test_reachable_import_without_contract_reports_source_location(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = {
                "unit_id": "unit:entry",
                "unit_rva": 0x1000,
                "event_index": 0,
                "event": {
                    "kind": "external_call",
                    "dll": "kernel32.dll",
                    "symbol": "WriteFile",
                    "ordinal": None,
                },
            }
            machine_ir, manifest, load_image, profile = self._fixture(
                root, external_events=[event]
            )
            report = write_static_hybrid_completeness_report(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                load_image_contract=load_image,
                machine_import_profiles=[profile],
                out=root / "report.json",
            )
            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "machine_import_contract_missing"
            )
            self.assertEqual(blocker["location"]["unit_id"], "unit:entry")
            self.assertEqual(blocker["location"]["rva_start"], 0x1000)

    def test_reachable_import_site_must_match_its_exact_machine_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            profile_payload = {
                "format": "stage-a-static-machine-import-profile-v1",
                "id": "test-profile-v1",
                "default_callback_effect": "none",
                "includes": [],
                "machine_import_signatures": [{
                    "id": "fixture.dll!Exact",
                    "import": {"dll": "fixture.dll", "symbol": "Exact"},
                    "abi_template": "pe32-stdcall-v1",
                    "arity": {"kind": "fixed", "words": 1},
                    "disposition": "returns",
                    "result_register_relations": [
                        {"register": "eax", "relation": "exact"}
                    ],
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                    "out_pointer_relations": [],
                    "out_interface_relations": [],
                }],
            }
            profile.write_text(
                json.dumps(profile_payload, sort_keys=True), encoding="utf-8"
            )
            argument = {
                "op": "load",
                "width": 4,
                "address": {"op": "reg", "name": "esp", "width": 32},
            }
            event = {
                "kind": "external_call",
                "dll": "fixture.dll",
                "symbol": "Exact",
                "ordinal": None,
                "return_rva": 0x1001,
                "arguments": [argument],
                "stack_inputs": [],
                "abi_contract": {
                    "template": "pe32-stdcall-v1",
                    "argument_words": 1,
                    "argument_base_offset": 0,
                    "contract_id": "fixture.dll!Exact",
                    "profile_binding": {
                        "profile_id": "test-profile-v1",
                        "profile_sha256": sha256_file(profile),
                        "entry_key": "machine_import_signatures",
                        "entry_index": 0,
                    },
                    "disposition": "returns",
                    "result_register_relations": [
                        {"register": "eax", "relation": "exact"}
                    ],
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                    "callback_effect": "none",
                    "out_pointer_relations": [],
                    "out_interface_relations": [],
                },
            }
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["semantics"]["external_events"] = [event]
            self._bind_instruction_schedule(unit)
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            manifest["external"]["events"] = [{
                "unit_id": "unit:entry",
                "unit_rva": 0x1000,
                "event_index": 0,
                "kind": "external_call",
                "instruction_rva": None,
                "dll": "fixture.dll",
                "symbol": "Exact",
                "ordinal": None,
                "event": event,
            }]
            self._write_manifest(manifest_path, manifest)

            complete = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )
            self.assertEqual(complete["status"], "complete", complete["blockers"])

            unit["semantics"]["external_events"][0]["abi_contract"].pop(
                "callback_effect"
            )
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            manifest["external"]["events"][0]["event"] = unit["semantics"][
                "external_events"
            ][0]
            self._write_manifest(manifest_path, manifest)
            incomplete = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )
            self.assertIn(
                "external_site_contract_incomplete",
                {item["code"] for item in incomplete["blockers"]},
            )

    def test_machine_ir_hash_mismatch_is_violated_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest, load_image, profile = self._fixture(root)
            machine_ir.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(
                StaticHybridCompletenessError, "does not bind"
            ):
                write_static_hybrid_completeness_report(
                    machine_ir=machine_ir,
                    machine_ir_manifest=manifest,
                    load_image_contract=load_image,
                    machine_import_profiles=[profile],
                    out=root / "report.json",
                )

    def test_machine_ir_violation_propagates_to_report_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest, load_image, profile = self._fixture(root, issues=[{
                "id": "issue:contradiction",
                "status": "violated",
                "category": "semantic_replay_mismatch",
                "message": "checked replay contradicts the submitted transfer",
                "location": {"unit_id": "unit:entry", "rva_start": 0x1000},
            }])

            report = write_static_hybrid_completeness_report(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                load_image_contract=load_image,
                machine_import_profiles=[profile],
                out=root / "report.json",
            )

            self.assertEqual(report["status"], "violated")
            self.assertEqual(report["counts"]["violated_source_issues"], 1)

    def test_incomplete_internal_call_summary_blocks_return_family(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["control"]["internal_call_preservation"]["status"] = (
                "incomplete"
            )
            manifest["control"]["internal_call_preservation"]["summaries"] = [{
                "status": "incomplete",
                "target_unit_id": "unit:entry",
                "target_rva": 0x1000,
                "blocker_codes": ["unterminated_control_path"],
                "return_nodes": 0,
                "reached_units": 1,
                "stack_cleanup": {"status": "incomplete"},
            }]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            report = write_static_hybrid_completeness_report(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest_path,
                load_image_contract=load_image,
                machine_import_profiles=[profile],
                out=root / "report.json",
            )

            self.assertEqual(report["status"], "incomplete")
            self.assertIn(
                "internal_call_return_summary_incomplete",
                {item["code"] for item in report["blockers"]},
            )

    def test_unreachable_incomplete_summary_does_not_block_rooted_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            units = [
                json.loads(line)
                for line in machine_ir.read_text(encoding="utf-8").splitlines()
            ]
            dead = json.loads(json.dumps(units[0]))
            dead["id"] = "unit:dead"
            dead["reachable"] = False
            dead["reachability"] = "confirmed_unreachable"
            dead["source"]["original"].update({
                "rva_start": 0x2000,
                "rva_end": 0x2001,
            })
            self._bind_instruction_schedule(dead)
            units.append(dead)
            manifest = self._rewrite_units(machine_ir, manifest_path, units)
            reachability = manifest["control"]["reachability"]
            reachability["confirmed_unreachable_units"] = ["unit:dead"]
            summaries = manifest["control"]["internal_call_preservation"]
            summaries["status"] = "incomplete"
            summaries["summaries"].append({
                "status": "incomplete",
                "target_unit_id": "unit:dead",
                "target_rva": 0x2000,
                "root_kind": "callee",
                "blocker_codes": ["dead_fixture_frontier"],
            })
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "complete", report["blockers"])

    def test_missing_behavioral_root_summary_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["control"]["internal_call_preservation"]["summaries"] = []
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertIn(
                "behavioral_root_summary_missing",
                {item["code"] for item in report["blockers"]},
            )

    def test_reachable_return_missing_from_summary_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["control"]["internal_call_preservation"]["summaries"] = []
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            report = write_static_hybrid_completeness_report(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest_path,
                load_image_contract=load_image,
                machine_import_profiles=[profile],
                out=root / "report.json",
            )

            self.assertIn(
                "reachable_return_not_summarized",
                {item["code"] for item in report["blockers"]},
            )

    def test_internal_summary_must_match_exact_normal_control_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            summary = manifest["control"]["internal_call_preservation"][
                "summaries"
            ][0]
            summary["reached_units"] = 99
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            blocker = next(
                item
                for item in report["blockers"]
                if item["code"] == "internal_call_return_summary_incomplete"
            )
            self.assertIn("reached_unit_count", blocker["details"]["graph_problems"])

    def test_incomplete_callback_registration_blocks_callback_family(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provenance = manifest["control"]["external_interface_provenance"]
            provenance["status"] = "incomplete"
            provenance["callback_registrations"] = [{
                "status": "incomplete",
                "unit_id": "unit:entry",
                "instruction_rva": 0x1000,
            }]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            report = write_static_hybrid_completeness_report(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest_path,
                load_image_contract=load_image,
                machine_import_profiles=[profile],
                out=root / "report.json",
            )

            self.assertIn(
                "callback_registration_incomplete",
                {item["code"] for item in report["blockers"]},
            )

    def test_omitted_direct_inventory_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["control"] = {
                "kind": "direct_jump",
                "direct_targets": [0x1000],
                "has_indirect_target": False,
            }
            unit["semantics"]["outcome"] = {
                "kind": "direct_jump",
                "target_rva": 0x1000,
            }
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            self._set_behavioral_root_nonreturning(manifest)
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            self.assertIn(
                "direct_inventory_omits_machine_ir_exit",
                {item["code"] for item in report["blockers"]},
            )

    def test_spurious_direct_inventory_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["control"]["direct_targets"] = [{
                "kind": "direct_control",
                "source_unit_id": "unit:entry",
                "source_rva": 0x1000,
                "target_rva": 0x1000,
                "guard": None,
                "status": "resolved",
                "resolved_unit_id": "unit:entry",
            }]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            self.assertIn(
                "direct_inventory_contains_spurious_exit",
                {item["code"] for item in report["blockers"]},
            )

    def test_corrupt_direct_inventory_binding_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["control"] = {
                "kind": "direct_jump",
                "direct_targets": [0x1000],
                "has_indirect_target": False,
            }
            unit["semantics"]["outcome"] = {
                "kind": "direct_jump",
                "target_rva": 0x1000,
            }
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            self._set_behavioral_root_nonreturning(manifest)
            manifest["control"]["direct_targets"] = [{
                "kind": "direct_control",
                "source_unit_id": "unit:entry",
                "source_rva": 0x1001,
                "target_rva": 0x1000,
                "guard": None,
                "status": "resolved",
                "resolved_unit_id": "unit:entry",
            }]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            self.assertIn(
                "direct_inventory_edge_binding_mismatch",
                {item["code"] for item in report["blockers"]},
            )

    def test_omitted_indirect_inventory_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            target_expression = {"op": "register", "name": "eax"}
            unit["control"] = {
                "kind": "indirect_jump",
                "direct_targets": [],
                "has_indirect_target": True,
            }
            unit["semantics"]["outcome"] = {
                "kind": "indirect_jump",
                "target": target_expression,
            }
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            self._set_behavioral_root_nonreturning(manifest)
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            self.assertIn(
                "indirect_inventory_omits_machine_ir_exit",
                {item["code"] for item in report["blockers"]},
            )

    def test_spurious_indirect_inventory_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["control"]["indirect_exits"] = [{
                "source_unit_id": "unit:entry",
                "source_rva": 0x1000,
                "kind": "indirect_jump",
                "target_expression": {"op": "register", "name": "eax"},
            }]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            self.assertIn(
                "indirect_inventory_contains_spurious_exit",
                {item["code"] for item in report["blockers"]},
            )

    def test_omitted_external_event_inventory_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = {
                "unit_id": "unit:entry",
                "unit_rva": 0x1000,
                "event_index": 0,
                "event": {
                    "kind": "external_call",
                    "dll": "kernel32.dll",
                    "symbol": "WriteFile",
                    "ordinal": None,
                },
            }
            machine_ir, manifest_path, load_image, profile = self._fixture(
                root, external_events=[event]
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["external"]["events"] = []
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            self.assertIn(
                "external_inventory_omits_machine_ir_event",
                {item["code"] for item in report["blockers"]},
            )

    def test_mixed_callback_proposals_are_normalized_before_root_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            entry = json.loads(machine_ir.read_text(encoding="utf-8"))
            callback_by_id = json.loads(json.dumps(entry))
            callback_by_id["id"] = "unit:callback-by-id"
            callback_by_id["source"]["original"] = {
                "rva_start": 0x1001,
                "rva_end": 0x1002,
            }
            callback_by_rva = json.loads(json.dumps(entry))
            callback_by_rva["id"] = "unit:callback-by-rva"
            callback_by_rva["source"]["original"] = {
                "rva_start": 0x1002,
                "rva_end": 0x1003,
            }
            manifest = self._rewrite_units(
                machine_ir,
                manifest_path,
                [entry, callback_by_id, callback_by_rva],
            )
            reachability = manifest["control"]["reachability"]
            reachability["reachable_units"] = [
                "unit:entry",
                "unit:callback-by-id",
                "unit:callback-by-rva",
            ]
            reachability["roots"] = ["unit:entry"]
            manifest["control"]["callback_cutpoint_proposals"] = [
                {"target_unit_id": "unit:callback-by-id"},
                {"rva": 0x1002},
            ]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            mismatch = next(
                item for item in report["blockers"]
                if item["code"] == "canonical_root_inventory_mismatch"
            )
            self.assertEqual(report["status"], "violated")
            self.assertEqual(
                mismatch["details"]["missing_root_unit_ids"],
                ["unit:callback-by-id", "unit:callback-by-rva"],
            )

    def test_duplicate_callback_registrations_share_one_behavioral_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["control"]["callback_cutpoint_proposals"] = [
                {"target_unit_id": "unit:entry"},
                {"rva": 0x1000},
            ]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "complete")
            self.assertEqual(
                report["families"]["rooted_control"]["status"], "satisfied"
            )

    def test_reported_fault_without_exception_inventory_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["semantics"]["faults"] = [{
                "kind": "divide_error",
                "instruction_rva": 0x1000,
            }]
            self._bind_instruction_schedule(unit)
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            manifest["control"].pop("exceptional_control")
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(
                report["families"]["exceptional_control"]["status"],
                "incomplete",
            )
            self.assertIn(
                "reachable_fault_transition_missing",
                {item["code"] for item in report["blockers"]},
            )

    def test_corrupt_exception_transition_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            fault = {"kind": "divide_error", "instruction_rva": 0x1000}
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["semantics"]["faults"] = [fault]
            self._bind_instruction_schedule(unit)
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            manifest["control"]["exceptional_control"]["transitions"] = [{
                "source_unit_id": "unit:entry",
                "source_fault_index": 0,
                "source_rva": 0x1000,
                "instruction_rva": 0x1000,
                "fault_kind": "divide_error",
                "fault_sha256": "0" * 64,
                "status": "complete",
                "disposition": {
                    "kind": "termination",
                    "observable": True,
                    "evidence": {
                        "status": "checked",
                        "checker": "test-exception-checker-v1",
                        "certificate_sha256": "1" * 64,
                    },
                },
            }]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "violated")
            self.assertIn(
                "exception_transition_fault_binding_mismatch",
                {item["code"] for item in report["blockers"]},
            )

    def test_checked_infeasible_exception_transition_is_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            fault = {"kind": "divide_error", "instruction_rva": 0x1000}
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["semantics"]["faults"] = [fault]
            self._bind_instruction_schedule(unit)
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            certificate = {
                "format": "stage-a-qf-bv-fault-infeasibility-certificate-v1",
                "source_unit_id": "unit:entry",
                "source_fault_index": 0,
                "source_contract_sha256": None,
                "fault_kind": "divide_error",
                "fault_sha256": sha256_bytes(
                    json.dumps(
                        fault, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ),
                "predicate_sha256": "1" * 64,
                "abstract_predicate_sha256": "2" * 64,
                "stateful_leaf_abstractions": [],
                "claim": "fault_condition_is_zero_for_all_machine_ir_inputs",
                "checked_claims": ["fault_condition"],
            }
            manifest["control"]["exceptional_control"]["transitions"] = [{
                "source_unit_id": "unit:entry",
                "source_fault_index": 0,
                "source_rva": 0x1000,
                "instruction_rva": 0x1000,
                "fault_kind": "divide_error",
                "fault_sha256": sha256_bytes(
                    json.dumps(
                        fault, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ),
                "status": "complete",
                "disposition": {
                    "kind": "infeasible",
                    "observable": False,
                    "evidence": {
                        "status": "checked",
                        "checker": (
                            "stage-a-machine-ir-qf-bv-fault-"
                            "infeasibility-v1"
                        ),
                        "certificate_sha256": sha256_bytes(
                            json.dumps(
                                certificate,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ),
                        "certificate": certificate,
                    },
                },
            }]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertNotIn(
                "exception_transition_incomplete",
                {item["code"] for item in report["blockers"]},
            )
            self.assertEqual(
                report["families"]["exceptional_control"]["status"],
                "satisfied",
            )

    def test_self_hashed_unknown_exception_checker_cannot_close_a_fault(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            fault = {"kind": "divide_error", "instruction_rva": 0x1000}
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["semantics"]["faults"] = [fault]
            self._bind_instruction_schedule(unit)
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            certificate = {
                "format": "invented-seh-certificate-v1",
                "source_unit_id": "unit:entry",
                "source_fault_index": 0,
            }
            manifest["control"]["exceptional_control"]["transitions"] = [{
                "source_unit_id": "unit:entry",
                "source_fault_index": 0,
                "source_rva": 0x1000,
                "instruction_rva": 0x1000,
                "fault_kind": "divide_error",
                "fault_sha256": sha256_bytes(
                    json.dumps(
                        fault, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ),
                "status": "complete",
                "disposition": {
                    "kind": "seh_transition",
                    "target_unit_id": "unit:entry",
                    "target_rva": 0x1000,
                    "evidence": {
                        "status": "checked",
                        "checker": "invented-self-hash-checker-v1",
                        "certificate_sha256": sha256_bytes(
                            json.dumps(
                                certificate,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ),
                        "certificate": certificate,
                    },
                },
            }]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertIn(
                "exception_transition_incomplete",
                {item["code"] for item in report["blockers"]},
            )

    def test_corrupt_infeasibility_certificate_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            fault = {"kind": "divide_error", "instruction_rva": 0x1000}
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["semantics"]["faults"] = [fault]
            self._bind_instruction_schedule(unit)
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            manifest["control"]["exceptional_control"]["transitions"] = [{
                "source_unit_id": "unit:entry",
                "source_fault_index": 0,
                "source_rva": 0x1000,
                "instruction_rva": 0x1000,
                "fault_kind": "divide_error",
                "fault_sha256": sha256_bytes(
                    json.dumps(
                        fault, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ),
                "status": "complete",
                "disposition": {
                    "kind": "infeasible",
                    "observable": False,
                    "evidence": {
                        "status": "checked",
                        "checker": "fixture-infeasibility-checker-v1",
                        "certificate_sha256": "0" * 64,
                        "certificate": {"claim": "infeasible"},
                    },
                },
            }]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertIn(
                "exception_transition_incomplete",
                {item["code"] for item in report["blockers"]},
            )

    def test_indirect_external_jump_transfer_kind_mismatch_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_expression = {"op": "register", "name": "eax"}
            event = {
                "unit_id": "unit:entry",
                "unit_rva": 0x1000,
                "event_index": 0,
                "event": {
                    "kind": "indirect_jump",
                    "instruction_rva": 0x1000,
                    "target": target_expression,
                },
            }
            machine_ir, manifest_path, load_image, profile = self._fixture(
                root, external_events=[event]
            )
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["control"] = {
                "kind": "indirect_jump",
                "direct_targets": [],
                "has_indirect_target": False,
            }
            unit["semantics"]["outcome"] = {"kind": "indirect_jump"}
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            self._set_behavioral_root_nonreturning(manifest)
            canonical_event = {
                **event,
                "kind": "indirect_jump",
                "instruction_rva": 0x1000,
                "dll": None,
                "symbol": None,
                "ordinal": None,
            }
            manifest["external"]["events"] = [canonical_event]
            manifest["control"]["indirect_exits"] = [{
                "source_unit_id": "unit:entry",
                "source_rva": 0x1000,
                "source_event_index": 0,
                "kind": "indirect_jump",
                "target_expression": target_expression,
                "closure": "checked_finite_target_inventory",
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [{
                    "argument_words": 4,
                    "external_protocol": {
                        "kind": "pe32-resolved-export",
                        "transfer_kind": "call",
                        "target": {
                            "dll": "user32.dll",
                            "symbol": "MessageBoxA",
                        },
                        "machine_contract": {
                            "import": {
                                "dll": "user32.dll",
                                "symbol": "MessageBoxA",
                            },
                            "arity": {"kind": "fixed", "words": 4},
                            "effect_model": {
                                "kind": "exact_native_dll_callthrough_v1",
                                "prerequisites": {
                                    "same_pinned_dll_implementation": True,
                                    "exact_machine_arguments": True,
                                    "candidate_address_space_used_directly": True,
                                },
                            },
                            "memory_effect": "nativeCallthrough",
                            "world_effect": "nativeCallthrough",
                            "callback_effect": "none",
                        },
                    },
                }],
            }]
            imported = {"dll": "user32.dll", "symbol": "MessageBoxA"}
            manifest["control"]["external_interface_provenance"]["resolutions"] = [{
                "source_unit_id": "unit:entry",
                "source_rva": 0x1000,
                "source_event_index": 0,
                "kind": "indirect_jump",
                "target_expression": target_expression,
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [{
                    "argument_words": 4,
                    "external_protocol": {
                        "kind": "pe32-resolved-export",
                        "transfer_kind": "call",
                        "target": imported,
                        "machine_contract": {
                            "import": imported,
                            "arity": {"kind": "fixed", "words": 4},
                            "effect_model": {
                                "kind": "exact_native_dll_callthrough_v1",
                                "prerequisites": {
                                    "same_pinned_dll_implementation": True,
                                    "exact_machine_arguments": True,
                                    "candidate_address_space_used_directly": True,
                                },
                            },
                            "memory_effect": "nativeCallthrough",
                            "world_effect": "nativeCallthrough",
                            "callback_effect": "none",
                        },
                    },
                }],
            }]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            self.assertEqual(report["status"], "incomplete")
            self.assertIn(
                "resolved_export_effects_incomplete",
                {item["code"] for item in report["blockers"]},
            )

    def test_unknown_external_event_kind_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = {
                "kind": "future_callback_dispatch",
                "instruction_rva": 0x1000,
            }
            event = {
                "unit_id": "unit:entry",
                "unit_rva": 0x1000,
                "event_index": 0,
                "kind": payload["kind"],
                "instruction_rva": 0x1000,
                "dll": None,
                "symbol": None,
                "ordinal": None,
                "event": payload,
            }
            machine_ir, manifest, load_image, profile = self._fixture(
                root, external_events=[event]
            )

            report = self._report(
                root, machine_ir, manifest, load_image, profile
            )

            self.assertEqual(report["status"], "incomplete")
            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "external_event_kind_unsupported"
            )
            self.assertEqual(
                blocker["details"]["event_kind"], "future_callback_dispatch"
            )

    def test_internal_rep_event_does_not_require_a_machine_abi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = {
                "kind": "rep_scas",
                "instruction_rva": 0x1000,
            }
            event = {
                "unit_id": "unit:entry",
                "unit_rva": 0x1000,
                "event_index": 0,
                "kind": payload["kind"],
                "instruction_rva": 0x1000,
                "dll": None,
                "symbol": None,
                "ordinal": None,
                "event": payload,
            }
            machine_ir, manifest, load_image, profile = self._fixture(
                root, external_events=[event]
            )

            report = self._report(
                root, machine_ir, manifest, load_image, profile
            )

            self.assertNotIn(
                "external_event_kind_unsupported",
                {item["code"] for item in report["blockers"]},
            )

    def test_global_interface_provenance_must_be_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provenance = manifest["control"]["external_interface_provenance"]
            provenance["status"] = "incomplete"
            provenance["fixed_point"]["converged"] = False
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root, machine_ir, manifest_path, load_image, profile
            )

            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "external_interface_provenance_incomplete"
            )
            self.assertEqual(blocker["details"]["mismatches"], ["fixed_point"])

    def test_callback_registration_requires_exact_rva_unit_pairing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            interface_profile = self._write_interface_profile(
                root, explicit_callback=True
            )
            _target, manifest = self._install_interface_target(
                machine_ir,
                manifest_path,
                interface_profile,
                include_callback_registration=True,
            )
            registration = manifest["control"]["external_interface_provenance"][
                "callback_registrations"
            ][0]
            registration["target_rvas"] = [0x1001]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root,
                machine_ir,
                manifest_path,
                load_image,
                profile,
                (interface_profile,),
            )

            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "callback_registration_not_canonical"
            )
            self.assertIn("target_pairing", blocker["details"]["mismatches"])

    def test_previous_callback_protocol_needs_prior_registration_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            interface_profile = self._write_interface_profile(
                root, explicit_callback=False
            )
            target, manifest = self._install_interface_target(
                machine_ir,
                manifest_path,
                interface_profile,
                include_callback_registration=False,
            )
            typed_profile = load_external_interface_profile(interface_profile)
            callback_abi = {
                "kind": "generic_callback",
                "argument_words": 2,
                "stack_cleanup_bytes": 8,
                "nullable": True,
            }
            previous = {
                "external_protocol": {
                    "kind": "pe32-previous-callback",
                    "contract_id": "invented-registration",
                    "profile_binding": {
                        "profile_id": typed_profile.profile_id,
                        "profile_sha256": typed_profile.sha256,
                    },
                    "callback_abi": callback_abi,
                    "callback_lifetime": "until_replaced_or_process_exit",
                    "effect_model": "same-process-callback-callthrough-v1",
                },
                "abi": target["abi"],
                "argument_words": 2,
            }
            resolution = manifest["control"]["external_interface_provenance"][
                "resolutions"
            ][0]
            resolution["origin_kinds"] = ["callback_token"]
            resolution["external_targets"] = [previous]
            manifest["control"]["indirect_exits"][0]["external_targets"] = [
                previous
            ]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root,
                machine_ir,
                manifest_path,
                load_image,
                profile,
                (interface_profile,),
            )

            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "previous_callback_effects_incomplete"
            )
            self.assertIn(
                "prior_registration.missing", blocker["details"]["mismatches"]
            )

    def test_returning_indirect_external_derives_site_from_exact_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            interface_profile = self._write_interface_profile(
                root, explicit_callback=False
            )
            self._install_interface_target(
                machine_ir,
                manifest_path,
                interface_profile,
                include_callback_registration=False,
            )
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["semantics"]["external_events"][0].pop("abi_contract")
            self._bind_instruction_schedule(unit)
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            manifest["external"]["events"][0]["event"] = unit["semantics"][
                "external_events"
            ][0]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root,
                machine_ir,
                manifest_path,
                load_image,
                profile,
                (interface_profile,),
            )

            self.assertNotIn(
                "indirect_external_site_contract_incomplete",
                {item["code"] for item in report["blockers"]},
            )
            self.assertEqual(report["counts"]["effect_complete_calls"], 1)

    def test_returning_indirect_external_needs_rooted_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, manifest_path, load_image, profile = self._fixture(root)
            interface_profile = self._write_interface_profile(
                root, explicit_callback=False
            )
            self._install_interface_target(
                machine_ir,
                manifest_path,
                interface_profile,
                include_callback_registration=False,
            )
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            unit["semantics"]["external_events"][0]["return_rva"] = 0x1001
            self._bind_instruction_schedule(unit)
            manifest = self._rewrite_units(machine_ir, manifest_path, [unit])
            manifest["external"]["events"][0]["event"] = unit["semantics"][
                "external_events"
            ][0]
            self._write_manifest(manifest_path, manifest)

            report = self._report(
                root,
                machine_ir,
                manifest_path,
                load_image,
                profile,
                (interface_profile,),
            )

            blocker = next(
                item for item in report["blockers"]
                if item["code"] == "indirect_external_site_contract_incomplete"
            )
            self.assertIn(
                "return_rva has no rooted reachable continuation",
                blocker["details"]["problems"],
            )


if __name__ == "__main__":
    unittest.main()
