from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.boundary import BoundarySchemaV1, TargetDataLayoutV1
from spaghetti_extractor.calls.frame import PhysicalCallFrameV3
from spaghetti_extractor.calls.dialects.ia32 import IA32DialectCheckerV1
from spaghetti_extractor.external.environment import (
    ExternalEnvironmentError,
    ResolvedExternalEnvironmentV1,
    _canonical_runtime_support_requirements,
    lower_machine_import_boundary_v1,
    write_external_environment_intent,
    write_resolved_external_environment,
)
from spaghetti_extractor.external.formats import (
    EXTERNAL_ENVIRONMENT_ANALYSIS_PROJECTION_FORMAT,
    EXTERNAL_ENVIRONMENT_INTENT_FORMAT,
    RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
)
from spaghetti_extractor.external.machine_import_profiles import (
    load_machine_import_profile_set,
)
from spaghetti_extractor.external.machine_callback_boundary import (
    MachineCallbackBoundaryError,
    machine_callback_boundary_catalog_v1,
)
from spaghetti_extractor.semantic_link.capabilities import (
    semantic_export_capabilities_v1,
)
from spaghetti_extractor.util import write_json
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit,
    transfer_row,
    write_fixture_transfer_plan,
)


TESTKIT = {
    "resources": (
        "profiles/pe32-msvcrt-lockstep-v1.json",
        "profiles/pe32-msvcrt-machine-runtime-v1.json",
        "profiles/pe32-win32-console-launch-assumptions-v1.json",
        "profiles/pe32-win32-windowing-runtime-v1.json",
        "targets/dxball/intent/boundaries.json",
    )
}


def _write_checked_schema_package(spec_path: Path, out: Path) -> None:
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    schema = BoundarySchemaV1.create(
        schema_id=spec["schema_id"],
        types=spec["types"],
        signatures=spec["signatures"],
    )
    layout_row = spec["layout"]
    layout = TargetDataLayoutV1.create(
        target=layout_row["target"],
        abi_dialect=layout_row["abi_dialect"],
        byte_order=layout_row["byte_order"],
        pointer_width_bits=layout_row["pointer_width_bits"],
        packing=layout_row["packing"],
        schema=schema,
        layouts=layout_row["layouts"],
    )
    checker = IA32DialectCheckerV1(layout.abi_dialect)
    out.mkdir(parents=True)
    write_json(out / "boundary-schema.json", schema.to_payload())
    write_json(out / "target-data-layout.json", layout.to_payload())
    frame_ids = []
    for row in spec["frames"]:
        frame = checker.lower_boundary(
            subject=row["subject"],
            schema=schema,
            layout=layout,
            signature_id=row["signature_id"],
            transfer_kind=row["transfer_kind"],
        )
        write_json(
            out / f"physical-call-frame-{row['id']}.json",
            frame.to_payload(),
        )
        frame_ids.append(frame.frame_id)
    write_json(out / "boundary-status.json", {
        "format": "spaghetti-extractor-boundary-check-result-v1",
        "status": "complete",
        "schema_id": schema.schema_id,
        "schema_sha256": schema.schema_sha256,
        "layout_sha256": layout.layout_sha256,
        "frames": frame_ids,
    })

class ExternalEnvironmentResolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).parents[3]
        cls.runtime_profile = (
            cls.root / "profiles/pe32-msvcrt-machine-runtime-v1.json"
        )
        cls.launch_profile = (
            cls.root
            / "profiles/pe32-win32-console-launch-assumptions-v1.json"
        )

    def test_interface_pack_factory_contract_resolves_ordinary_import(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime_payload = json.loads(
                (
                    self.root / "profiles/pe32-msvcrt-lockstep-v1.json"
                ).read_text(encoding="utf-8")
            )
            factory_contract = next(
                dict(row)
                for row in runtime_payload["machine_import_call_contracts"]
                if row["import"].get("symbol") == "__getmainargs"
            )
            factory_contract["id"] = "fixture-interface-factory"
            factory_contract["import"] = {
                "dll": "fixture-interface.dll",
                "symbol": "CreateFixtureInterface",
            }
            interface_profile = root / "interface-profile.json"
            write_json(interface_profile, {
                "format": "spaghetti-extractor-external-interface-profile-v1",
                "status": "complete",
                "id": "fixture-interface-profile",
                "model": "x86-pe32",
                "provenance": {},
                "factories": [],
                "interfaces": [],
                "machine_import_call_contracts": [factory_contract],
            })
            write_external_environment_intent(
                environment_id="fixture",
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[interface_profile],
                launch_profile=self.launch_profile,
                boundary_intents={},
                process_termination=None,
                target_abi="pe32-i686-mingw32",
                target_data_layout="pe32-ilp32-v1",
                out=root / "intent",
            )
            module = {
                "format": "spaghetti-extractor-pe32-module-interface-v2",
                "status": "complete",
                "identity": {"pe_sha256": "0" * 64},
                "imports": [{
                    "dll": "fixture-interface.dll",
                    "symbol": "CreateFixtureInterface",
                    "ordinal": None,
                    "descriptor_index": 0,
                    "cell_index": 0,
                    "iat_rva": 4096,
                }],
                "delay_imports": [],
                "blockers": [],
            }
            module["interface_sha256"] = canonical_sha256_v3(module)
            module_path = root / "module-interface.json"
            write_json(module_path, module)
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(as_machine_ir_unit(transfer_row()), sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            transfer_plan = write_fixture_transfer_plan(machine_ir)
            resolved = write_resolved_external_environment(
                intent_path=root / "intent/external-environment-intent.json",
                module_interface_path=module_path,
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[interface_profile],
                boundary_intent_paths={},
                boundary_packages={},
                static_authority_paths={
                    "executable_transfer_plan": transfer_plan,
                },
                out=root / "resolved",
            )
        self.assertEqual(resolved["status"], "complete")
        self.assertEqual(resolved["blockers"], [])
        self.assertEqual(
            resolved["original_semantic_imports"][0]["contract"]["profile_id"],
            "fixture-interface-profile",
        )
        self.assertEqual(
            resolved["original_semantic_imports"][0]["boundary"]
            ["physical_call_frame_v3"]["transport"]["transfer_kind"],
            "import",
        )

    def test_unstable_boundary_subject_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ExternalEnvironmentError, "kind:id"):
                write_external_environment_intent(
                    environment_id="fixture",
                    runtime_profile_packs=[self.runtime_profile],
                    interface_profile_packs=[],
                    launch_profile=self.launch_profile,
                    boundary_intents={"untyped": self.launch_profile},
                    process_termination=None,
                    target_abi="pe32-i686-mingw32",
                    target_data_layout="pe32-ilp32-v1",
                    out=Path(temporary),
                )

    def test_exception_escape_support_is_derived_from_canonical_transfer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_external_environment_intent(
                environment_id="fixture",
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[],
                launch_profile=self.launch_profile,
                boundary_intents={},
                process_termination=None,
                target_abi="pe32-i686-mingw32",
                target_data_layout="pe32-ilp32-v1",
                out=root / "intent",
            )
            module = {
                "format": "spaghetti-extractor-pe32-module-interface-v2",
                "status": "complete",
                "identity": {"pe_sha256": "0" * 64},
                "imports": [],
                "delay_imports": [],
                "blockers": [],
            }
            module["interface_sha256"] = canonical_sha256_v3(module)
            module_path = root / "module-interface.json"
            write_json(module_path, module)
            row = transfer_row()
            row["faults"] = [{
                "kind": "divide_error",
                "condition": {"op": "true"},
            }]
            row["ordered_events"] = [{
                "family": "fault",
                "kind": "divide_error",
                "condition": {"op": "true"},
            }]
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(as_machine_ir_unit(row), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            transfer_plan = write_fixture_transfer_plan(machine_ir)
            resolved = write_resolved_external_environment(
                intent_path=root / "intent/external-environment-intent.json",
                module_interface_path=module_path,
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[],
                boundary_intent_paths={},
                boundary_packages={},
                static_authority_paths={
                    "executable_transfer_plan": transfer_plan,
                },
                out=root / "resolved",
            )
        support = resolved["generated_runtime_support_imports"]
        self.assertEqual(len(support), 1)
        self.assertEqual(support[0]["support"], "exception_escape")
        self.assertEqual(support[0]["identity"], {
            "dll": "kernel32.dll",
            "symbol": "RaiseException",
            "ordinal": None,
        })
        self.assertIsNotNone(support[0]["contract"])
        self.assertIsNotNone(support[0]["boundary"])

    def test_resolution_rejects_stale_intent_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            intent, _projection = write_external_environment_intent(
                environment_id="fixture",
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[],
                launch_profile=self.launch_profile,
                boundary_intents={},
                process_termination=None,
                target_abi="pe32-i686-mingw32",
                target_data_layout="pe32-ilp32-v1",
                out=root,
            )
            intent["id"] = "tampered"
            write_json(root / "external-environment-intent.json", intent)
            with self.assertRaisesRegex(ExternalEnvironmentError, "hash is stale"):
                write_resolved_external_environment(
                    intent_path=root / "external-environment-intent.json",
                    module_interface_path=root / "missing.json",
                    runtime_profile_packs=[self.runtime_profile],
                    interface_profile_packs=[],
                    boundary_intent_paths={},
                    boundary_packages={},
                    static_authority_paths={"final": root / "missing.json"},
                    out=root / "resolved",
                )
