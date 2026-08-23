from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_export_image, pe32_import_image

from spaghetti_extractor.artifacts.formats import (
    PE32_LOAD_OBSERVATION_FORMAT,
    PE32_MODULE_DEPLOYMENT_FORMAT,
    PE32_PROJECT_INTENT_FORMAT,
)
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.project import (
    write_pe32_module_interface,
    write_pe32_observed_load_graph,
    write_pe32_project_completion,
    write_pe32_project_load_plan,
)
from spaghetti_extractor.roundtrip_fuzz.image_io import write_spx_load_image_contract
from spaghetti_extractor.errors import ToolkitInputError


class MultiImageProjectTests(unittest.TestCase):
    def test_duplicate_slots_resolve_to_one_target_export_without_collapsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            importer = root / "app.exe"
            provider = root / "private.dll"
            importer.write_bytes(
                pe32_import_image(
                    b"\xc3", symbol="Ping", dll="private.dll", cell_count=2
                )
            )
            provider.write_bytes(
                pe32_export_image(b"\xc3", symbol="Ping", dll="private.dll")
            )
            app_contract = root / "app-load.json"
            dll_contract = root / "dll-load.json"
            write_spx_load_image_contract(original_pe=importer, out=app_contract)
            write_spx_load_image_contract(original_pe=provider, out=dll_contract)
            app_interface = root / "app-interface"
            dll_interface = root / "dll-interface"
            write_pe32_module_interface(
                image_id="app", original_pe=importer,
                load_image_contract=app_contract, out=app_interface,
            )
            write_pe32_module_interface(
                image_id="private", original_pe=provider,
                load_image_contract=dll_contract, out=dll_interface,
            )
            intent = root / "project-intent.json"
            intent.write_text(json.dumps({
                "format": PE32_PROJECT_INTENT_FORMAT,
                "project_id": "fixture",
                "root_image_id": "app",
                "images": [
                    {
                        "image_id": "app", "filename": "app.exe", "aliases": [],
                        "ownership": "target", "implementation": "behavioral_c",
                    },
                    {
                        "image_id": "private", "filename": "private.dll", "aliases": [],
                        "ownership": "target", "implementation": "behavioral_c",
                    },
                    {
                        "image_id": "msvcrt", "filename": "msvcrt.dll", "aliases": [],
                        "ownership": "runtime", "implementation": "native_host",
                    },
                ],
                "target_distribution_roots": ["bin"],
                "host_environment": {"id": "wine", "sha256": "1" * 64},
            }, sort_keys=True), encoding="utf-8")
            plan_root = root / "plan"
            plan = write_pe32_project_load_plan(
                intent=intent,
                module_interfaces={
                    "app": app_interface / "module-interface.json",
                    "private": dll_interface / "module-interface.json",
                },
                out=plan_root,
            )

            self.assertEqual(plan["status"], "complete")
            self.assertEqual(plan["counts"]["images"], 3)
            self.assertIsNone(
                next(row for row in plan["images"] if row["image_id"] == "msvcrt")
                ["interface_sha256"]
            )
            self.assertEqual(len(plan["edges"]), 2)
            self.assertEqual(len({row["slot_id"] for row in plan["edges"]}), 2)
            self.assertEqual(
                {row["resolution"]["provider_image_id"] for row in plan["edges"]},
                {"private"},
            )

            deployments: dict[str, Path] = {}
            candidate_hashes = {"app": "4" * 64, "private": "5" * 64}
            for image_id in ("app", "private"):
                path = root / f"{image_id}-deployment.json"
                deployment = {
                    "format": PE32_MODULE_DEPLOYMENT_FORMAT,
                    "status": "complete",
                    "image_id": image_id,
                    "module_kind": "exe" if image_id == "app" else "dll",
                    "candidate": {
                        "filename": "app.exe" if image_id == "app" else "private.dll",
                        "sha256": candidate_hashes[image_id],
                        "decoded_loader_surface_sha256": "6" * 64,
                    },
                    "bindings": {
                        key: {"filename": f"{key}.json", "sha256": "7" * 64}
                        for key in (
                            "original_interface", "behavioral_c_completion",
                            "ingress_plan", "link_receipt",
                            "exact_runtime_qualification", "loader_surface",
                            "static_assurance", "candidate_interface",
                        )
                    },
                    "original_identity": {},
                    "decoded_loader_surface": {
                        "kind": "exe" if image_id == "app" else "dll",
                        "loader": {}, "export_directory": {}, "tls": None,
                        "imports": [], "load_config": None,
                    },
                    "blockers": [],
                    "definition_of_complete": "fixture deployment is complete",
                }
                deployment["deployment_sha256"] = canonical_sha256_v3(deployment)
                path.write_text(json.dumps(deployment), encoding="utf-8")
                deployments[image_id] = path
            observation = root / "observation.json"
            observation.write_text(json.dumps({
                "format": PE32_LOAD_OBSERVATION_FORMAT,
                "project_id": "fixture",
                "environment_sha256": "1" * 64,
                "runner_sha256": "2" * 64,
                "trace_sha256": "3" * 64,
                "process_exit_code": 0,
                "modules": [
                    {
                        "loader_name": "app.exe",
                        "resolved_path": "C:/fixture/app.exe",
                        "sha256": "4" * 64,
                        "origin": "target_distribution",
                        "image_id": "app",
                    },
                    {
                        "loader_name": "private.dll",
                        "resolved_path": "C:/fixture/private.dll",
                        "sha256": "5" * 64,
                        "origin": "target_distribution",
                        "image_id": "private",
                    },
                ],
                "slots": [
                    {
                        "slot_id": edge["slot_id"],
                        "resolution": {
                            "kind": "target_image",
                            "provider_image_id": "private",
                        },
                    }
                    for edge in plan["edges"]
                ],
            }), encoding="utf-8")
            observed_root = root / "observed"
            observed = write_pe32_observed_load_graph(
                load_plan=plan_root / "project-load-plan.json",
                observation=observation,
                out=observed_root,
            )
            self.assertEqual(observed["status"], "qualified")
            completion = write_pe32_project_completion(
                load_plan=plan_root / "project-load-plan.json",
                module_deployments=deployments,
                observed_load_graph=observed_root / "observed-load-graph.json",
                out=root / "completion",
            )
            self.assertEqual(completion["status"], "complete")
            self.assertEqual(completion["blockers"], [])

            minimal_path = root / "minimal-deployment.json"
            minimal = {
                "format": PE32_MODULE_DEPLOYMENT_FORMAT,
                "status": "complete", "image_id": "app",
                "candidate": {"sha256": candidate_hashes["app"]},
            }
            minimal["deployment_sha256"] = canonical_sha256_v3(minimal)
            minimal_path.write_text(json.dumps(minimal), encoding="utf-8")
            with self.assertRaisesRegex(
                ToolkitInputError, "incomplete deployment surface"
            ):
                write_pe32_project_completion(
                    load_plan=plan_root / "project-load-plan.json",
                    module_deployments={**deployments, "app": minimal_path},
                    observed_load_graph=(
                        observed_root / "observed-load-graph.json"
                    ),
                    out=root / "minimal-completion",
                )

            next(
                row for row in plan["images"] if row["image_id"] == "private"
            )["implementation"] = "native_host"
            plan["plan_sha256"] = canonical_sha256_v3({
                key: value for key, value in plan.items() if key != "plan_sha256"
            })
            native_plan = root / "native-project-plan.json"
            native_plan.write_text(json.dumps(plan), encoding="utf-8")
            incomplete = write_pe32_project_completion(
                load_plan=native_plan,
                module_deployments=deployments,
                observed_load_graph=observed_root / "observed-load-graph.json",
                out=root / "incomplete",
            )
            self.assertEqual(incomplete["status"], "incomplete")
            self.assertIn(
                "target_image_not_lifted",
                {row["category"] for row in incomplete["blockers"]},
            )


if __name__ == "__main__":
    unittest.main()
