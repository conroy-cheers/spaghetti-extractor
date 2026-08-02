from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifact_formats import (
    COMPONENT_EVIDENCE_FORMAT,
    COMPONENT_REFINEMENT_FORMAT,
    COMPONENT_WORKSPACE_FORMAT,
    COMPONENT_SLICE_FORMAT,
)
from spaghetti_extractor.component_workspace import (
    _canonical_sha256,
    _cbmc_violations,
    _enforce_portable_symbol,
    _load_component_slice,
    qualify_component,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file, write_json


class ComponentWorkspaceTests(unittest.TestCase):
    def test_component_slice_is_self_bound_and_requires_all_machine_units(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "slice.json"
            core = {
                "format": COMPONENT_SLICE_FORMAT,
                "status": "checked",
                "executes_original_binary": False,
                "component_id": "worker",
                "bindings": {
                    "catalog_artifact_sha256": "a" * 64,
                    "reconstruction_plan_sha256": "b" * 64,
                    "machine_ir_sha256": "c" * 64,
                },
                "component": {
                    "id": "worker",
                    "membership": {"resolved_unit_ids": ["unit:a", "unit:b"]},
                },
                "cluster": {
                    "id": "cluster:worker",
                    "entry_unit_id": "unit:a",
                    "unit_ids": ["unit:a"],
                },
                "units": [{"id": "unit:a"}, {"id": "unit:b"}],
            }
            write_json(path, {**core, "slice_sha256": _canonical_sha256(core)})
            self.assertEqual(_load_component_slice(path, "worker")["component_id"], "worker")

            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["units"] = [{"id": "unit:a"}]
            payload.pop("slice_sha256")
            payload["slice_sha256"] = _canonical_sha256(payload)
            write_json(path, payload)
            with self.assertRaisesRegex(StageAInputError, "omits required"):
                _load_component_slice(path, "worker")

    def test_portable_symbol_rebinding_is_component_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "implementation.c"
            source.write_text(
                "bool reconstruct_region(void *a, void *b) { return a == b; }\n",
                encoding="ascii",
            )
            _enforce_portable_symbol(
                source, "component_00001050_reconstruct_region"
            )
            text = source.read_text(encoding="ascii")
            self.assertIn("component_00001050_reconstruct_region", text)
            self.assertNotIn("bool reconstruct_region", text)

    def test_cbmc_failure_retains_source_location(self) -> None:
        report = json.dumps(
            [
                {
                    "result": [
                        {
                            "property": "main.assertion.1",
                            "status": "FAILURE",
                            "description": "wrong result",
                            "sourceLocation": {
                                "file": "implementation.c",
                                "line": "17",
                                "function": "main",
                            },
                        }
                    ]
                }
            ]
        )
        self.assertEqual(
            _cbmc_violations(report),
            [
                {
                    "property": "main.assertion.1",
                    "description": "wrong result",
                    "location": {
                        "file": "implementation.c",
                        "line": "17",
                        "function": "main",
                    },
                }
            ],
        )

    def test_qualification_rejects_modified_generated_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "contract").mkdir()
            source = root / "src" / "implementation.c"
            header = root / "src" / "implementation.h"
            adapter = root / "src" / "replacement.c"
            adapter_reference = root / "contract" / "generated-machine-adapter.c"
            source.write_text("int component(void) { return 0; }\n", encoding="ascii")
            header.write_text("int component(void);\n", encoding="ascii")
            adapter.write_text("int adapter(void) { return 0; }\n", encoding="ascii")
            adapter_reference.write_text(adapter.read_text(encoding="ascii"), encoding="ascii")
            manifest = {
                "format": "stage-b-region-replacement-v2",
                "manifest_sha256": "manifest-binding",
            }
            write_json(root / "region-replacement.json", manifest)
            refinement_core = {
                "format": COMPONENT_REFINEMENT_FORMAT,
                "status": "checked",
                "portable_symbol": "component",
                "machine_projection": {"status": "checked", "call_closure": {}},
                "adapter_effect_plan": {"internal_call_frames": []},
                "bindings": {
                    "generated_adapter_sha256": sha256_file(adapter),
                    "portable_source_sha256": sha256_file(source),
                },
            }
            refinement = {
                **refinement_core,
                "refinement_sha256": _canonical_sha256(refinement_core),
            }
            write_json(root / "contract" / "component-refinement.json", refinement)
            workspace_core = {
                "format": COMPONENT_WORKSPACE_FORMAT,
                "status": "editable",
                "component_id": "test-component",
                "proof_profile": "compare_branch_v1",
                "bindings": {"refinement_sha256": refinement["refinement_sha256"]},
                "files": {
                    "refinement": "contract/component-refinement.json",
                    "portable_source": "src/implementation.c",
                    "portable_header": "src/implementation.h",
                    "machine_adapter_source": "src/replacement.c",
                    "generated_adapter_reference": "contract/generated-machine-adapter.c",
                    "replacement_manifest": "region-replacement.json",
                },
                "activation": {"status": "blocked_pending_qualification"},
            }
            workspace = {
                **workspace_core,
                "workspace_sha256": _canonical_sha256(workspace_core),
            }
            write_json(root / "component-workspace.json", workspace)
            evidence = {
                "format": COMPONENT_EVIDENCE_FORMAT,
                "status": "satisfied",
                "bindings": {
                    "portable_source_sha256": sha256_file(source),
                    "refinement_sha256": refinement["refinement_sha256"],
                },
            }
            evidence_path = root / "source-evidence.json"
            write_json(evidence_path, evidence)
            write_json(
                root / "validation-report.json",
                {
                    "status": "qualified",
                    "bindings": {
                        "replacement_manifest_sha256": "manifest-binding"
                    },
                },
            )

            qualified = qualify_component(
                workspace=root,
                source_evidence=evidence_path,
                out=root / "qualification.json",
            )
            self.assertEqual(qualified["status"], "qualified")

            adapter.write_text("int adapter(void) { return 1; }\n", encoding="ascii")
            rejected = qualify_component(
                workspace=root,
                source_evidence=evidence_path,
                out=root / "qualification-tampered.json",
            )
            self.assertEqual(rejected["status"], "incomplete")
            generated = next(
                item for item in rejected["checks"] if item["family"] == "generated_adapter"
            )
            self.assertEqual(generated["observed"], "modified")


if __name__ == "__main__":
    unittest.main()
