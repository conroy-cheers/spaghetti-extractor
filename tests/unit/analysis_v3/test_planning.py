from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.analysis_v3._schema import AnalysisV3Error
from spaghetti_extractor.analysis_v3.planning import (
    DEFAULT_RESOURCE_CLASSES_V3,
    prepare_dependency_boundary_v3,
    prepare_scheduling_boundaries_v3,
    prepare_structural_boundary_v3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactV3Error,
    StructuralSchedulingManifestV3,
    StructuralUnitPlanV3,
    canonical_json_bytes_v3,
)


def _write(path: Path, value: object) -> None:
    path.write_bytes(canonical_json_bytes_v3(value))


def _inventory() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-structural-inventory-v3",
        "universe_sha256": "a" * 64,
        "units": [
            {
                "unit_id": "unit:a",
                "start": 0x1000,
                "end": 0x1010,
                "dependencies": ["unit:b"],
                "resource_class": "small",
            },
            {
                "unit_id": "unit:b",
                "start": 0x1010,
                "end": 0x1020,
                "dependencies": ["unit:a"],
                "resource_class": "medium",
            },
            {
                "unit_id": "unit:c",
                "start": 0x1020,
                "end": 0x1030,
                "dependencies": [],
                "resource_class": "small",
            },
        ],
    }


def _edges() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-record-edges-v3",
        "nodes": [
            {
                "node_id": "unit:a",
                "dependencies": ["unit:b"],
                "records": [],
                "resource_class": "small",
            },
            {
                "node_id": "unit:b",
                "dependencies": ["unit:a"],
                "records": [],
                "resource_class": "medium",
            },
            {
                "node_id": "unit:c",
                "dependencies": [],
                "records": [],
                "resource_class": "small",
            },
        ],
    }


class CheckedPlanningV3Tests(unittest.TestCase):
    def _inputs(self, root: Path) -> tuple[Path, Path]:
        inventory = root / "inventory.json"
        edges = root / "edges.json"
        _write(inventory, _inventory())
        _write(edges, _edges())
        return inventory, edges

    def test_combined_planner_is_byte_identical_to_standalone_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory, edges = self._inputs(root)
            combined_root = root / "combined"
            descriptor = prepare_scheduling_boundaries_v3(
                structural_inventory=inventory,
                record_edges=edges,
                output_directory=combined_root / "boundaries",
                schedule_bucket_count=4,
            )
            standalone_structural = prepare_structural_boundary_v3(
                inventory=inventory,
                output_directory=root / "standalone-structural",
                resource_classes=DEFAULT_RESOURCE_CLASSES_V3,
                schedule_bucket_count=4,
            )
            prepare_dependency_boundary_v3(
                structural_schedule=standalone_structural.output_directory
                / "schedule.json",
                record_edges=edges,
                output_directory=root / "standalone-dependency",
                schedule_bucket_count=4,
            )

            self.assertEqual(
                descriptor["format"],
                "spaghetti-extractor-scheduling-boundaries-v3",
            )
            for family in ("structural", "dependency"):
                combined = combined_root / "boundaries" / family
                standalone = root / f"standalone-{family}"
                self.assertEqual(
                    sorted(path.relative_to(combined) for path in combined.rglob("*")),
                    sorted(path.relative_to(standalone) for path in standalone.rglob("*")),
                )
                for path in combined.rglob("*"):
                    if path.is_file():
                        self.assertEqual(
                            path.read_bytes(),
                            (standalone / path.relative_to(combined)).read_bytes(),
                        )

    def test_submitted_schedule_omission_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory, _edges_path = self._inputs(root)
            checked = prepare_structural_boundary_v3(
                inventory=inventory,
                output_directory=root / "checked",
                resource_classes=DEFAULT_RESOURCE_CLASSES_V3,
            )
            payload = json.loads(
                (checked.output_directory / "schedule.json").read_text(encoding="ascii")
            )
            incomplete = StructuralSchedulingManifestV3.create(
                payload["universe_sha256"],
                (
                    StructuralUnitPlanV3.parse(row)
                    for row in payload["units"][:-1]
                ),
            )
            corrupt = root / "corrupt-schedule.json"
            corrupt.write_bytes(incomplete.to_bytes())

            with self.assertRaises(ArtifactV3Error) as raised:
                prepare_structural_boundary_v3(
                    inventory=inventory,
                    schedule=corrupt,
                    output_directory=root / "rejected",
                    resource_classes=DEFAULT_RESOURCE_CLASSES_V3,
                )
            self.assertEqual(raised.exception.code, "planner_omission")

    def test_dependency_inventory_omission_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory, _edges_path = self._inputs(root)
            edges = copy.deepcopy(_edges())
            edges["nodes"] = edges["nodes"][:-1]  # type: ignore[index]
            omitted = root / "omitted-edges.json"
            _write(omitted, edges)
            structural = prepare_structural_boundary_v3(
                inventory=inventory,
                output_directory=root / "structural",
                resource_classes=DEFAULT_RESOURCE_CLASSES_V3,
            )

            with self.assertRaises(AnalysisV3Error) as raised:
                prepare_dependency_boundary_v3(
                    structural_schedule=structural.output_directory / "schedule.json",
                    record_edges=omitted,
                    output_directory=root / "dependency",
                )
            self.assertEqual(raised.exception.code, "dependency_coverage_mismatch")


if __name__ == "__main__":
    unittest.main()
