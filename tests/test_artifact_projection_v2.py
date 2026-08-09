from __future__ import annotations

import unittest

from spaghetti_extractor.artifact_projection_v2 import (
    project_joint_interprocedural_artifact_v2,
)


class ArtifactProjectionV2Tests(unittest.TestCase):
    def test_projects_a_schema_checked_child(self) -> None:
        child = {"format": "child-v2", "status": "incomplete", "value": 7}
        result = project_joint_interprocedural_artifact_v2(
            {
                "format": "spaghetti-extractor-joint-interprocedural-analysis-v2",
                "status": "incomplete",
                "interprocedural": child,
            },
            field="interprocedural",
            expected_format="child-v2",
            allowed_statuses=("complete", "incomplete", "violated"),
        )
        self.assertEqual(result, child)

    def test_rejects_wrong_parent_or_child_schema(self) -> None:
        with self.assertRaisesRegex(ValueError, "joint interprocedural artifact"):
            project_joint_interprocedural_artifact_v2(
                {"format": "wrong", "status": "complete"},
                field="interprocedural",
                expected_format="child-v2",
                allowed_statuses=("complete",),
            )
        with self.assertRaisesRegex(ValueError, "format mismatch"):
            project_joint_interprocedural_artifact_v2(
                {
                    "format": "spaghetti-extractor-joint-interprocedural-analysis-v2",
                    "status": "complete",
                    "interprocedural": {"format": "wrong", "status": "complete"},
                },
                field="interprocedural",
                expected_format="child-v2",
                allowed_statuses=("complete",),
            )


if __name__ == "__main__":
    unittest.main()
