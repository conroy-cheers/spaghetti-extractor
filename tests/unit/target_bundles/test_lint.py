from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.target_bundles.lint import (
    TargetBundleLintError,
    lint_target_bundle,
)


def _asset(path: str, role: str = "metadata") -> dict[str, str]:
    return {"path": path, "role": role, "owner": "fixture"}


class TargetBundleLintTests(unittest.TestCase):
    def test_exact_inventory_is_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.json").write_text("{}\n", encoding="ascii")
            (root / "intent").mkdir()
            (root / "intent/components.json").write_text("{}\n", encoding="ascii")
            output = root.parent / f"{root.name}-lint.json"
            result = lint_target_bundle(
                target_root=root,
                target_id="fixture",
                declared_assets=(
                    _asset("target.json"),
                    _asset("intent/components.json", "component_intent"),
                ),
                out=output,
            )
            self.assertEqual(result["status"], "checked")
            self.assertEqual(result["counts"], {"declared": 2, "actual": 2, "issues": 0})
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["lint_sha256"],
                result["lint_sha256"],
            )

    def test_missing_undeclared_duplicate_and_symlink_are_violations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.json").write_text("{}\n", encoding="ascii")
            (root / "extra.txt").write_text("extra\n", encoding="ascii")
            (root / "link").symlink_to("target.json")
            result = lint_target_bundle(
                target_root=root,
                target_id="fixture",
                declared_assets=(
                    _asset("target.json"),
                    _asset("target.json"),
                    _asset("missing.txt", "documentation"),
                ),
                out=root.parent / f"{root.name}-lint.json",
            )
            self.assertEqual(result["status"], "violated")
            self.assertEqual(
                {row["code"] for row in result["issues"]},
                {
                    "duplicate_asset_declaration",
                    "missing_declared_asset",
                    "target_asset_symlink",
                    "undeclared_target_asset",
                },
            )

    def test_rejects_escaping_and_generated_manual_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(TargetBundleLintError, "strict relative"):
                lint_target_bundle(
                    target_root=root,
                    target_id="fixture",
                    declared_assets=(_asset("../escape", "runtime"),),
                    out=root / "lint.json",
                )
            with self.assertRaisesRegex(TargetBundleLintError, "generated workspace"):
                lint_target_bundle(
                    target_root=root,
                    target_id="fixture",
                    declared_assets=(_asset("build/result.json", "runtime"),),
                    out=root / "lint.json",
                )


if __name__ == "__main__":
    unittest.main()
