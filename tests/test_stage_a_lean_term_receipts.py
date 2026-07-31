from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "nix" / "stage-a-lean-term-receipts.py"
SPEC = importlib.util.spec_from_file_location(
    "stage_a_lean_term_receipts",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LeanTermReceiptTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path]:
        source_root = root / "source"
        source = source_root / "StageA" / "GeneratedReceipt.lean"
        source.parent.mkdir(parents=True)
        source.write_text(
            "namespace StageA.Generated\n"
            "def checkedTerm : True := True.intro\n"
            "end StageA.Generated\n",
            encoding="utf-8",
        )
        bundle = root / "bundle.json"
        bundle.write_text(
            json.dumps({
                "format": "stage-a-lean-target-bundle-v2",
                "nodes": [{
                    "outputs": [{
                        "module": "GeneratedReceipt",
                        "olean_sha256": "1" * 64,
                        "axiom_audit": {
                            "complete": True,
                            "inventories": {"checkedTerm": []},
                            "requested": ["checkedTerm"],
                        },
                    }],
                }],
            }),
            encoding="utf-8",
        )
        requests = root / "requests.json"
        requests.write_text(
            json.dumps({
                "format": "stage-a-lean-kernel-check-requests-v1",
                "requests": [{
                    "term": {
                        "module": "StageA.GeneratedReceipt",
                        "namespace": "StageA.Generated",
                        "symbol": "checkedTerm",
                    },
                }],
            }),
            encoding="utf-8",
        )
        return bundle, source_root, requests

    def test_binds_exact_source_and_olean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, source_root, requests = self._fixture(root)
            result = MODULE.create_receipts(
                bundle_path=bundle,
                source_root=source_root,
                requests_path=requests,
            )
            receipt = result["receipts"]["StageA.GeneratedReceipt"]
            self.assertEqual(receipt["status"], "checked")
            self.assertEqual(receipt["olean_sha256"], "1" * 64)
            self.assertEqual(
                receipt["term"]["symbol"],
                "checkedTerm",
            )

    def test_rejects_ambiguous_compiled_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, source_root, requests = self._fixture(root)
            value = json.loads(bundle.read_text(encoding="utf-8"))
            value["nodes"].append(value["nodes"][0])
            bundle.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "absent or ambiguous"):
                MODULE.create_receipts(
                    bundle_path=bundle,
                    source_root=source_root,
                    requests_path=requests,
                )

    def test_rejects_missing_exact_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, source_root, requests = self._fixture(root)
            (
                source_root / "StageA" / "GeneratedReceipt.lean"
            ).unlink()
            with self.assertRaisesRegex(ValueError, "source is missing"):
                MODULE.create_receipts(
                    bundle_path=bundle,
                    source_root=source_root,
                    requests_path=requests,
                )

    def test_rejects_unaudited_term_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, source_root, requests = self._fixture(root)
            value = json.loads(requests.read_text(encoding="utf-8"))
            value["requests"][0]["term"]["symbol"] = "notCompiled"
            requests.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "did not audit"):
                MODULE.create_receipts(
                    bundle_path=bundle,
                    source_root=source_root,
                    requests_path=requests,
                )


if __name__ == "__main__":
    unittest.main()
