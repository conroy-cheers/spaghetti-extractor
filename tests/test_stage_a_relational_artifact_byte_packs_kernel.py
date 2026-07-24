from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.artifact_byte_packs import (
    generate_artifact_byte_pack_bundle,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_AXIOMS = re.compile(r"depends on axioms: \[([^\]]*)\]")
_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARelationalArtifactBytePackKernelTests(unittest.TestCase):
    def test_aggregate_bytes_and_consumer_hash_are_kernel_checked(self) -> None:
        data = bytes(index % 251 for index in range(3073))
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.bin"
            artifact.write_bytes(data)
            inventory = generate_artifact_byte_pack_bundle(
                artifact_path=artifact,
                out_dir=root,
                module_prefix="KernelArtifactFixture",
                namespace="StageA.GeneratedRelational.KernelArtifactFixture",
                pack_size=1024,
                chunk_size=256,
            )
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(
                source_root, root / "StageA", "RelationalInterpreterKernel"
            )
            (root / "StageA/ArtifactBytePackConsumer.lean").write_text(
                f"""import StageA.RelationalInterpreterKernel
import StageA.{inventory.aggregate_module}

namespace StageA.GeneratedRelational.KernelArtifactFixture

open StageA.Relational.InterpreterKernel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem exactLength : {inventory.aggregate_bytes_name}.length = {len(data)} := by
  decide

theorem exactKernelHash :
    KernelSHA256.checkedHex {inventory.aggregate_bytes_name} \"{digest}\" = true := by
  decide

#print axioms exactLength
#print axioms exactKernelHash

end StageA.GeneratedRelational.KernelArtifactFixture
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="ArtifactBytePackConsumer"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        self.assertNotIn("sorryAx", result["stdout"])
        for match in _AXIOMS.finditer(result["stdout"]):
            observed = {
                item.strip()
                for item in match.group(1).split(",")
                if item.strip()
            }
            self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


if __name__ == "__main__":
    unittest.main()
