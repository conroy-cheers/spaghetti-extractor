from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from spaghetti_extractor.components.bisimulation_diagnostics import ProofQueryTimings


class ProofQueryTimingsTests(unittest.TestCase):
    def test_compile_record_keeps_identical_sources_in_their_header_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(2):
                shard = root / str(index)
                shard.mkdir()
                (shard / "source.c").write_text('#include "region.h"\n')
                (shard / "region.h").write_text(f"#define REGION {index}\n")
            model = root / "0" / "model.goto"
            timings = ProofQueryTimings(model, {})
            timings.record_compile_inputs(
                ["goto-cc", "-I", str(root), str(root / "0" / "source.c"), "-o", str(model)],
                proof_root=root,
                compiler_workspace=Path('/tmp/spx-proof'),
            )
            record = json.loads((model.parent / "compile-inputs.json").read_text())
        self.assertFalse(record["authorizing"])
        self.assertEqual(record["compiler_workspace"], "/tmp/spx-proof")
        self.assertEqual(record["compiler_workspace_host"], "$PROOF_ROOT")
        self.assertIn("$PROOF_ROOT/0/source.c", record["command"])
        self.assertNotIn("$PROOF_ROOT/1/source.c", record["command"])
        files = {row["path"]: row["sha256"] for row in record["files"]}
        self.assertNotEqual(files["$PROOF_ROOT/0/region.h"], files["$PROOF_ROOT/1/region.h"])

    def test_timeout_is_recorded_without_changing_the_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            model = Path(temporary) / "model.goto"
            model.write_bytes(b"model")
            timings = ProofQueryTimings(model, {"proof_function": "proof"})
            result = {"status": "incomplete", "code": "cbmc_timeout", "output_sha256": "a" * 64,
                      "detail": "exceeded 30 seconds"}
            observed = timings.run("assertion:proof.assertion.1", lambda **_: result,
                                   command=["cbmc", str(model)])
            self.assertIs(observed, result)
            row = json.loads(timings.path.read_text())
        self.assertFalse(row["authorizing"])
        self.assertEqual(row["status"], "incomplete")
        self.assertEqual(row["code"], "cbmc_timeout")
        self.assertEqual(row["detail"], result["detail"])
        self.assertEqual(row["command"], ["cbmc", "$OBLIGATION_ROOT/model.goto"])
        self.assertGreaterEqual(row["elapsed_seconds"], 0)
        self.assertNotIn("elapsed_seconds", result)

    def test_exception_is_recorded_and_propagated(self) -> None:
        def failure(**_):
            raise RuntimeError("checker crashed")

        with tempfile.TemporaryDirectory() as temporary:
            timings = ProofQueryTimings(Path(temporary) / "model.goto", {})
            with self.assertRaisesRegex(RuntimeError, "checker crashed"):
                timings.run("compile", failure, command=["goto-cc"])
            row = json.loads(timings.path.read_text())
        self.assertFalse(row["authorizing"])
        self.assertEqual(row["status"], "error")
        self.assertIsNone(row["goto_model_sha256"])

    def test_parallel_queries_produce_complete_independent_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            timings = ProofQueryTimings(Path(temporary) / "model.goto", {})
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda index: timings.run("assertion", lambda **_: {"status": "satisfied"},
                                                       command=["cbmc", str(index)]), range(12)))
            rows = [json.loads(line) for line in timings.path.read_text().splitlines()]
        self.assertEqual(len(rows), 12)
        self.assertEqual({int(row["command"][-1]) for row in rows}, set(range(12)))
        self.assertTrue(all(row["authorizing"] is False for row in rows))
