from __future__ import annotations

from pathlib import Path
import unittest


class StageARelationalInterpreterKernelInvokeResultProducerTests(unittest.TestCase):
    def test_producer_uses_exact_epilogue_operation_result(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (
            root
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelInvokeResultProducer.lean"
        ).read_text(encoding="utf-8")

        for name in (
            "InvokeCallNativeInternalResultProducer",
            "InvokeCallNativeExternalHelperResultProducer",
            "InvokeCallNativeIndirectResultProducer",
        ):
            self.assertIn(f"structure {name}", source)
            self.assertIn(f"def {name}.resultEncoding", source)

        self.assertIn("certificate.operationResult", source)
        self.assertIn("exactSegmentTopLevelCdeclReturnedState", source)
        self.assertIn("epilogueStartExact", source)
        self.assertIn("epilogueFuelExact", source)
        self.assertNotIn(".responseRelated", source)
        self.assertNotIn("sorry", source)
        self.assertNotIn("native_decide", source)


if __name__ == "__main__":
    unittest.main()
