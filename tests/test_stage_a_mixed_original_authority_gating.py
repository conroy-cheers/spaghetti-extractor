from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    OriginalPERecoveryInput,
    plan_interpreter_mixed_original,
    write_relational_interpreter_mixed_original_base,
)
from tests.test_stage_a_relational_interpreter_mixed_original import (
    _pe32_writable_static_word_call_image,
    _spec,
    _writable_static_word_call_rows,
    _write_jsonl,
)


class StageAMixedOriginalAuthorityGatingTests(unittest.TestCase):
    def test_writable_slot_requires_external_and_call_frame_authorities(self) -> None:
        image = _pe32_writable_static_word_call_image()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _writable_static_word_call_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )

            self.assertFalse(plan.complete)
            self.assertEqual(len(plan.blockers), 1)
            detail = plan.blockers[0].detail
            self.assertIn("external-call memory-footprint preservation", detail)
            self.assertIn("call-frame argument provenance", detail)

            written = write_relational_interpreter_mixed_original_base(
                root / "base", plan
            )
            base_module = next(
                path
                for path in written
                if path.name == "GeneratedRelationalInterpreterMixedOriginalBase.lean"
            )
            source = base_module.read_text(encoding="utf-8")
            self.assertNotIn("ExactOriginalDecodedReachability", source)


if __name__ == "__main__":
    unittest.main()
