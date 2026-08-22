from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from spaghetti_extractor.calls.compiler_proposal import (
    CompilerCallProposalV1,
    run_clang_call_proposal,
)


class CompilerCallProposalTests(unittest.TestCase):
    def test_pinned_clang_output_is_proposal_only(self) -> None:
        compiler = shutil.which("clang")
        if compiler is None:
            self.skipTest("clang is not in PATH")
        source = Path(__file__).parents[2] / "fixtures" / "calls" / "abi_probe.c"
        proposal = run_clang_call_proposal(
            compiler=compiler,
            source=source,
            declaration="fixture_call",
            abi_dialect="pe32-i386-gnu-v1",
        )
        self.assertEqual(proposal.to_payload()["authority"], "proposal-only")
        self.assertEqual(CompilerCallProposalV1.parse(proposal.to_payload()), proposal)


if __name__ == "__main__":
    unittest.main()
