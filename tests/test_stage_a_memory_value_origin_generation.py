from __future__ import annotations

import unittest

from spaghetti_extractor.relational.lean.expressions import _lean_state_invariant


class StageAMemoryValueOriginGenerationTests(unittest.TestCase):
    def test_memory_origin_uses_the_shared_expression_and_origin_languages(
        self,
    ) -> None:
        source = _lean_state_invariant({
            "memory_value_origin_relations": [{
                "original_address": {"op": "constant", "value": 0x4200AC},
                "candidate_address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": "esp"},
                    "right": {"op": "constant", "value": 24},
                },
                "finite_alternative_budget": 2,
                "origins": [
                    {
                        "kind": "static_code_target",
                        "target_id": 17,
                        "offset": 0,
                    },
                    {"kind": "opaque_resource", "resource_id": 3},
                ],
            }],
        })

        self.assertIn("memoryValueOriginRelations := [", source)
        self.assertIn(
            "originalAddress := StageA.Formal.Expr.constant 4325548",
            source,
        )
        self.assertIn(
            "candidateAddress := StageA.Formal.Expr.add "
            "(StageA.Formal.Expr.inputReg (StageA.Formal.Reg.esp)) "
            "(StageA.Formal.Expr.constant 24)",
            source,
        )
        self.assertIn(
            "origins := [.staticCodeTarget 17 0, .opaqueResource 3]",
            source,
        )


if __name__ == "__main__":
    unittest.main()
