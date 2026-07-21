from tests.stage_a_relational_support import *

from spaghetti_extractor.relational.analyses.registers import (
    _infer_register_output_relation,
    _matching_static_word_relation_slot,
)
from spaghetti_extractor.relational.analyses.memory import _initial_u32
from spaghetti_extractor.relational.analyses.segments import (
    _paired_stack_word_value_claim,
    _static_word_zero_guard_claim,
)


class StageAStaticWordRelationTests(StageARelationalTestBase):
    @staticmethod
    def _read(address):
        return {
            "op": "read32",
            "address": {"op": "constant", "value": address},
        }

    @classmethod
    def _zero_guard(cls, address, *, masked=True, not_count=0):
        value = cls._read(address)
        if masked:
            value = {"op": "bit_and", "left": value, "right": value}
        result = {
            "op": "equal",
            "left": value,
            "right": {"op": "constant", "value": 0},
        }
        for _ in range(not_count):
            result = {"op": "not", "value": result}
        return result

    @staticmethod
    def _slot(relation="related_word", *, candidate_address=0x402004):
        return {
            "id": 7,
            "original_address": 0x402000,
            "candidate_address": candidate_address,
            "relation": relation,
        }

    def test_static_slot_inference_preserves_relation_and_fails_on_ambiguity(self):
        original = self._read(0x402000)
        candidate = self._read(0x402004)
        slot = self._slot()
        contract = {"static_word_relation_slots": [slot]}

        self.assertEqual(
            _matching_static_word_relation_slot(original, candidate, contract),
            slot,
        )
        self.assertEqual(
            _infer_register_output_relation(
                original,
                candidate,
                {},
                contract,
                0x400000,
                0x400000,
                True,
            ),
            ("related_word", "static_word_slot"),
        )
        self.assertIsNone(_matching_static_word_relation_slot(
            original,
            candidate,
            {"static_word_relation_slots": [slot, dict(slot)]},
        ))
        self.assertIsNone(_matching_static_word_relation_slot(
            original,
            candidate,
            {"static_word_relation_slots": [
                self._slot(candidate_address=0x402000),
            ]},
        ))

    def test_loaded_initial_word_zero_fills_virtual_section_tail(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            sections=(SimpleNamespace(
                rva_start=0x3000,
                rva_end=0x3100,
                raw_size=0,
            ),),
            pe=SimpleNamespace(get_data=lambda _rva, _size: b""),
        )
        self.assertEqual(_initial_u32(binary, 0x40300C), 0)

    def test_static_slot_zero_guard_requires_relation_address_and_shape(self):
        slot = self._slot()
        contract = {"static_word_relation_slots": [slot]}
        original = self._zero_guard(0x402000, not_count=1)
        candidate = self._zero_guard(0x402004, not_count=1)

        self.assertEqual(
            _static_word_zero_guard_claim(contract, original, candidate),
            {
                "profile": "static_word_zero_guard_v1",
                "slot": slot,
                "original_address": 0x402000,
                "candidate_address": 0x402004,
                "masked": True,
                "not_count": 1,
            },
        )
        self.assertIsNone(_static_word_zero_guard_claim(
            {"static_word_relation_slots": [slot, dict(slot)]},
            original,
            candidate,
        ))
        self.assertIsNone(_static_word_zero_guard_claim(
            {"static_word_relation_slots": [self._slot("code_pointer")]},
            original,
            candidate,
        ))
        self.assertIsNone(_static_word_zero_guard_claim(
            contract,
            original,
            self._zero_guard(0x402004, masked=False, not_count=1),
        ))
        self.assertIsNone(_static_word_zero_guard_claim(
            contract,
            original,
            self._zero_guard(0x402000, not_count=1),
        ))

    def test_stack_word_can_publish_related_value_to_static_slot(self):
        window = {
            "range_id": 3,
            "original_register": "esp",
            "candidate_register": "esp",
            "bytes_below": 0,
            "bytes_above": 8,
        }
        value = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": 4},
            },
        }
        claim = _paired_stack_word_value_claim(
            {"stack_windows": [window]}, value, value
        )
        self.assertEqual(claim, {
            "profile": "stack_read32_v1",
            "original": value,
            "candidate": value,
            "window": window,
            "adjustment": {"kind": "add", "amount": 4},
        })
        self.assertIsNone(_paired_stack_word_value_claim(
            {"stack_windows": [window, dict(window)]}, value, value
        ))

        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "fixture.exe"
            image.write_bytes(_pe32_image_with_relocated_data(0x3000))
            original = _parse_stage_a_pe(image)
            candidate = _parse_stage_a_pe(image)
            contract = {
                "regions": [{
                    "id": "publish-stack-word",
                    "input_relations": [],
                    "stack_windows": [window],
                    "input_dynamic_range_relations": [],
                    "code_targets": [],
                    "values": [],
                }],
                "static_word_relation_slots": [],
                "static_dynamic_pointer_slots": [],
            }
            behavior = {
                "original_ir": {"writes": [{
                    "address": {"op": "constant", "value": 0x403000},
                    "value": value,
                }]},
                "candidate_ir": {"writes": [{
                    "address": {"op": "constant", "value": 0x403000},
                    "value": value,
                }]},
            }
            inferred, analysis = _attach_static_word_relation_slots(
                contract, [behavior], original, candidate
            )
            self.assertEqual(analysis["counts"], {
                "existing": 0, "inferred": 1, "rejected": 0,
            })
            self.assertEqual(
                inferred["static_word_relation_slots"][0]["relation"],
                "related_word",
            )

    def test_untouched_writable_static_read_infers_exact_slot(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "fixture.exe"
            image.write_bytes(_pe32_image_with_writable_data(
                b"\xa1\x00\x20\x40\x00\xeb\xf9",
                relocation_offsets=[],
            ))
            binary = _parse_stage_a_pe(image)
            contract = {
                "regions": [{
                    "id": "read-static-word",
                    "input_relations": [],
                    "stack_windows": [],
                    "input_dynamic_range_relations": [],
                    "code_targets": [],
                    "values": [],
                }],
                "static_word_relation_slots": [],
                "static_dynamic_pointer_slots": [],
            }
            read = self._read(0x402000)
            behavior = {
                "original_ir": {"registers": {"eax": read}, "writes": []},
                "candidate_ir": {"registers": {"eax": read}, "writes": []},
            }

            inferred, analysis = _attach_static_word_relation_slots(
                contract, [behavior], binary, binary
            )

            self.assertEqual(analysis["counts"], {
                "existing": 0, "inferred": 1, "rejected": 0,
            })
            self.assertEqual(inferred["static_word_relation_slots"], [{
                "id": 0,
                "original_address": 0x402000,
                "candidate_address": 0x402000,
                "relation": "exact",
            }])
            self.assertEqual(analysis["inferred"][0]["relation"], "exact")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for static-word proof")
    def test_related_static_word_load_and_zero_guard_close_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_writable_data(
                bytes.fromhex("a10020400085c07402ebfeebfe"),
                relocation_offsets=[],
                data_size=8,
            ))
            candidate.write_bytes(_pe32_image_with_writable_data(
                bytes.fromhex("a10420400085c07402ebfeebfe"),
                relocation_offsets=[],
                data_size=8,
            ))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate((0x1000, 0x1009, 0x100B))
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (name, rva, size) in enumerate((
                        ("static-load-branch", 0x1000, 9),
                        ("fallthrough-loop", 0x1009, 2),
                        ("taken-loop", 0x100B, 2),
                    ))
                ],
                "static_word_relation_slots": [self._slot()],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")

            prepared = root / "prepared"
            stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )
            acceptance = json.loads(
                (prepared / "whole-program-acceptance.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(acceptance["status"], "ready", acceptance)
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            static_claims = [
                claim
                for region in register_relations["regions"]
                for claim in region["output_claims"]
                if claim["kind"] == "static_word_slot"
            ]
            self.assertEqual(len(static_claims), 1)
            self.assertEqual(
                static_claims[0]["output"]["relation"], "related_word"
            )
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertIn("RegisterOutputClaim.staticWordSlot", segment_source)
            self.assertIn(": StaticWordZeroGuardClaim", segment_source)
            self.assertIn(
                "staticWordZeroGuard_eval_equal_of_checked", segment_source
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

            relation["static_word_relation_slots"][0][
                "candidate_address"
            ] = 0x402000
            contract.write_text(json.dumps(relation), encoding="utf-8")
            stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatch",
            )
            mismatch = json.loads(
                (root / "mismatch" / "whole-program-acceptance.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(mismatch["status"], "incomplete", mismatch)


if __name__ == "__main__":
    unittest.main()
