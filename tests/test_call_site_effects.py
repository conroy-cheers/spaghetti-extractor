from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.call_site_effects import (
    CallOutput,
    CallSiteEffect,
    CallSiteId,
    CallWriteSpan,
    parse_call_site_effect,
    parse_call_site_effects,
)
from spaghetti_extractor.machine_abi import resolve_machine_call_abi
from spaghetti_extractor.provenance_domain import ValueOrigin


class CallSiteEffectTests(unittest.TestCase):
    def _effect(self) -> CallSiteEffect:
        abi = resolve_machine_call_abi("pe32-stdcall-v1")
        assert abi is not None
        dependency = "checked-external-site:unit-1:0"
        location = ValueOrigin("register_location", ("eax",))
        value = ValueOrigin(
            "resource",
            ("directdraw", "surface", 3),
            (dependency,),
        )
        write_base = ValueOrigin("stack_location", (12,))
        return CallSiteEffect(
            site=CallSiteId("unit-1", 0),
            transfer_kind="indirect_call",
            status="complete",
            register_frame_status="complete",
            preserved_registers=frozenset({"ebp", "ebx", "edi", "esi"}),
            stack_frame_status="complete",
            stack_cleanup_bytes=12,
            result_status="complete",
            outputs=(CallOutput(location, frozenset({value})),),
            memory_frame_status="complete",
            memory_preserved=False,
            memory_writes=(CallWriteSpan(write_base, 4),),
            abi=abi,
            argument_words=3,
            dependencies=(dependency,),
        )

    def test_round_trip_preserves_typed_call_effect(self) -> None:
        effect = self._effect()

        parsed = parse_call_site_effect(
            effect.as_json(), finite_value_budget=4
        )

        self.assertEqual(parsed, effect)
        self.assertEqual(parsed.as_json(), effect.as_json())

    def test_inventory_rejects_duplicate_sites(self) -> None:
        payload = self._effect().as_json()

        with self.assertRaisesRegex(ValueError, "duplicate call-site effect"):
            parse_call_site_effects(
                [payload, copy.deepcopy(payload)], finite_value_budget=4
            )

    def test_complete_memory_frame_rejects_contradictory_preservation(self) -> None:
        payload = self._effect().as_json()
        payload["memory_frame"] = {
            "status": "complete",
            "preserved": True,
            "writes": payload["memory_frame"]["writes"],
        }

        with self.assertRaisesRegex(
            ValueError, "preservation must match its write set"
        ):
            parse_call_site_effect(payload, finite_value_budget=4)

    def test_parser_rejects_noncanonical_abi(self) -> None:
        payload = self._effect().as_json()
        payload["abi"]["preserved_registers"] = ["ebp"]

        with self.assertRaisesRegex(ValueError, "canonical template"):
            parse_call_site_effect(payload, finite_value_budget=4)

    def test_parser_rejects_excessive_result_alternatives(self) -> None:
        payload = self._effect().as_json()
        payload["result_frame"]["outputs"][0]["origins"].append(
            ValueOrigin("exact", (7,)).as_json()
        )

        with self.assertRaisesRegex(ValueError, "1..1 alternatives"):
            parse_call_site_effect(payload, finite_value_budget=1)

    def test_incomplete_family_cannot_smuggle_authorizing_facts(self) -> None:
        payload = self._effect().as_json()
        payload["status"] = "incomplete"
        payload["memory_frame"]["status"] = "incomplete"
        payload["failure_codes"] = ["memory_frame_unknown"]

        with self.assertRaisesRegex(ValueError, "cannot carry effects"):
            parse_call_site_effect(payload, finite_value_budget=4)

    def test_nested_expression_origin_key_remains_reproducible(self) -> None:
        effect = self._effect()
        payload = effect.as_json()
        payload["result_frame"]["outputs"][0]["origins"] = [
            ValueOrigin(
                "symbolic_affine",
                (("add", ("register", "eax"), ("constant", 4)),),
            ).as_json()
        ]

        parsed = parse_call_site_effect(payload, finite_value_budget=4)

        self.assertEqual(parsed.as_json(), payload)


if __name__ == "__main__":
    unittest.main()
