from __future__ import annotations

import unittest

from spaghetti_extractor.call_frame_hypotheses import (
    CallFrameHypothesisError,
    PRESERVED_REGISTER_HYPOTHESIS_FORMAT,
    PreservedRegisterHypothesis,
    hypothesis_id,
    parse_preserved_register_hypotheses,
)


def _row(**changes: object) -> dict[str, object]:
    row: dict[str, object] = {
        "format": PRESERVED_REGISTER_HYPOTHESIS_FORMAT,
        "id": hypothesis_id("unit:entry", 3, "edi"),
        "unit_id": "unit:entry",
        "event_index": 3,
        "transfer_kind": "indirect_call",
        "register": "edi",
        "proposal_source": "unresolved-call-bootstrap-v1",
        "proof_authority": False,
    }
    row.update(changes)
    return row


class PreservedRegisterHypothesisTests(unittest.TestCase):
    def test_canonical_id_uses_compact_json(self) -> None:
        self.assertEqual(
            hypothesis_id("unit:entry", 3, "edi"),
            'call-frame-hypothesis:["unit:entry",3,"edi"]',
        )

    def test_round_trip(self) -> None:
        parsed = PreservedRegisterHypothesis.parse(_row())
        self.assertEqual(parsed.as_json(), _row())
        self.assertEqual(parse_preserved_register_hypotheses([_row()]), (parsed,))

    def test_all_supported_transfer_kinds_and_registers(self) -> None:
        for transfer_kind in ("external_call", "indirect_call", "internal_call"):
            for register in ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi"):
                with self.subTest(transfer_kind=transfer_kind, register=register):
                    row = _row(
                        id=hypothesis_id("unit:entry", 3, register),
                        transfer_kind=transfer_kind,
                        register=register,
                    )
                    self.assertEqual(
                        PreservedRegisterHypothesis.parse(row).register,
                        register,
                    )

    def test_rejects_missing_and_extra_fields(self) -> None:
        missing = _row()
        del missing["proposal_source"]
        for row in (missing, {**_row(), "extra": 1}):
            with self.subTest(row=row):
                with self.assertRaises(CallFrameHypothesisError):
                    PreservedRegisterHypothesis.parse(row)

    def test_rejects_wrong_format(self) -> None:
        with self.assertRaises(CallFrameHypothesisError):
            PreservedRegisterHypothesis.parse(_row(format="wrong"))

    def test_rejects_malformed_id(self) -> None:
        for bad_id in (
            "",
            "different",
            'call-frame-hypothesis:["unit:entry",3, "edi"]',
            'call-frame-hypothesis:["other",3,"edi"]',
        ):
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(CallFrameHypothesisError):
                    PreservedRegisterHypothesis.parse(_row(id=bad_id))

    def test_rejects_malformed_site(self) -> None:
        for field, value in (
            ("unit_id", ""),
            ("unit_id", "   "),
            ("unit_id", 7),
            ("event_index", -1),
            ("event_index", True),
            ("event_index", 1.0),
            ("transfer_kind", "call"),
            ("transfer_kind", 1),
            ("proposal_source", ""),
            ("proposal_source", "  "),
            ("proposal_source", False),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(CallFrameHypothesisError):
                    PreservedRegisterHypothesis.parse(_row(**{field: value}))

    def test_rejects_invalid_register_and_esp(self) -> None:
        for register in ("ax", "EDI", "esp", "", 1):
            with self.subTest(register=register):
                with self.assertRaises(CallFrameHypothesisError):
                    PreservedRegisterHypothesis.parse(
                        _row(register=register)
                    )

    def test_rejects_authorizing_hypothesis(self) -> None:
        for value in (True, 0, None, "false"):
            with self.subTest(value=value):
                with self.assertRaises(CallFrameHypothesisError):
                    PreservedRegisterHypothesis.parse(
                        _row(proof_authority=value)
                    )

    def test_inventory_requires_a_list(self) -> None:
        for value in (None, {}, (), ""):
            with self.subTest(value=value):
                with self.assertRaises(CallFrameHypothesisError):
                    parse_preserved_register_hypotheses(value)

    def test_inventory_rejects_duplicate_id_and_site_register(self) -> None:
        with self.assertRaisesRegex(
            CallFrameHypothesisError, "duplicates an ID or site/register"
        ):
            parse_preserved_register_hypotheses([_row(), _row()])

    def test_inventory_wraps_record_location(self) -> None:
        with self.assertRaisesRegex(
            CallFrameHypothesisError, "hypothesis 1 is invalid"
        ):
            parse_preserved_register_hypotheses([_row(), _row(id="bad")])


if __name__ == "__main__":
    unittest.main()
