from __future__ import annotations

import unittest

from spaghetti_extractor.semantic_link.module import _semantic_import_uses_v1
from spaghetti_extractor.semantic_objects.semantic_object import SemanticObjectV1


def _expression(
    identity: int, op: str, operands: list[int] | None = None,
    *, aux: int = 0, immediate: int = 0,
) -> dict[str, object]:
    return {
        "id": identity,
        "op": op,
        "operands": operands or [],
        "parameters": {
            "aux": aux, "immediate": immediate, "identity": None,
        },
    }


def _frame() -> dict[str, object]:
    return {
        "id": "physical-frame-v3:ping",
        "transport": {
            "format": "fixture", "id": "fixture", "subject": {
                "kind": "call", "id": "Ping",
            },
        },
    }


def _semantic(*, data_identity: str = "SharedValue") -> SemanticObjectV1:
    image_base = 0x400000
    ping_rva = 0x3000
    data_rva = 0x3004
    expressions = [
        _expression(0, "const", immediate=image_base + data_rva),
        _expression(1, "load", [0], aux=4),
        _expression(2, "load", [1], aux=4),
        _expression(3, "const", immediate=7),
    ]
    transfer = {
        "identity": "semantic-transfer:entry",
        "source": {"rva_start": 0x1000},
        "expressions": expressions,
        "effects": [{
            "id": 0, "op": "memory_write", "operands": [1, 3],
            "parameters": {"aux": 4},
        }],
        "calls": [{
            "id": 0, "kind": "external_call", "dll": "private.dll",
            "symbol": "Ping", "ordinal": None, "instruction_rva": 0x1001,
        }],
    }
    interface = {
        "image_id": "app",
        "loader": {"preferred_base": image_base},
        "imports": [{
            "slot_id": "app:iat:00003000", "dll": "private.dll",
            "symbol": "Ping", "ordinal": None, "iat_rva": ping_rva,
        }, {
            "slot_id": "app:iat:00003004", "dll": "private.dll",
            "symbol": data_identity, "ordinal": None, "iat_rva": data_rva,
        }],
        "delay_imports": [],
    }
    return SemanticObjectV1(
        payload={}, transfer_plan={"transfers": [transfer]}, transfers=(),
        module_interface=interface, machine_object_authority=None,  # type: ignore[arg-type]
    )


def _environment() -> dict[str, object]:
    return {
        "machine_import_contracts": [{
            "import_kind": "ordinary",
            "identity": {
                "dll": "private.dll", "symbol": "Ping", "ordinal": None,
            },
            "iat_rva": 0x3000,
            "boundary": {"physical_call_frame_v3": _frame()},
        }],
    }


class SemanticImportUseTests(unittest.TestCase):
    def test_code_and_data_uses_come_from_reachable_transfer_v2(self) -> None:
        uses, blockers = _semantic_import_uses_v1(
            semantic=_semantic(), resolved_environment=_environment(),
            roots_by_unit={"semantic-transfer:entry": {"module:process_entry"}},
        )

        self.assertEqual(blockers, [])
        by_slot = {row["slot_id"]: row for row in uses}
        self.assertEqual(by_slot["app:iat:00003000"]["use_kind"], "code")
        self.assertEqual(
            by_slot["app:iat:00003000"]["importer_physical_frame_id"],
            "physical-frame-v3:ping",
        )
        data = by_slot["app:iat:00003004"]
        self.assertEqual(data["use_kind"], "data")
        self.assertEqual(data["required_permissions"], 3)
        self.assertEqual(data["minimum_extent"], 4)
        self.assertEqual(
            {site["kind"] for site in data["sites"]},
            {"data_read", "data_write"},
        )

    def test_same_iat_slot_used_as_code_and_data_fails_closed(self) -> None:
        semantic = _semantic(data_identity="Ping")
        semantic.module_interface["imports"] = [
            semantic.module_interface["imports"][0]
        ]
        semantic.transfer_plan["transfers"][0]["expressions"][0][
            "parameters"
        ]["immediate"] = 0x403000
        uses, blockers = _semantic_import_uses_v1(
            semantic=semantic, resolved_environment=_environment(),
            roots_by_unit={"semantic-transfer:entry": {"module:process_entry"}},
        )

        self.assertEqual(uses[0]["use_kind"], "ambiguous")
        self.assertIn(
            "linked_import_code_data_use_ambiguous",
            {row["code"] for row in blockers},
        )

    def test_nonexact_pointer_transform_fails_closed(self) -> None:
        semantic = _semantic()
        transfer = semantic.transfer_plan["transfers"][0]
        transfer["expressions"].append(_expression(4, "reg"))
        transfer["expressions"].append(_expression(5, "xor32", [1, 4]))
        transfer["expressions"].append(_expression(6, "load", [5], aux=4))
        uses, blockers = _semantic_import_uses_v1(
            semantic=semantic, resolved_environment=_environment(),
            roots_by_unit={"semantic-transfer:entry": {"module:process_entry"}},
        )

        self.assertEqual(len(uses), 2)
        self.assertIn(
            "linked_import_data_pointer_use_inexact",
            {row["code"] for row in blockers},
        )

    def test_missing_code_protocol_is_an_honest_blocker(self) -> None:
        uses, blockers = _semantic_import_uses_v1(
            semantic=_semantic(), resolved_environment={
                "machine_import_contracts": [],
            },
            roots_by_unit={"semantic-transfer:entry": {"module:process_entry"}},
        )

        code_use = next(row for row in uses if row["use_kind"] == "code")
        self.assertIsNone(code_use["importer_physical_frame"])
        self.assertIsNone(code_use["importer_physical_frame_id"])
        self.assertIn(
            "linked_import_code_protocol_missing",
            {row["code"] for row in blockers},
        )


if __name__ == "__main__":
    unittest.main()
