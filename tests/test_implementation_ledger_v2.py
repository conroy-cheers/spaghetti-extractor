from __future__ import annotations

import dataclasses
import json
import unittest

from spaghetti_extractor.authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
    UnitBinding,
)
from spaghetti_extractor.implementation_ledger_v2 import (
    ArtifactIdentityV2,
    CompletionProfileV2,
    CompletionStatusV2,
    ImplementationLedgerBindingV2,
    ImplementationLedgerV2,
    ImplementationOwnerKindV2,
    ImplementationOwnerV2,
    UnitOwnershipRecordV2,
)


def _digest(character: str) -> str:
    return character * 64


def _artifact(kind: str, name: str, character: str) -> ArtifactIdentityV2:
    return ArtifactIdentityV2(kind, name, _digest(character))


def _binary() -> BinaryBinding:
    return BinaryBinding(_digest("a"), _digest("b"))


def _unit(
    unit_id: str,
    start: int,
    character: str,
    *,
    binary: BinaryBinding | None = None,
) -> UnitBinding:
    return UnitBinding(
        binary=binary or _binary(),
        unit_id=unit_id,
        rva_start=start,
        rva_end=start + 16,
        unit_sha256=_digest(character),
        instruction_bytes_sha256=_digest(character),
    )


def _owner(
    kind: ImplementationOwnerKindV2,
    name: str,
    character: str,
) -> ImplementationOwnerV2:
    return ImplementationOwnerV2(
        kind=kind,
        implementation=_artifact("implementation", name, character),
        qualification=_artifact("qualification", f"{name}-qualification", character),
    )


def _codes(ledger: ImplementationLedgerV2) -> set[str]:
    return {issue.code for issue in ledger.issues}


class ImplementationLedgerV2Tests(unittest.TestCase):
    def test_static_baseline_has_exactly_one_fallback_owner_per_unit(self) -> None:
        left = _unit("left", 0x1000, "c")
        right = _unit("right", 0x1010, "d")
        fallback = _owner(
            ImplementationOwnerKindV2.MACHINE_IR_FALLBACK,
            "fallback",
            "e",
        )
        ledger = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.STATIC_BASELINE,
            binary=_binary(),
            structural_units=[right, left],
            ownership_records=[
                UnitOwnershipRecordV2.create(owner=fallback, units=[right, left])
            ],
        )

        self.assertIs(ledger.status, CompletionStatusV2.COMPLETE)
        self.assertEqual(ledger.issues, ())
        self.assertEqual(ledger.structural_units, (left, right))
        self.assertEqual(
            ImplementationLedgerV2.parse(json.loads(ledger.to_json())),
            ledger,
        )
        self.assertEqual(ledger.to_binding().status, CompletionStatusV2.COMPLETE)
        self.assertEqual(len(ledger.to_binding().qualification_requirements), 1)
        self.assertEqual(
            ImplementationLedgerBindingV2.parse(ledger.to_binding().to_payload()),
            ledger.to_binding(),
        )

    def test_create_is_deterministic_across_input_order(self) -> None:
        left = _unit("left", 0x1000, "c")
        right = _unit("right", 0x1010, "d")
        first = UnitOwnershipRecordV2.create(
            owner=_owner(
                ImplementationOwnerKindV2.PORTABLE_COMPONENT,
                "left-source",
                "e",
            ),
            units=[left],
        )
        second = UnitOwnershipRecordV2.create(
            owner=_owner(
                ImplementationOwnerKindV2.LIBRARY_SUBSTITUTION,
                "right-library",
                "f",
            ),
            units=[right],
        )

        one = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.PORTABLE_APPLICATION,
            binary=_binary(),
            structural_units=[left, right],
            ownership_records=[first, second],
        )
        two = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.PORTABLE_APPLICATION,
            binary=_binary(),
            structural_units=[right, left],
            ownership_records=[second, first],
        )

        self.assertIs(one.status, CompletionStatusV2.COMPLETE)
        self.assertEqual(one.to_payload(), two.to_payload())
        self.assertEqual(one.ledger_id, two.ledger_id)
        self.assertEqual(one.artifact_identity, two.artifact_identity)

    def test_missing_owner_is_incomplete(self) -> None:
        left = _unit("left", 0x1000, "c")
        right = _unit("right", 0x1010, "d")
        ledger = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.STATIC_BASELINE,
            binary=_binary(),
            structural_units=[left, right],
            ownership_records=[
                UnitOwnershipRecordV2.create(
                    owner=_owner(
                        ImplementationOwnerKindV2.MACHINE_IR_FALLBACK,
                        "fallback",
                        "e",
                    ),
                    units=[left],
                )
            ],
        )

        self.assertIs(ledger.status, CompletionStatusV2.INCOMPLETE)
        self.assertIn("structural_unit_owner_missing", _codes(ledger))

    def test_empty_structural_universe_is_incomplete(self) -> None:
        ledger = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.STATIC_BASELINE,
            binary=_binary(),
            structural_units=[],
            ownership_records=[],
        )

        self.assertIs(ledger.status, CompletionStatusV2.INCOMPLETE)
        self.assertIn("structural_unit_universe_empty", _codes(ledger))

    def test_unassigned_owner_is_incomplete(self) -> None:
        unit = _unit("left", 0x1000, "c")
        ledger = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.STATIC_BASELINE,
            binary=_binary(),
            structural_units=[unit],
            ownership_records=[
                UnitOwnershipRecordV2.create(
                    owner=ImplementationOwnerV2(
                        ImplementationOwnerKindV2.UNASSIGNED,
                        None,
                        None,
                    ),
                    units=[unit],
                )
            ],
        )

        self.assertIs(ledger.status, CompletionStatusV2.INCOMPLETE)
        self.assertIn("unit_owner_unassigned", _codes(ledger))

    def test_portable_profiles_forbid_machine_ir_fallback(self) -> None:
        unit = _unit("left", 0x1000, "c")
        record = UnitOwnershipRecordV2.create(
            owner=_owner(
                ImplementationOwnerKindV2.MACHINE_IR_FALLBACK,
                "fallback",
                "e",
            ),
            units=[unit],
        )
        for profile in (
            CompletionProfileV2.PORTABLE_APPLICATION,
            CompletionProfileV2.VALIDATION_QUALIFIED,
        ):
            with self.subTest(profile=profile):
                ledger = ImplementationLedgerV2.create(
                    profile=profile,
                    binary=_binary(),
                    structural_units=[unit],
                    ownership_records=[record],
                )
                self.assertIs(ledger.status, CompletionStatusV2.INCOMPLETE)
                self.assertIn("machine_ir_fallback_forbidden", _codes(ledger))

    def test_overlapping_owners_are_violated(self) -> None:
        unit = _unit("left", 0x1000, "c")
        ledger = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.PORTABLE_APPLICATION,
            binary=_binary(),
            structural_units=[unit],
            ownership_records=[
                UnitOwnershipRecordV2.create(
                    owner=_owner(
                        ImplementationOwnerKindV2.PORTABLE_COMPONENT,
                        "source",
                        "d",
                    ),
                    units=[unit],
                ),
                UnitOwnershipRecordV2.create(
                    owner=_owner(
                        ImplementationOwnerKindV2.LIBRARY_SUBSTITUTION,
                        "library",
                        "e",
                    ),
                    units=[unit],
                ),
            ],
        )

        self.assertIs(ledger.status, CompletionStatusV2.VIOLATED)
        self.assertIn("structural_unit_owner_overlap", _codes(ledger))

    def test_duplicate_owner_record_is_violated(self) -> None:
        unit = _unit("left", 0x1000, "c")
        record = UnitOwnershipRecordV2.create(
            owner=_owner(
                ImplementationOwnerKindV2.PORTABLE_COMPONENT,
                "source",
                "d",
            ),
            units=[unit],
        )
        ledger = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.PORTABLE_APPLICATION,
            binary=_binary(),
            structural_units=[unit],
            ownership_records=[record, record],
        )

        self.assertIs(ledger.status, CompletionStatusV2.VIOLATED)
        self.assertIn("duplicate_ownership_record", _codes(ledger))

    def test_duplicate_claim_inside_one_record_is_violated(self) -> None:
        unit = _unit("left", 0x1000, "c")
        record = UnitOwnershipRecordV2(
            owner=_owner(
                ImplementationOwnerKindV2.PORTABLE_COMPONENT,
                "source",
                "d",
            ),
            units=(unit, unit),
        )
        ledger = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.PORTABLE_APPLICATION,
            binary=_binary(),
            structural_units=[unit],
            ownership_records=[record],
        )

        self.assertIs(ledger.status, CompletionStatusV2.VIOLATED)
        self.assertIn("duplicate_unit_claim", _codes(ledger))

    def test_stale_and_unknown_unit_claims_are_violated(self) -> None:
        unit = _unit("left", 0x1000, "c")
        stale = _unit("left", 0x1000, "d")
        unknown = _unit("unknown", 0x2000, "e")
        ledger = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.PORTABLE_APPLICATION,
            binary=_binary(),
            structural_units=[unit],
            ownership_records=[
                UnitOwnershipRecordV2.create(
                    owner=_owner(
                        ImplementationOwnerKindV2.PORTABLE_COMPONENT,
                        "source",
                        "f",
                    ),
                    units=[stale, unknown],
                )
            ],
        )

        self.assertIs(ledger.status, CompletionStatusV2.VIOLATED)
        self.assertTrue(
            {"stale_unit_claim", "unknown_unit_claim"} <= _codes(ledger)
        )

    def test_duplicate_structural_identity_and_stale_inventory_are_violated(self) -> None:
        unit = _unit("left", 0x1000, "c")
        conflicting = _unit("left", 0x1010, "d")
        ledger = ImplementationLedgerV2(
            profile=CompletionProfileV2.STATIC_BASELINE,
            binary=_binary(),
            exact_unit_inventory_sha256=_digest("0"),
            structural_units=(unit, conflicting),
            ownership_records=(),
        )

        self.assertIs(ledger.status, CompletionStatusV2.VIOLATED)
        self.assertTrue(
            {"duplicate_structural_unit", "stale_structural_unit_inventory"}
            <= _codes(ledger)
        )

    def test_missing_owner_evidence_is_incomplete_but_unassigned_evidence_is_violated(self) -> None:
        unit = _unit("left", 0x1000, "c")
        missing = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.PORTABLE_APPLICATION,
            binary=_binary(),
            structural_units=[unit],
            ownership_records=[
                UnitOwnershipRecordV2.create(
                    owner=ImplementationOwnerV2(
                        ImplementationOwnerKindV2.PORTABLE_COMPONENT,
                        None,
                        None,
                    ),
                    units=[unit],
                )
            ],
        )
        contradictory = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.STATIC_BASELINE,
            binary=_binary(),
            structural_units=[unit],
            ownership_records=[
                UnitOwnershipRecordV2.create(
                    owner=ImplementationOwnerV2(
                        ImplementationOwnerKindV2.UNASSIGNED,
                        _artifact("implementation", "unexpected", "d"),
                        None,
                    ),
                    units=[unit],
                )
            ],
        )

        self.assertIs(missing.status, CompletionStatusV2.INCOMPLETE)
        self.assertTrue(
            {"implementation_identity_missing", "qualification_identity_missing"}
            <= _codes(missing)
        )
        self.assertIs(contradictory.status, CompletionStatusV2.VIOLATED)
        self.assertIn("unassigned_owner_has_evidence", _codes(contradictory))

    def test_parser_rejects_stale_status_issue_and_ids(self) -> None:
        unit = _unit("left", 0x1000, "c")
        ledger = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.PORTABLE_APPLICATION,
            binary=_binary(),
            structural_units=[unit],
            ownership_records=[
                UnitOwnershipRecordV2.create(
                    owner=_owner(
                        ImplementationOwnerKindV2.PORTABLE_COMPONENT,
                        "source",
                        "d",
                    ),
                    units=[unit],
                )
            ],
        )
        for mutation in ("status", "issues", "ledger_id", "record_id"):
            with self.subTest(mutation=mutation):
                payload = json.loads(ledger.to_json())
                if mutation == "status":
                    payload["status"] = "incomplete"
                elif mutation == "issues":
                    payload["issues"] = [{
                        "status": "incomplete",
                        "code": "forged",
                        "location": "ledger",
                        "detail": "forged issue",
                    }]
                elif mutation == "ledger_id":
                    payload["ledger_id"] = "implementation-ledger-v2:" + _digest("0")
                else:
                    payload["ownership_records"][0]["record_id"] = (
                        "implementation-owner-v2:" + _digest("0")
                    )
                with self.assertRaises(AuthorityDataError):
                    ImplementationLedgerV2.parse(payload)

    def test_schema_is_immutable_and_rejects_non_v2_payloads(self) -> None:
        identity = _artifact("qualification", "source", "c")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            identity.sha256 = _digest("d")  # type: ignore[misc]

        unit = _unit("left", 0x1000, "c")
        ledger = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.STATIC_BASELINE,
            binary=_binary(),
            structural_units=[unit],
            ownership_records=[],
        )
        payload = json.loads(ledger.to_json())
        payload["schema_version"] = 1
        with self.assertRaises(AuthorityDataError):
            ImplementationLedgerV2.parse(payload)

    def test_complete_compact_binding_cannot_claim_an_empty_ledger(self) -> None:
        complete = ImplementationLedgerV2.create(
            profile=CompletionProfileV2.STATIC_BASELINE,
            binary=_binary(),
            structural_units=[_unit("left", 0x1000, "c")],
            ownership_records=[
                UnitOwnershipRecordV2.create(
                    owner=_owner(
                        ImplementationOwnerKindV2.MACHINE_IR_FALLBACK,
                        "fallback",
                        "d",
                    ),
                    units=[_unit("left", 0x1000, "c")],
                )
            ],
        ).to_binding()
        with self.assertRaises(AuthorityDataError):
            dataclasses.replace(
                complete,
                structural_unit_count=0,
                ownership_record_count=0,
                qualification_requirements=(),
            )


if __name__ == "__main__":
    unittest.main()
