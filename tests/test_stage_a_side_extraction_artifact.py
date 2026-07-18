import copy
import unittest

from spaghetti_extractor.relational.side_extraction_artifact import (
    SIDE_EXTRACTION_REQUEST_FORMAT,
    SIDE_EXTRACTION_RESULT_FORMAT,
    canonical_request_sha256,
    parse_request,
    parse_result,
    request_payload,
    result_payload,
    select_result_spans,
)
from spaghetti_extractor.stage_binary import StageAInputError


def _contract() -> dict[str, object]:
    return {
        "format": "stage-a-relation-contract-v1",
        "machine_import_call_contracts": [
            {
                "id": 0,
                "import": {"dll": "kernel32.dll", "symbol": "ExitProcess"},
                "stack_argument_offsets": [0],
                "stack_result_delta": 0,
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "result_register_relations": [],
                "disposition": "terminates",
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "none",
            }
        ],
        "regions": [
            {
                "id": "entry",
                "numeric_id": 0,
                "original": {"rva_start": 0x1000, "rva_end": 0x1002, "size": 2},
                "candidate": {"rva_start": 0x2000, "rva_end": 0x2003, "size": 3},
                "candidate_only_analysis": {"ignored": True},
            },
            {
                "id": "return",
                "numeric_id": 1,
                "original": {"rva_start": 0x1002, "rva_end": 0x1003, "size": 1},
                "candidate": {"rva_start": 0x2003, "rva_end": 0x2004, "size": 1},
            },
        ],
    }


class StageASideExtractionArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.binary_sha256 = "a" * 64
        self.decoder_semantics_sha256 = "b" * 64

    def _request(self, side: str = "original"):
        return parse_request(
            request_payload(_contract(), side, self.binary_sha256)
        )

    def _result(self):
        request = self._request()
        payload = result_payload(
            request,
            self.decoder_semantics_sha256,
            ["(entry behavior)", "(return behavior)"],
        )
        return request, payload

    def test_request_and_result_roundtrip(self):
        request_payload_value = request_payload(
            _contract(), "original", self.binary_sha256
        )
        request = parse_request(request_payload_value)
        self.assertEqual(request_payload_value["format"], SIDE_EXTRACTION_REQUEST_FORMAT)
        self.assertNotIn("machine_import_call_contracts", request_payload_value)
        self.assertEqual(request.to_payload(), request_payload_value)
        self.assertEqual(
            request_payload_value["regions"][0]["span"],
            {"rva_start": 0x1000, "size": 2},
        )

        payload = result_payload(
            request,
            self.decoder_semantics_sha256,
            ["(entry behavior)", "(return behavior)"],
        )
        self.assertEqual(payload["format"], SIDE_EXTRACTION_RESULT_FORMAT)
        self.assertNotIn("machine_import_call_contracts", payload)
        self.assertEqual(payload["request_sha256"], canonical_request_sha256(request))
        self.assertEqual(
            parse_result(
                payload,
                expected_request=request,
                expected_decoder_semantics_sha256=self.decoder_semantics_sha256,
            ),
            ["(entry behavior)", "(return behavior)"],
        )

    def test_candidate_only_contract_fields_do_not_change_original_request_hash(self):
        contract = _contract()
        baseline = request_payload(contract, "original", self.binary_sha256)
        changed = copy.deepcopy(contract)
        changed["regions"][0]["candidate"] = {
            "rva_start": 0x9000,
            "rva_end": 0x9010,
            "size": 0x10,
            "candidate_only": "changed",
        }
        changed["regions"][0]["candidate_only_analysis"] = {
            "ignored": False,
        }
        changed["machine_import_call_contracts"] = [
            {"candidate_pair_normalization_only": True}
        ]
        projected = request_payload(changed, "original", self.binary_sha256)
        self.assertEqual(
            canonical_request_sha256(baseline),
            canonical_request_sha256(projected),
        )

    def test_original_span_changes_original_request_hash(self):
        contract = _contract()
        baseline = request_payload(contract, "original", self.binary_sha256)
        changed = copy.deepcopy(contract)
        changed["regions"][0]["original"] = {
            "rva_start": 0x1001,
            "rva_end": 0x1003,
            "size": 2,
        }
        projected = request_payload(changed, "original", self.binary_sha256)
        self.assertNotEqual(
            canonical_request_sha256(baseline),
            canonical_request_sha256(projected),
        )

    def test_tampered_behavior_and_region_inventory_fail_closed(self):
        request, payload = self._result()
        tampered = copy.deepcopy(payload)
        tampered["regions"][0]["behavior_term"] = "(tampered)"
        with self.assertRaisesRegex(StageAInputError, "behavior hash mismatch"):
            parse_result(
                tampered,
                expected_request=request,
                expected_decoder_semantics_sha256=self.decoder_semantics_sha256,
            )

        for mutate in (
            lambda rows: rows.reverse(),
            lambda rows: rows.pop(),
            lambda rows: rows.append(copy.deepcopy(rows[-1])),
        ):
            malformed = copy.deepcopy(payload)
            mutate(malformed["regions"])
            with self.assertRaises(StageAInputError):
                parse_result(
                    malformed,
                    expected_request=request,
                    expected_decoder_semantics_sha256=self.decoder_semantics_sha256,
                )

        extra = copy.deepcopy(payload)
        extra["regions"][0]["unexpected"] = True
        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            parse_result(
                extra,
                expected_request=request,
                expected_decoder_semantics_sha256=self.decoder_semantics_sha256,
            )

    def test_wrong_binary_side_and_decoder_hash_fail_closed(self):
        request, payload = self._result()
        for field, value in (
            ("binary_sha256", "c" * 64),
            ("side", "candidate"),
            ("decoder_semantics_sha256", "d" * 64),
        ):
            malformed = copy.deepcopy(payload)
            malformed[field] = value
            with self.assertRaisesRegex(StageAInputError, f"{field} mismatch"):
                parse_result(
                    malformed,
                    expected_request=request,
                    expected_decoder_semantics_sha256=self.decoder_semantics_sha256,
                )

    def test_duplicate_region_ids_and_numeric_ids_are_rejected(self):
        payload = request_payload(_contract(), "original", self.binary_sha256)
        duplicate_id = copy.deepcopy(payload)
        duplicate_id["regions"][1]["id"] = duplicate_id["regions"][0]["id"]
        with self.assertRaisesRegex(StageAInputError, "region ids must be unique"):
            parse_request(duplicate_id)

        duplicate_numeric_id = copy.deepcopy(payload)
        duplicate_numeric_id["regions"][1]["numeric_id"] = 0
        with self.assertRaisesRegex(StageAInputError, "numeric ids must be unique"):
            parse_request(duplicate_numeric_id)

    def test_malformed_spans_and_noncanonical_indices_are_rejected(self):
        payload = request_payload(_contract(), "original", self.binary_sha256)
        malformed_spans = [
            {"rva_start": 0x1000, "size": 0},
            {"rva_start": -1, "size": 1},
            {"rva_start": 0x1000},
            [0x1000, 1],
        ]
        for span in malformed_spans:
            malformed = copy.deepcopy(payload)
            malformed["regions"][0]["span"] = span
            with self.assertRaises(StageAInputError):
                parse_request(malformed)

        reordered = copy.deepcopy(payload)
        reordered["regions"][0]["index"] = 1
        with self.assertRaisesRegex(StageAInputError, "indices are not canonical"):
            parse_request(reordered)

    def test_hashes_lists_objects_and_exact_fields_are_strict(self):
        payload = request_payload(_contract(), "original", self.binary_sha256)
        for bad_hash in ("A" * 64, "a" * 63, "g" * 64):
            malformed = copy.deepcopy(payload)
            malformed["binary_sha256"] = bad_hash
            with self.assertRaises(StageAInputError):
                parse_request(malformed)

        malformed = copy.deepcopy(payload)
        malformed["regions"] = {}
        with self.assertRaisesRegex(StageAInputError, "must be a list"):
            parse_request(malformed)

        malformed = copy.deepcopy(payload)
        malformed["regions"] = ["not-an-object"]
        with self.assertRaisesRegex(StageAInputError, "must be an object"):
            parse_request(malformed)

        malformed = copy.deepcopy(payload)
        malformed["machine_import_call_contracts"] = []
        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            parse_request(malformed)

        malformed = copy.deepcopy(payload)
        malformed["unexpected"] = True
        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            parse_request(malformed)

    def test_pair_request_selects_exact_spans_from_superset_inventory(self):
        inventory_contract = _contract()
        inventory_contract["regions"].insert(
            1,
            {
                "id": "middle",
                "numeric_id": 2,
                "original": {
                    "rva_start": 0x1800,
                    "rva_end": 0x1801,
                    "size": 1,
                },
                "candidate": {
                    "rva_start": 0x2800,
                    "rva_end": 0x2801,
                    "size": 1,
                },
            },
        )
        inventory_request = parse_request(
            request_payload(
                inventory_contract, "original", self.binary_sha256
            )
        )
        inventory = result_payload(
            inventory_request,
            self.decoder_semantics_sha256,
            ["entry", "middle", "return"],
        )
        pair_request = self._request()

        self.assertEqual(
            select_result_spans(
                inventory,
                expected_request=pair_request,
                expected_decoder_semantics_sha256=self.decoder_semantics_sha256,
            ),
            ["entry", "return"],
        )

        omitted = copy.deepcopy(inventory)
        omitted["regions"].pop()
        with self.assertRaises(StageAInputError):
            select_result_spans(
                omitted,
                expected_request=pair_request,
                expected_decoder_semantics_sha256=self.decoder_semantics_sha256,
            )

if __name__ == "__main__":
    unittest.main()
