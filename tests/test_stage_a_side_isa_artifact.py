import copy
import unittest

from spaghetti_extractor.relational.side_extraction_artifact import (
    parse_request,
    request_payload,
)
from spaghetti_extractor.relational.side_isa_artifact import (
    parse_side_isa_unbound,
    select_side_isa_spans,
    side_isa_payload,
)
from spaghetti_extractor.stage_binary import StageAInputError


class StageASideISAArtifactTests(unittest.TestCase):
    def setUp(self):
        self.binary_sha256 = "a" * 64
        self.hashes = {
            "classifier_sha256": "b" * 64,
            "extractor_sha256": "c" * 64,
            "source_sha256": "d" * 64,
        }
        contract = {
            "regions": [
                {
                    "id": "first",
                    "numeric_id": 0,
                    "original": {"rva_start": 0x1000, "size": 2},
                    "candidate": {"rva_start": 0x2000, "size": 2},
                },
                {
                    "id": "second",
                    "numeric_id": 1,
                    "original": {"rva_start": 0x1002, "size": 1},
                    "candidate": {"rva_start": 0x2002, "size": 1},
                },
            ]
        }
        self.request = parse_request(
            request_payload(contract, "original", self.binary_sha256)
        )
        self.forms = {
            ("original", 0): (
                {"rva": 0x1000, "size": 2, "bytes": "eb00", "form": "jump"},
            ),
            ("original", 1): (
                {"rva": 0x1002, "size": 1, "bytes": "c3", "form": "return"},
            ),
        }

    def test_roundtrip_and_span_selection(self):
        artifact = side_isa_payload(
            self.request, forms=self.forms, **self.hashes
        )
        request, rows = parse_side_isa_unbound(
            artifact,
            expected_side="original",
            expected_binary_sha256=self.binary_sha256,
            **self.hashes,
        )
        self.assertEqual(request, self.request)
        self.assertEqual(rows[0][0]["form"], "jump")
        selected = select_side_isa_spans(
            artifact, expected_request=self.request, **self.hashes
        )
        self.assertEqual(selected, self.forms)

    def test_tampering_and_span_gaps_fail_closed(self):
        artifact = side_isa_payload(
            self.request, forms=self.forms, **self.hashes
        )
        tampered = copy.deepcopy(artifact)
        tampered["regions"][0]["occurrences"][0]["bytes"] = "9090"
        with self.assertRaisesRegex(StageAInputError, "hash mismatch"):
            parse_side_isa_unbound(
                tampered,
                expected_side="original",
                expected_binary_sha256=self.binary_sha256,
                **self.hashes,
            )

        gap = copy.deepcopy(self.forms)
        gap[("original", 0)] = (
            {"rva": 0x1001, "size": 1, "bytes": "00", "form": "bad"},
        )
        with self.assertRaises(StageAInputError):
            side_isa_payload(self.request, forms=gap, **self.hashes)


if __name__ == "__main__":
    unittest.main()
