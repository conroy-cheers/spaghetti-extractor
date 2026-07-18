import copy
import hashlib
import json
import unittest

from spaghetti_extractor.relational.pair_normalization_artifact import (
    PAIR_NORMALIZATION_FORMAT,
    PAIR_NORMALIZATION_STATUS,
    canonical_relation_contract_sha256,
    pair_normalization_payload,
    parse_pair_normalization,
)
from spaghetti_extractor.relational.schema import (
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
)
from spaghetti_extractor.stage_binary import StageAInputError


REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")


def _contract() -> dict[str, object]:
    return {
        "format": "stage-a-relation-contract-v1",
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "environment": {"id": "adversarial-pe32-external-v1"},
        "regions": [
            {
                "id": "entry",
                "numeric_id": 10,
                "root": True,
                "original": {
                    "rva_start": 0x1000,
                    "rva_end": 0x1002,
                    "size": 2,
                },
                "candidate": {
                    "rva_start": 0x2000,
                    "rva_end": 0x2003,
                    "size": 3,
                },
            },
            {
                "id": "return",
                "numeric_id": 40,
                "root": False,
                "original": {
                    "rva_start": 0x1002,
                    "rva_end": 0x1003,
                    "size": 1,
                },
                "candidate": {
                    "rva_start": 0x2003,
                    "rva_end": 0x2004,
                    "size": 1,
                },
            },
        ],
    }


def _expression(operation: str, **fields: object) -> dict[str, object]:
    return {"op": operation, **fields}


def _semantic_ir(outcome: dict[str, object]) -> dict[str, object]:
    return {
        "format": "stage-a-normalized-behavior-v1",
        "registers": {
            register: _expression("input_reg", reg=register)
            for register in REGISTERS
        },
        "x87": {
            "stack": [
                _expression("input_stack", index=index) for index in range(8)
            ],
            "control": _expression("input_x87_control"),
            "status": _expression("input_x87_status"),
        },
        "writes": [],
        "flags": {
            "auxiliary": None,
            "carry": _expression("input_flag", index=0),
            "parity": _expression("input_flag", index=2),
            "zero": _expression("input_flag", index=6),
            "sign": _expression("input_flag", index=7),
            "overflow": _expression("input_flag", index=11),
        },
        "outcome": outcome,
    }


def _behaviors() -> list[dict[str, object]]:
    return [
        {
            "original": (
                "{ registers := originalEntry, x87 := originalX87, "
                "writes := [], flags := none, outcome := jump 40 }"
            ),
            "candidate": (
                "{ registers := candidateEntry, x87 := candidateX87, "
                "writes := [], flags := none, outcome := jump 40 }"
            ),
            "original_ir": _semantic_ir({"op": "jump", "target": 40}),
            "candidate_ir": _semantic_ir({"op": "jump", "target": 40}),
        },
        {
            "original": (
                "{ registers := originalReturn, x87 := originalX87, "
                "writes := [], flags := none, outcome := returned eax }"
            ),
            "candidate": (
                "{ registers := candidateReturn, x87 := candidateX87, "
                "writes := [], flags := none, outcome := returned eax }"
            ),
            "original_ir": _semantic_ir({
                "op": "returned",
                "target": _expression("input_reg", reg="eax"),
            }),
            "candidate_ir": _semantic_ir({
                "op": "returned",
                "target": _expression("input_reg", reg="eax"),
            }),
        },
    ]


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


class StageAPairNormalizationArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_sha256 = "a" * 64
        self.candidate_sha256 = "b" * 64
        self.original_extraction_sha256 = "c" * 64
        self.candidate_extraction_sha256 = "d" * 64
        self.normalizer_semantics_sha256 = "e" * 64
        self.contract = _contract()
        self.behaviors = _behaviors()

    def _payload(self) -> dict[str, object]:
        return pair_normalization_payload(
            original_sha256=self.original_sha256,
            candidate_sha256=self.candidate_sha256,
            relation_contract=self.contract,
            original_extraction_sha256=self.original_extraction_sha256,
            candidate_extraction_sha256=self.candidate_extraction_sha256,
            normalizer_semantics_sha256=self.normalizer_semantics_sha256,
            behaviors=self.behaviors,
        )

    def _parse(
        self,
        payload: object,
        *,
        contract: dict[str, object] | None = None,
    ) -> list[dict[str, object]]:
        return parse_pair_normalization(
            payload,
            expected_original_sha256=self.original_sha256,
            expected_candidate_sha256=self.candidate_sha256,
            expected_contract=self.contract if contract is None else contract,
            expected_original_extraction_sha256=(
                self.original_extraction_sha256
            ),
            expected_candidate_extraction_sha256=(
                self.candidate_extraction_sha256
            ),
            expected_normalizer_semantics_sha256=(
                self.normalizer_semantics_sha256
            ),
        )

    def test_roundtrip_binds_all_identities_and_canonical_rows(self):
        payload = self._payload()
        self.assertEqual(payload["format"], PAIR_NORMALIZATION_FORMAT)
        self.assertEqual(payload["profile"], STAGE_A_RELATIONAL_PROFILE_ID)
        self.assertEqual(payload["model"], STAGE_A_RELATIONAL_MODEL_ID)
        self.assertEqual(payload["status"], PAIR_NORMALIZATION_STATUS)
        self.assertEqual(
            payload["relation_contract_sha256"],
            canonical_relation_contract_sha256(self.contract),
        )
        self.assertEqual(
            payload["regions"][0]["id"], self.contract["regions"][0]["id"]
        )
        self.assertEqual(
            payload["regions"][1]["numeric_id"],
            self.contract["regions"][1]["numeric_id"],
        )
        self.assertEqual(
            self._parse(json.loads(json.dumps(payload))), self.behaviors
        )

        self.assertEqual(
            parse_pair_normalization(
                payload,
                expected_original_sha256=self.original_sha256,
                expected_candidate_sha256=self.candidate_sha256,
                expected_relation_contract=self.contract,
                expected_original_extraction_sha256=(
                    self.original_extraction_sha256
                ),
                expected_candidate_extraction_sha256=(
                    self.candidate_extraction_sha256
                ),
                expected_normalizer_semantics_sha256=(
                    self.normalizer_semantics_sha256
                ),
            ),
            self.behaviors,
        )

    def test_contract_hash_is_canonical_and_content_sensitive(self):
        reordered = {
            key: copy.deepcopy(self.contract[key])
            for key in reversed(list(self.contract))
        }
        self.assertEqual(
            canonical_relation_contract_sha256(self.contract),
            canonical_relation_contract_sha256(reordered),
        )

        changed = copy.deepcopy(self.contract)
        changed["regions"][0]["candidate"]["rva_end"] += 1
        changed["regions"][0]["candidate"]["size"] += 1
        self.assertNotEqual(
            canonical_relation_contract_sha256(self.contract),
            canonical_relation_contract_sha256(changed),
        )

    def test_top_level_fields_and_all_expected_identities_fail_closed(self):
        payload = self._payload()
        replacements = {
            "format": "unsupported",
            "profile": "unsupported",
            "model": "unsupported",
            "status": "proved",
            "original_sha256": "f" * 64,
            "candidate_sha256": "f" * 64,
            "relation_contract_sha256": "f" * 64,
            "original_extraction_sha256": "f" * 64,
            "candidate_extraction_sha256": "f" * 64,
            "normalizer_semantics_sha256": "f" * 64,
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                malformed = copy.deepcopy(payload)
                malformed[field] = replacement
                with self.assertRaisesRegex(StageAInputError, f"{field} mismatch"):
                    self._parse(malformed)

        for field in ("status", "regions"):
            malformed = copy.deepcopy(payload)
            del malformed[field]
            with self.assertRaisesRegex(StageAInputError, "missing fields"):
                self._parse(malformed)
        malformed = copy.deepcopy(payload)
        malformed["unchecked"] = True
        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            self._parse(malformed)

    def test_term_and_ir_tampering_is_detected_by_content_hashes(self):
        payload = self._payload()
        tampered_term = copy.deepcopy(payload)
        tampered_term["regions"][0]["original_term"] = (
            "{ registers := tampered, x87 := originalX87, writes := [], "
            "flags := none, outcome := jump 40 }"
        )
        with self.assertRaisesRegex(StageAInputError, "term hash mismatch"):
            self._parse(tampered_term)

        tampered_ir = copy.deepcopy(payload)
        tampered_ir["regions"][0]["candidate_ir"]["outcome"]["target"] = 41
        with self.assertRaisesRegex(StageAInputError, "semantic IR hash mismatch"):
            self._parse(tampered_ir)

    def test_malformed_terms_are_rejected_even_if_attacker_rehashes(self):
        payload = self._payload()
        malformed_terms = (
            " { registers := value }",
            "{ registers  := value }",
            "{ registers := value",
            "some behavior",
            "{ registers := value }\n",
        )
        for term in malformed_terms:
            with self.subTest(term=term):
                malformed = copy.deepcopy(payload)
                malformed["regions"][0]["original_term"] = term
                malformed["regions"][0]["original_term_sha256"] = (
                    hashlib.sha256(term.encode("utf-8")).hexdigest()
                )
                with self.assertRaises(StageAInputError):
                    self._parse(malformed)

    def test_malformed_semantic_ir_is_rejected_even_if_rehashed(self):
        payload = self._payload()
        malformed_irs = []

        missing_field = copy.deepcopy(payload["regions"][0]["original_ir"])
        del missing_field["outcome"]
        malformed_irs.append(missing_field)

        extra_field = copy.deepcopy(payload["regions"][0]["original_ir"])
        extra_field["unchecked"] = True
        malformed_irs.append(extra_field)

        wrong_format = copy.deepcopy(payload["regions"][0]["original_ir"])
        wrong_format["format"] = "stage-a-normalized-behavior-v2"
        malformed_irs.append(wrong_format)

        missing_register = copy.deepcopy(payload["regions"][0]["original_ir"])
        del missing_register["registers"]["eax"]
        malformed_irs.append(missing_register)

        malformed_x87 = copy.deepcopy(payload["regions"][0]["original_ir"])
        malformed_x87["x87"]["stack"] = {"unchecked": True}
        malformed_irs.append(malformed_x87)

        malformed_expression = copy.deepcopy(
            payload["regions"][0]["original_ir"]
        )
        malformed_expression["registers"]["eax"] = {"reg": "eax"}
        malformed_irs.append(malformed_expression)

        non_json = copy.deepcopy(payload["regions"][0]["original_ir"])
        non_json["outcome"]["weight"] = 1.5
        malformed_irs.append(non_json)

        for semantic_ir in malformed_irs:
            with self.subTest(semantic_ir=semantic_ir):
                malformed = copy.deepcopy(payload)
                malformed["regions"][0]["original_ir"] = semantic_ir
                malformed["regions"][0]["original_ir_sha256"] = (
                    _canonical_sha256(semantic_ir)
                )
                with self.assertRaises(StageAInputError):
                    self._parse(malformed)

    def test_duplicate_reordered_and_noncanonical_region_rows_are_rejected(self):
        payload = self._payload()
        mutations = (
            lambda rows: rows.reverse(),
            lambda rows: rows.__setitem__(1, copy.deepcopy(rows[0])),
            lambda rows: rows.pop(),
            lambda rows: rows.append(copy.deepcopy(rows[-1])),
        )
        for mutate in mutations:
            malformed = copy.deepcopy(payload)
            mutate(malformed["regions"])
            with self.assertRaises(StageAInputError):
                self._parse(malformed)

        for region_index in (0, 1):
            malformed_index = copy.deepcopy(payload)
            malformed_index["regions"][region_index]["index"] = True
            with self.assertRaisesRegex(StageAInputError, "must be an integer"):
                self._parse(malformed_index)

        malformed_numeric_id = copy.deepcopy(payload)
        malformed_numeric_id["regions"][1]["numeric_id"] = True
        with self.assertRaisesRegex(StageAInputError, "must be an integer"):
            self._parse(malformed_numeric_id)

        malformed_identity = copy.deepcopy(payload)
        malformed_identity["regions"][0]["id"] = "different"
        with self.assertRaisesRegex(StageAInputError, "canonical contract order"):
            self._parse(malformed_identity)

        extra_region_field = copy.deepcopy(payload)
        extra_region_field["regions"][0]["unchecked"] = True
        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            self._parse(extra_region_field)

    def test_contract_identity_and_structure_are_checked(self):
        payload = self._payload()
        changed = copy.deepcopy(self.contract)
        changed["regions"][0]["candidate"]["rva_end"] += 1
        changed["regions"][0]["candidate"]["size"] += 1
        with self.assertRaisesRegex(StageAInputError, "contract_sha256 mismatch"):
            self._parse(payload, contract=changed)

        malformed_contracts = []
        duplicate_id = copy.deepcopy(self.contract)
        duplicate_id["regions"][1]["id"] = "entry"
        malformed_contracts.append(duplicate_id)
        duplicate_numeric_id = copy.deepcopy(self.contract)
        duplicate_numeric_id["regions"][1]["numeric_id"] = 10
        malformed_contracts.append(duplicate_numeric_id)
        invalid_span = copy.deepcopy(self.contract)
        invalid_span["regions"][0]["original"]["rva_end"] += 1
        malformed_contracts.append(invalid_span)
        wrong_model = copy.deepcopy(self.contract)
        wrong_model["model"] = "other"
        malformed_contracts.append(wrong_model)

        for contract in malformed_contracts:
            with self.assertRaises(StageAInputError):
                canonical_relation_contract_sha256(contract)

    def test_builder_rejects_partial_rows_bad_counts_and_bad_hashes(self):
        partial = copy.deepcopy(self.behaviors)
        partial[0]["unchecked"] = True
        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            pair_normalization_payload(
                original_sha256=self.original_sha256,
                candidate_sha256=self.candidate_sha256,
                relation_contract=self.contract,
                original_extraction_sha256=self.original_extraction_sha256,
                candidate_extraction_sha256=self.candidate_extraction_sha256,
                normalizer_semantics_sha256=self.normalizer_semantics_sha256,
                behaviors=partial,
            )

        with self.assertRaisesRegex(StageAInputError, "count does not match"):
            pair_normalization_payload(
                original_sha256=self.original_sha256,
                candidate_sha256=self.candidate_sha256,
                relation_contract=self.contract,
                original_extraction_sha256=self.original_extraction_sha256,
                candidate_extraction_sha256=self.candidate_extraction_sha256,
                normalizer_semantics_sha256=self.normalizer_semantics_sha256,
                behaviors=self.behaviors[:-1],
            )

        with self.assertRaisesRegex(StageAInputError, "lowercase hex"):
            pair_normalization_payload(
                original_sha256="A" * 64,
                candidate_sha256=self.candidate_sha256,
                relation_contract=self.contract,
                original_extraction_sha256=self.original_extraction_sha256,
                candidate_extraction_sha256=self.candidate_extraction_sha256,
                normalizer_semantics_sha256=self.normalizer_semantics_sha256,
                behaviors=self.behaviors,
            )

    def test_expected_contract_alias_is_unambiguous(self):
        payload = self._payload()
        common = {
            "expected_original_sha256": self.original_sha256,
            "expected_candidate_sha256": self.candidate_sha256,
            "expected_original_extraction_sha256": (
                self.original_extraction_sha256
            ),
            "expected_candidate_extraction_sha256": (
                self.candidate_extraction_sha256
            ),
            "expected_normalizer_semantics_sha256": (
                self.normalizer_semantics_sha256
            ),
        }
        with self.assertRaisesRegex(StageAInputError, "exactly one"):
            parse_pair_normalization(payload, **common)
        with self.assertRaisesRegex(StageAInputError, "exactly one"):
            parse_pair_normalization(
                payload,
                expected_contract=self.contract,
                expected_relation_contract=self.contract,
                **common,
            )


if __name__ == "__main__":
    unittest.main()
