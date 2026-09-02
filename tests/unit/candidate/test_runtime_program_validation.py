from __future__ import annotations

import json
import unittest
from types import SimpleNamespace

from spaghetti_extractor.candidate.runtime_model import CandidateRuntimeError
from spaghetti_extractor.candidate.runtime_program_validation import (
    validate_transfer_plan_runtime_metadata,
)
from spaghetti_extractor.util import sha256_bytes


def _payload(location: object) -> dict[str, object]:
    expression = {"name": "eax", "op": "reg", "width": 32}
    choice = {
        "format": "spaghetti-extractor-definedness-choice-source-v4",
        "kind": "related_machine_input",
        "slot": 7,
        "undefined_id": "1000:eax",
        "profile": "ia32-bsr-zero-preserves-destination-v1",
        "instruction_rva": 0x1000,
        "instruction_sha256": "1" * 64,
        "instruction_model": "sanitized_typed_machine_ir_v2",
        "location": location,
        "input_expression": expression,
        "input_expression_sha256": sha256_bytes(
            json.dumps(
                expression,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ),
    }
    definedness = {
        "format": "spaghetti-extractor-definedness-noninterference-v4",
        "status": "complete",
        "proof_authority": False,
        "slots": [{
            "slot": 7,
            "undefined_id": "1000:eax",
            "classification": "synchronized_behavior_relevant",
            "witness_policy": "synchronized",
            "choice_source": choice,
            "proof_obligations": [],
            "occurrences": [{"transfer_id": "unit:1000"}],
        }],
    }
    evidence_body = dict(definedness)
    definedness["evidence_sha256"] = sha256_bytes(
        json.dumps(
            evidence_body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    )
    return {"diagnostics": {"definedness": definedness}}


class TransferPlanRuntimeMetadataTests(unittest.TestCase):
    def test_projects_canonical_structured_register_location(self) -> None:
        _rvas, _bindings, policies, _evidence = (
            validate_transfer_plan_runtime_metadata(
                _payload({"family": "register", "name": "eax"}),
                (SimpleNamespace(identity="unit:1000", rva_start=0x1000),),
            )
        )
        self.assertEqual(policies[0].input_location, "eax")
        self.assertEqual(policies[0].choice_kind, "related_machine_input")

    def test_rejects_retired_string_register_location(self) -> None:
        with self.assertRaisesRegex(
            CandidateRuntimeError, "synchronized undefined input location"
        ):
            validate_transfer_plan_runtime_metadata(
                _payload("eax"),
                (SimpleNamespace(identity="unit:1000", rva_start=0x1000),),
            )


if __name__ == "__main__":
    unittest.main()
