from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.internal_function_contracts import (
    INTERNAL_FUNCTION_CONTRACT_PROFILE_FORMAT,
    InternalFunctionContractError,
    bind_internal_function_contract_profile,
    load_internal_function_contracts,
    rebind_internal_function_contract_profile,
)


def _unit(identifier: str, rva: int, digest: str) -> dict[str, object]:
    return {
        "id": identifier,
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 4},
            "contract_sha256": digest,
            "instruction_bytes_sha256": "f" * 64,
        },
        "control": {"direct_targets": []},
        "semantics": {"outcome": {"kind": "return"}},
    }


def _profile() -> dict[str, object]:
    return bind_internal_function_contract_profile({
        "format": INTERNAL_FUNCTION_CONTRACT_PROFILE_FORMAT,
        "id": "fixture-runtime-contracts",
        "binary_sha256": "a" * 64,
        "contracts": [{
            "id": "fixture-allocator",
            "entry_unit_id": "allocator",
            "entry_rva": 0x2000,
            "entry_contract_sha256": "b" * 64,
            "entry_instruction_bytes_sha256": "f" * 64,
            "body_units": [{
                "unit_id": "allocator",
                "contract_sha256": "b" * 64,
            }],
            "summary": {
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "stack_cleanup": 0,
                "may_return": True,
                "may_not_return": False,
                "result_register_origins": {
                    "eax": {"relation": "dynamic_range_base", "nullable": True}
                },
            },
        }],
    })


class InternalFunctionContractTests(unittest.TestCase):
    def test_exact_unit_bound_profile_loads_analysis_only_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps(_profile(), sort_keys=True), encoding="utf-8")
            contracts = load_internal_function_contracts(
                [path], binary_sha256="a" * 64, units=[_unit("allocator", 0x2000, "b" * 64)]
            )

        summary = contracts["allocator"]
        self.assertEqual(summary["status"], "complete")
        self.assertFalse(summary["declared_internal_contract"]["replacement_authority"])
        self.assertEqual(
            summary["result_register_origins"]["registers"]["eax"],
            {
                "kind": "internal_contract_result",
                "contract_id": "fixture-allocator",
                "relation": "dynamic_range_base",
                "nullable": True,
            },
        )

    def test_affine_stack_transform_is_normalized(self) -> None:
        payload = copy.deepcopy(_profile())
        summary = payload["contracts"][0]["summary"]
        summary.pop("stack_cleanup")
        summary["stack_transform"] = {
            "format": "stage-a-affine-stack-transform-v1",
            "constant": 0,
            "register_terms": [{"register": "eax", "coefficient": -1}],
        }
        payload = bind_internal_function_contract_profile(payload)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            contracts = load_internal_function_contracts(
                [path],
                binary_sha256="a" * 64,
                units=[_unit("allocator", 0x2000, "b" * 64)],
            )

        cleanup = contracts["allocator"]["stack_cleanup"]
        self.assertIsNone(cleanup["stack_delta"])
        self.assertEqual(
            cleanup["transform"]["register_terms"],
            [{"register": "eax", "coefficient": -1}],
        )

    def test_stale_binary_unit_and_self_hash_fail_closed(self) -> None:
        mutations = {
            "binary": lambda payload: payload.update(binary_sha256="c" * 64),
            "unit": lambda payload: payload["contracts"][0].update(
                entry_contract_sha256="d" * 64
            ),
            "self hash": lambda payload: payload.update(profile_sha256="0" * 64),
            "body omission": lambda payload: payload["contracts"][0].update(
                body_units=[]
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                payload = copy.deepcopy(_profile())
                mutate(payload)
                if label != "self hash":
                    payload = bind_internal_function_contract_profile(payload)
                path = Path(temporary) / "profile.json"
                path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
                with self.assertRaises(InternalFunctionContractError):
                    load_internal_function_contracts(
                        [path],
                        binary_sha256="a" * 64,
                        units=[_unit("allocator", 0x2000, "b" * 64)],
                    )

    def test_rebind_refreshes_only_semantic_hashes(self) -> None:
        rebound = rebind_internal_function_contract_profile(
            _profile(),
            binary_sha256="a" * 64,
            units=[_unit("allocator", 0x2000, "c" * 64)],
        )

        contract = rebound["contracts"][0]
        self.assertEqual(contract["entry_contract_sha256"], "c" * 64)
        self.assertEqual(contract["body_units"], [{
            "unit_id": "allocator",
            "contract_sha256": "c" * 64,
        }])
        self.assertEqual(contract["summary"], _profile()["contracts"][0]["summary"])

    def test_rebind_rejects_byte_or_control_closure_changes(self) -> None:
        changed_bytes = _unit("allocator", 0x2000, "c" * 64)
        changed_bytes["source"]["instruction_bytes_sha256"] = "e" * 64
        with self.assertRaisesRegex(InternalFunctionContractError, "changed bytes"):
            rebind_internal_function_contract_profile(
                _profile(),
                binary_sha256="a" * 64,
                units=[changed_bytes],
            )

        changed_control = _unit("allocator", 0x2000, "c" * 64)
        changed_control["control"]["direct_targets"] = [0x2010]
        with self.assertRaises(InternalFunctionContractError):
            rebind_internal_function_contract_profile(
                _profile(),
                binary_sha256="a" * 64,
                units=[changed_control, _unit("new-body", 0x2010, "d" * 64)],
            )


if __name__ == "__main__":
    unittest.main()
