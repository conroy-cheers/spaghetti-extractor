import json
import unittest

from spaghetti_extractor.relational.analyses.registers import (
    REGISTER_CONTROL_AMBIGUOUS_WRITABLE_LOAD,
    REGISTER_CONTROL_DISJUNCTION_BUDGET_EXCEEDED,
    REGISTER_CONTROL_UNKNOWN_CALL,
    RegisterControlBlockedOutput,
    RegisterControlCallContract,
    RegisterControlCopy,
    RegisterControlEdge,
    RegisterControlImportResult,
    RegisterControlProvenanceAtom,
    RegisterControlRegionTransfer,
    RegisterControlRegisterPair,
    RegisterControlUse,
    build_register_control_provenance_witness,
)


EAX = RegisterControlRegisterPair("eax", "eax")
EBX = RegisterControlRegisterPair("ebx", "ebx")


def _code_atom(
    *,
    region: int,
    register: RegisterControlRegisterPair,
    target: int,
    static: bool = False,
) -> RegisterControlProvenanceAtom:
    return RegisterControlProvenanceAtom(
        kind="static_code_pointer" if static else "exact_code_pointer",
        producer_region_index=region,
        register_pair=register,
        target_id=target,
        claim_kind="immutable_static_word" if static else "exact_constant",
    )


def _import_result(
    *, register: RegisterControlRegisterPair,
) -> RegisterControlImportResult:
    return RegisterControlImportResult(
        register_pair=register,
        import_identity=("KERNEL32.dll", "symbol", "GetLastError"),
    )


def _use(payload: dict, index: int = 0) -> dict:
    return payload["uses"][index]


class StageARegisterControlProvenanceTests(unittest.TestCase):
    def test_import_return_is_held_through_checked_direct_call(self) -> None:
        witness = build_register_control_provenance_witness(
            region_count=3,
            register_pairs=(EAX, EBX),
            entry_region_indices=(0,),
            transfers=(
                RegisterControlRegionTransfer(0, preserve_unmentioned=True),
                RegisterControlRegionTransfer(
                    1,
                    copies=(RegisterControlCopy(output=EBX, source=EAX),),
                    preserve_unmentioned=True,
                ),
                RegisterControlRegionTransfer(2, preserve_unmentioned=True),
            ),
            edges=(
                RegisterControlEdge(0, 1, "call_return", 7),
                RegisterControlEdge(1, 2, "call_return", 8),
            ),
            call_contracts=(
                RegisterControlCallContract(
                    7, import_results=(_import_result(register=EAX),),
                ),
                RegisterControlCallContract(8, preserved_registers=(EBX,)),
            ),
            uses=(RegisterControlUse(2, EBX),),
        )

        payload = witness.to_payload()
        self.assertEqual(
            payload["status"], "proposal_requires_generated_lean_replay"
        )
        self.assertEqual(_use(payload)["status"], "resolved")
        self.assertEqual(_use(payload)["atoms"][0]["kind"], "import_return")
        self.assertEqual(
            _use(payload)["atoms"][0]["import"],
            {"dll": "kernel32.dll", "symbol": "GetLastError"},
        )
        self.assertEqual(
            [edge["contract_status"] for edge in payload["edges"]],
            ["checked", "checked"],
        )
        json.dumps(payload, sort_keys=True, allow_nan=False)

    def test_static_pointer_survives_loop_scc(self) -> None:
        witness = build_register_control_provenance_witness(
            region_count=2,
            register_pairs=(EAX,),
            entry_region_indices=(0,),
            transfers=(
                RegisterControlRegionTransfer(
                    0,
                    producers=(_code_atom(
                        region=0, register=EAX, target=4, static=True,
                    ),),
                ),
                RegisterControlRegionTransfer(1, preserve_unmentioned=True),
            ),
            edges=(
                RegisterControlEdge(0, 1),
                RegisterControlEdge(1, 1),
            ),
            uses=(RegisterControlUse(1, EAX, "indirect_control"),),
        )

        payload = witness.to_payload()
        self.assertEqual(_use(payload)["status"], "resolved")
        self.assertEqual(_use(payload)["atoms"][0]["target_id"], 4)
        loop_scc = next(
            item for item in payload["sccs"] if item["region_indices"] == [1]
        )
        self.assertTrue(loop_scc["cyclic"])
        self.assertRegex(loop_scc["evidence_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(payload["fixed_point"]["converged"])

    def test_unknown_call_fails_closed(self) -> None:
        witness = build_register_control_provenance_witness(
            region_count=2,
            register_pairs=(EAX,),
            entry_region_indices=(0,),
            transfers=(
                RegisterControlRegionTransfer(
                    0,
                    producers=(_code_atom(
                        region=0, register=EAX, target=1,
                    ),),
                ),
                RegisterControlRegionTransfer(1, preserve_unmentioned=True),
            ),
            edges=(RegisterControlEdge(0, 1, "call_return"),),
            uses=(RegisterControlUse(1, EAX, "indirect_control"),),
        )

        payload = witness.to_payload()
        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(payload["edges"][0]["contract_status"], "missing")
        self.assertIn(
            REGISTER_CONTROL_UNKNOWN_CALL,
            {row["code"] for row in payload["blockers"]},
        )
        self.assertEqual(
            _use(payload)["blockers"], [REGISTER_CONTROL_UNKNOWN_CALL]
        )

    def test_ambiguous_writable_load_fails_closed(self) -> None:
        witness = build_register_control_provenance_witness(
            region_count=2,
            register_pairs=(EAX,),
            entry_region_indices=(0,),
            transfers=(
                RegisterControlRegionTransfer(
                    0,
                    blocked_outputs=(RegisterControlBlockedOutput(
                        EAX, REGISTER_CONTROL_AMBIGUOUS_WRITABLE_LOAD,
                    ),),
                ),
                RegisterControlRegionTransfer(1, preserve_unmentioned=True),
            ),
            edges=(RegisterControlEdge(0, 1),),
            uses=(RegisterControlUse(1, EAX, "indirect_control"),),
        )

        payload = witness.to_payload()
        self.assertEqual(payload["status"], "incomplete")
        blockers = payload["blockers"]
        self.assertEqual(blockers[0]["code"], REGISTER_CONTROL_AMBIGUOUS_WRITABLE_LOAD)
        self.assertEqual(blockers[0]["region_index"], 0)
        self.assertEqual(blockers[0]["direction"], "output")
        self.assertEqual(
            _use(payload)["blockers"],
            [REGISTER_CONTROL_AMBIGUOUS_WRITABLE_LOAD],
        )

    def test_finite_disjunction_budget_overflow_fails_closed(self) -> None:
        witness = build_register_control_provenance_witness(
            region_count=3,
            register_pairs=(EAX,),
            entry_region_indices=(0, 1),
            transfers=(
                RegisterControlRegionTransfer(
                    0,
                    producers=(_code_atom(
                        region=0, register=EAX, target=10,
                    ),),
                ),
                RegisterControlRegionTransfer(
                    1,
                    producers=(_code_atom(
                        region=1, register=EAX, target=11,
                    ),),
                ),
                RegisterControlRegionTransfer(2, preserve_unmentioned=True),
            ),
            edges=(RegisterControlEdge(0, 2), RegisterControlEdge(1, 2)),
            uses=(RegisterControlUse(2, EAX, "indirect_control"),),
            finite_disjunction_budget=1,
        )

        payload = witness.to_payload()
        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(
            _use(payload)["blockers"],
            [REGISTER_CONTROL_DISJUNCTION_BUDGET_EXCEEDED],
        )
        self.assertIn(
            REGISTER_CONTROL_DISJUNCTION_BUDGET_EXCEEDED,
            {row["code"] for row in payload["blockers"]},
        )

    def test_witness_is_deterministic(self) -> None:
        kwargs = dict(
            region_count=1,
            register_pairs=(EAX,),
            entry_region_indices=(0,),
            transfers=(RegisterControlRegionTransfer(
                0,
                producers=(_code_atom(region=0, register=EAX, target=0),),
            ),),
            edges=(),
            uses=(RegisterControlUse(0, EAX, "indirect_control"),),
        )
        first = build_register_control_provenance_witness(**kwargs).to_payload()
        second = build_register_control_provenance_witness(**kwargs).to_payload()
        self.assertEqual(first, second)
        self.assertRegex(first["witness_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
