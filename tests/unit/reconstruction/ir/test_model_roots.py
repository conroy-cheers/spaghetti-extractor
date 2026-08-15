from __future__ import annotations

from tests.unit.reconstruction.ir._support import *


class ReconstructionIRRootModelTests(unittest.TestCase):
    def test_binary_tls_callbacks_are_roots_even_with_a_submitted_root(self) -> None:
        rows = [
            _row(
                "semantic-transfer:return",
                0x1000,
                b"\xc3",
                outcome={"kind": "return"},
            ),
            _row(
                "semantic-transfer:tls",
                0x1010,
                b"\xc2\x0c\x00",
                outcome={"kind": "return"},
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            static_program = root / "static-program-contract.json"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_tls_image((0x1010,)))
            _write_static_program_contract(static_program, original)
            for row in rows:
                row["static_program_export"] = {
                    "format": "spaghetti-extractor-static-program-semantic-binding-v2",
                    "static_program_contract_sha256": sha256_file(static_program),
                    "semantic_transfer_sha256": "b" * 64,
                }
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                static_program_contract=static_program,
                out=root / "out",
            )
            roots = _read_json(package.manifest)["control"]["roots"]

            self.assertEqual([root["rva"] for root in roots], [0x1000, 0x1010])
            self.assertEqual(roots[0]["kind"], "pe_entrypoint")
            self.assertEqual(roots[0]["block_id"], "return")
            self.assertEqual(roots[1]["kind"], "pe_tls_callback")

    def test_checked_callback_provenance_proposes_a_root(self) -> None:
        callback_rva = 0x2200
        roots = _callback_root_proposals_from_provenance({
            "callback_registrations": [{
                "format": "stage-a-callback-registration-provenance-v1",
                "status": "complete",
                "unit_id": "unit:register",
                "event_index": 0,
                "import": {
                    "dll": "kernel32.dll",
                    "symbol": "SetUnhandledExceptionFilter",
                    "ordinal": None,
                },
                "callback_source": {
                    "kind": "argument_word",
                    "argument": 0,
                },
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 1,
                    "stack_cleanup_bytes": 4,
                    "nullable": True,
                },
                "target_rvas": [callback_rva],
            }],
        })

        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]["rva"], callback_rva)
        self.assertEqual(roots[0]["source_unit_id"], "unit:register")

    def test_incomplete_callback_provenance_does_not_propose_a_root(self) -> None:
        callback_rva = 0x2203
        roots = _callback_root_proposals_from_provenance({
            "callback_registrations": [{
                "format": "stage-a-callback-registration-provenance-v1",
                "status": "incomplete",
                "unit_id": "unit:register",
                "event_index": 0,
                "target_rvas": [callback_rva],
                "failure": {"code": "callback_target_not_canonical_code"},
            }],
        })

        self.assertEqual(roots, [])

    def test_local_direct_callback_bootstraps_an_interior_cutpoint(self) -> None:
        stack_address = {
            "op": "sub32",
            "args": [
                _expr_register("esp"),
                {"op": "const", "value": 4, "width": 32},
            ],
        }
        callback_rva = 0x2203
        event = {
            "kind": "external_call",
            "dll": "kernel32.dll",
            "symbol": "SetUnhandledExceptionFilter",
            "ordinal": None,
            "return_rva": 0x110B,
            "stack_inputs": [{
                "offset": 0,
                "width": 4,
                "value": {"op": "load", "address": stack_address, "width": 4},
            }],
            "abi_contract": {
                "argument_words": 1,
                "world_effect": "callbackRegistration",
                "callback_source": {
                    "kind": "argument_word",
                    "argument": 0,
                },
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 1,
                    "stack_cleanup_bytes": 4,
                    "nullable": True,
                },
            },
        }
        units = [{
            "id": "unit:registration",
            "semantics": {
                "external_events": [event],
                "ordered_events": [
                    {
                        "kind": "write",
                        "instruction_rva": 0x1100,
                        "address": stack_address,
                        "width": 4,
                        "value": {
                            "op": "const",
                            "value": 0x400000 + callback_rva,
                            "width": 32,
                        },
                    },
                    {**event, "instruction_rva": 0x1105},
                ],
            },
        }]
        binary = SimpleNamespace(
            image_base=0x400000,
            sections=(SimpleNamespace(
                executable=True,
                rva_start=0x2000,
                rva_end=0x2300,
            ),),
        )

        roots = _local_callback_cutpoint_proposals(binary, units)

        self.assertEqual([root["rva"] for root in roots], [callback_rva])
        self.assertFalse(roots[0]["proof_authority"])

    def test_callback_root_requires_a_reachable_registration_source(self) -> None:
        proposals = [
            {
                "kind": "registered_callback",
                "rva": 0x2200,
                "source_unit_id": "unit:registration",
            }
        ]

        self.assertEqual(
            _newly_eligible_callback_roots(proposals, {"unit:other"}, {}), []
        )
        self.assertEqual(
            _newly_eligible_callback_roots(
                proposals, {"unit:registration"}, {}
            ),
            proposals,
        )


if __name__ == "__main__":
    unittest.main()
