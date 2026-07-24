from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pe_fixtures import pe32_import_image

from spaghetti_extractor.relational.lean.callable_external_proposal import (
    CallableExternalProposalError,
    discover_callable_external_proposal,
    parse_callable_external_profile,
)


def _profile(symbol: bytes = b"resolved_fn") -> dict[str, object]:
    return {
        "format": "stage-a-callable-external-profile-v1",
        "id": "fixture-resolvers-v1",
        "resolvers": [
            {
                "id": 0,
                "import": {
                    "dll": "kernel32.dll",
                    "symbol": "GetProcAddress",
                },
                "result_register": "eax",
                "identity_argument_indices": [1],
                "nullable": True,
            }
        ],
        "targets": [
            {
                "id": 0,
                "resolver_id": 0,
                "identity_arguments": [
                    {
                        "kind": "canonical_static_string",
                        "index": 1,
                        "bytes": list(symbol),
                    }
                ],
                "abis": [
                    {
                        "transfer": "jump",
                        "argument_sources": [],
                        "stack_result_delta": 4,
                        "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                        "clobbered_registers": ["eax", "ecx", "edx"],
                        "memory_effect": "none",
                        "memory_footprints": [],
                        "world_effect": "none",
                    }
                ],
            }
        ],
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class StageACallableExternalProposalTests(unittest.TestCase):
    def test_profile_rejects_overlapping_abi_register_classes(self) -> None:
        payload = _profile()
        abi = payload["targets"][0]["abis"][0]  # type: ignore[index]
        abi["clobbered_registers"] = ["eax", "ebx", "ecx", "edx"]  # type: ignore[index]
        with self.assertRaisesRegex(
            CallableExternalProposalError, "disjointly cover"
        ):
            parse_callable_external_profile(payload)

    def test_discovers_only_profiled_callable_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            image = bytearray(
                pe32_import_image(
                    b"\x90\xc3", symbol="GetProcAddress", iat_offset=0x40
                )
            )
            idata_raw = 0x400
            first_offset = 0x120
            second_offset = 0x140
            image[idata_raw + first_offset : idata_raw + first_offset + 12] = (
                b"resolved_fn\0"
            )
            image[idata_raw + second_offset : idata_raw + second_offset + 10] = (
                b"data_name\0"
            )
            original.write_bytes(image)

            state_machine = root / "state-machine.jsonl"
            rows = [
                self._state_row(0x1000, 0x402120),
                self._state_row(0x1010, 0x402140),
            ]
            state_machine.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                encoding="utf-8",
            )
            report = root / "machine-import-report.json"
            report.write_text(
                json.dumps({
                    "format": "stage-a-static-machine-import-contracts-v1",
                    "inputs": {
                        "original_sha256": _sha256(original),
                        "state_machine_sha256": _sha256(state_machine),
                    },
                    "signatures": [
                        {
                            "id": 7,
                            "import": {
                                "dll": "kernel32.dll",
                                "symbol": "GetProcAddress",
                            },
                            "arity": {"kind": "fixed", "words": 2},
                            "world_effect": "opaqueResources",
                        }
                    ],
                    "boundaries": [
                        self._boundary(10, 0x1000, 0x1008),
                        self._boundary(11, 0x1010, 0x1018),
                    ],
                }),
                encoding="utf-8",
            )

            proposal = discover_callable_external_proposal(
                original_pe=original,
                state_machine=state_machine,
                machine_import_report=report,
                profile=parse_callable_external_profile(_profile()),
            )

        self.assertTrue(proposal.complete)
        self.assertEqual([site.boundary_id for site in proposal.sites], [10])
        self.assertEqual(proposal.sites[0].machine_contract_id, 10)
        self.assertEqual(len(proposal.static_data_bindings), 1)
        binding = proposal.static_data_bindings[0]
        self.assertEqual((binding.rva, binding.va, binding.size), (
            0x2120,
            0x402120,
            12,
        ))
        self.assertEqual(binding.relocation_offsets, ())

    def test_wrong_machine_world_effect_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            original.write_bytes(
                pe32_import_image(
                    b"\x90\xc3", symbol="GetProcAddress", iat_offset=0x40
                )
            )
            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(
                json.dumps(self._state_row(0x1000, 0x402120)) + "\n",
                encoding="utf-8",
            )
            report = root / "machine-import-report.json"
            report.write_text(
                json.dumps({
                    "format": "stage-a-static-machine-import-contracts-v1",
                    "inputs": {
                        "original_sha256": _sha256(original),
                        "state_machine_sha256": _sha256(state_machine),
                    },
                    "signatures": [
                        {
                            "id": 7,
                            "import": {
                                "dll": "kernel32.dll",
                                "symbol": "GetProcAddress",
                            },
                            "arity": {"kind": "fixed", "words": 2},
                            "world_effect": "tlsState",
                        }
                    ],
                    "boundaries": [self._boundary(10, 0x1000, 0x1008)],
                }),
                encoding="utf-8",
            )
            proposal = discover_callable_external_proposal(
                original_pe=original,
                state_machine=state_machine,
                machine_import_report=report,
                profile=parse_callable_external_profile(_profile()),
            )
        self.assertFalse(proposal.complete)
        self.assertIn("opaqueResources", proposal.blockers[0].detail)

    @staticmethod
    def _state_row(source_rva: int, identity: int) -> dict[str, object]:
        return {
            "original": {
                "rva_start": source_rva,
                "rva_end": source_rva + 10,
                "size": 10,
            },
            "external_events": [
                {
                    "kind": "indirect_call",
                    "stack_inputs": [
                        {
                            "offset": 0,
                            "width": 4,
                            "value": {"op": "const", "value": 1, "width": 32},
                        },
                        {
                            "offset": 4,
                            "width": 4,
                            "value": {
                                "op": "const",
                                "value": identity,
                                "width": 32,
                            },
                        },
                    ],
                }
            ],
        }

    @staticmethod
    def _boundary(
        boundary_id: int, source_rva: int, instruction_rva: int
    ) -> dict[str, object]:
        return {
            "id": boundary_id,
            "import": {
                "dll": "kernel32.dll",
                "symbol": "GetProcAddress",
            },
            "source_rva": source_rva,
            "instruction_rva": instruction_rva,
            "signature_id": 7,
        }


if __name__ == "__main__":
    unittest.main()
