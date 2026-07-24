from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pe_fixtures import pe32_image
from spaghetti_extractor.roundtrip_fuzz.semantic_c_mapping import (
    SEMANTIC_C_MAPPING_PROPOSAL_FORMAT,
    build_semantic_c_mapping_proposal,
    write_semantic_c_mapping_proposal,
)
from spaghetti_extractor.util import sha256_file, write_json


def _transfer(
    transfer_id: str,
    *,
    rva_start: int,
    symbol: str,
    contract_sha256: str,
    **updates,
) -> dict:
    row = {
        "id": transfer_id,
        "function": transfer_id,
        "block_id": transfer_id,
        "contract_sha256": contract_sha256,
        "rva_start": rva_start,
        "symbol": symbol,
        "implementation": "generated_semantic_c",
        "source": {
            "path": "state-machine-transfers.c",
            "line_start": 1,
            "line_end": 2,
        },
        "blockers": [],
    }
    row.update(updates)
    return row


def _write_manifests(root: Path, transfers: list[dict]) -> tuple[Path, Path]:
    source_map = root / "state-machine-source-map.json"
    write_json(source_map, {
        "format": "stage-b-semantic-c-source-map-v1",
        "authority": "stage-a-semantic-transfer-contracts",
        "transfers": transfers,
    })
    implementation = root / "state-machine-implementation.json"
    write_json(implementation, {
        "format": "stage-b-semantic-c-implementation-v1",
        "authority": "stage-a-semantic-transfer-contracts",
        "status": "complete",
        "transfer_inventory": [
            {
                "id": row["id"],
                "contract_sha256": row["contract_sha256"],
                "rva_start": row["rva_start"],
                "symbol": row["symbol"],
                "implementation": row["implementation"],
            }
            for row in transfers
        ],
        "artifacts": {
            "source_map": {
                "path": source_map.name,
                "sha256": sha256_file(source_map),
            },
        },
        "strict_candidate": {"status": "ready", "blockers": []},
        "acceptance": "compile this implementation, then prove the resulting PE with Stage A",
    })
    return source_map, implementation


def _write_map(path: Path, rows: list[tuple[int, str]], *, size: int) -> Path:
    lines = [f" .text          0x00401000       0x{size:x}"]
    lines.extend(f"                0x{0x400000 + rva:08x}                {symbol}" for rva, symbol in rows)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class StageARoundTripSemanticCMappingTests(unittest.TestCase):
    def test_builds_deterministic_untrusted_mapping_from_manifest_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(pe32_image(bytes.fromhex("b801000000c331c0c3")))
            candidate.write_bytes(pe32_image(bytes.fromhex("5589e5c39090c3")))
            transfers = [
                _transfer(
                    "semantic-transfer:first",
                    rva_start=0x1000,
                    symbol="stage_b_transfer_first",
                    contract_sha256="1" * 64,
                ),
                _transfer(
                    "semantic-transfer:second",
                    rva_start=0x1006,
                    symbol="stage_b_transfer_second",
                    contract_sha256="2" * 64,
                ),
            ]
            source_map, implementation = _write_manifests(root, transfers)
            linker_map = _write_map(
                root / "candidate.map",
                [
                    (0x1000, "_stage_b_transfer_first"),
                    (0x1004, "_stage_b_transfer_second"),
                ],
                size=7,
            )

            first = build_semantic_c_mapping_proposal(
                original=original,
                candidate=candidate,
                source_map=source_map,
                implementation_manifest=implementation,
                candidate_linker_map=linker_map,
            )
            out = root / "proposal.json"
            second = write_semantic_c_mapping_proposal(
                original=original,
                candidate=candidate,
                source_map=source_map,
                implementation=implementation,
                candidate_linker_map=linker_map,
                out=out,
            )

            self.assertEqual(first, second)
            self.assertEqual(first, json.loads(out.read_text(encoding="utf-8")))
            self.assertEqual(first["format"], "stage-a-block-map-v1")
            self.assertEqual(first["proposal_format"], SEMANTIC_C_MAPPING_PROPOSAL_FORMAT)
            self.assertEqual(first["status"], "ready", first)
            self.assertFalse(first["acceptance_authority"])
            self.assertFalse(first["trust"]["equivalence_claimed"])
            self.assertTrue(first["trust"]["requires_ordinary_lean_checker"])
            self.assertEqual(first["issues"], [])
            self.assertEqual(
                [
                    (row["original"], row["candidate"])
                    for row in first["blocks"]
                ],
                [
                    ({"rva": 0x1000, "size": 6}, {"rva": 0x1000, "size": 4}),
                    ({"rva": 0x1006, "size": 3}, {"rva": 0x1004, "size": 3}),
                ],
            )
            self.assertTrue(all(
                row["invariant"] == {
                    "checked": False,
                    "kind": "untrusted_semantic_c_mapping_proposal",
                }
                for row in first["blocks"]
            ))

    def test_later_native_binding_closes_only_the_unbound_adapter_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(pe32_image(b"\xc3"))
            candidate.write_bytes(pe32_image(b"\xc3"))
            source_map, implementation = _write_manifests(root, [
                _transfer(
                    "semantic-transfer:return",
                    rva_start=0x1000,
                    symbol="stage_b_transfer_return",
                    contract_sha256="9" * 64,
                )
            ])
            implementation_payload = json.loads(
                implementation.read_text(encoding="utf-8")
            )
            implementation_payload["status"] = "incomplete"
            implementation_payload["strict_candidate"] = {
                "status": "incomplete",
                "blockers": ["runtime_call_adapters_unbound"],
            }
            implementation_payload["state_machine"] = {
                "path": "state-machine.jsonl",
                "sha256": "a" * 64,
            }
            implementation_payload["artifacts"]["runtime_obligations"] = {
                "path": "state-machine-runtime-obligations.json",
                "sha256": "b" * 64,
            }
            write_json(implementation, implementation_payload)
            runtime_binding = root / "native-runtime-binding.json"
            write_json(runtime_binding, {
                "format": "stage-b-native-runtime-binding-v1",
                "status": "ready",
                "acceptance_authority": False,
                "sources": {
                    "state_machine": {"sha256": "a" * 64},
                    "runtime_call_obligations": {"sha256": "b" * 64},
                },
                "counts": {
                    "native_obligations": 1,
                    "native_sites": 1,
                    "bound_native_sites": 1,
                    "unbound_native_obligations": 0,
                    "blockers": 0,
                },
                "blockers": [],
            })
            linker_map = _write_map(
                root / "candidate.map",
                [(0x1000, "_stage_b_transfer_return")],
                size=1,
            )

            ready = build_semantic_c_mapping_proposal(
                original=original,
                candidate=candidate,
                source_map=source_map,
                implementation_manifest=implementation,
                runtime_binding=runtime_binding,
                candidate_linker_map=linker_map,
            )
            self.assertEqual(ready["status"], "ready", ready)
            self.assertEqual(
                ready["inputs"]["runtime_binding"]["sha256"],
                sha256_file(runtime_binding),
            )

            stale = json.loads(runtime_binding.read_text(encoding="utf-8"))
            stale["sources"]["state_machine"]["sha256"] = "c" * 64
            write_json(runtime_binding, stale)
            incomplete = build_semantic_c_mapping_proposal(
                original=original,
                candidate=candidate,
                source_map=source_map,
                implementation_manifest=implementation,
                runtime_binding=runtime_binding,
                candidate_linker_map=linker_map,
            )
            self.assertEqual(incomplete["status"], "incomplete")
            self.assertIn(
                "semantic_c_candidate_not_ready",
                incomplete["counts"]["issues_by_category"],
            )

    def test_hash_mismatch_fails_closed_with_actionable_issue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(pe32_image(b"\xc3"))
            candidate.write_bytes(pe32_image(b"\xc3"))
            source_map, implementation = _write_manifests(root, [
                _transfer(
                    "semantic-transfer:return",
                    rva_start=0x1000,
                    symbol="stage_b_transfer_return",
                    contract_sha256="a" * 64,
                )
            ])
            payload = json.loads(source_map.read_text(encoding="utf-8"))
            payload["authority"] = "tampered"
            write_json(source_map, payload)
            linker_map = _write_map(
                root / "candidate.map",
                [(0x1000, "_stage_b_transfer_return")],
                size=1,
            )

            proposal = build_semantic_c_mapping_proposal(
                original=original,
                candidate=candidate,
                source_map=source_map,
                implementation=implementation,
                candidate_linker_map=linker_map,
            )

            self.assertEqual(proposal["status"], "incomplete")
            self.assertEqual(proposal["blocks"], [])
            self.assertEqual(
                proposal["counts"]["issues_by_category"],
                {"source_map_hash_mismatch": 1},
            )
            self._assert_actionable(proposal)

    def test_rejects_contract_hash_disagreement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(pe32_image(b"\xc3"))
            candidate.write_bytes(pe32_image(b"\xc3"))
            source_map, implementation = _write_manifests(root, [
                _transfer(
                    "semantic-transfer:return",
                    rva_start=0x1000,
                    symbol="stage_b_transfer_return",
                    contract_sha256="a" * 64,
                )
            ])
            manifest = json.loads(implementation.read_text(encoding="utf-8"))
            manifest["transfer_inventory"][0]["contract_sha256"] = "b" * 64
            write_json(implementation, manifest)
            linker_map = _write_map(
                root / "candidate.map",
                [(0x1000, "_stage_b_transfer_return")],
                size=1,
            )

            proposal = build_semantic_c_mapping_proposal(
                original=original,
                candidate=candidate,
                source_map=source_map,
                implementation=implementation,
                candidate_linker_map=linker_map,
            )

            self.assertEqual(proposal["blocks"], [])
            self.assertEqual(
                proposal["counts"]["issues_by_category"],
                {"contract_hash_mismatch": 1},
            )
            self._assert_actionable(proposal)

    def test_rejects_duplicate_original_rvas(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(pe32_image(b"\xc3"))
            candidate.write_bytes(pe32_image(b"\xc3\xc3"))
            transfers = [
                _transfer(
                    "semantic-transfer:a",
                    rva_start=0x1000,
                    symbol="stage_b_transfer_a",
                    contract_sha256="a" * 64,
                ),
                _transfer(
                    "semantic-transfer:b",
                    rva_start=0x1000,
                    symbol="stage_b_transfer_b",
                    contract_sha256="b" * 64,
                ),
            ]
            source_map, implementation = _write_manifests(root, transfers)
            linker_map = _write_map(
                root / "candidate.map",
                [(0x1000, "_stage_b_transfer_a"), (0x1001, "_stage_b_transfer_b")],
                size=2,
            )

            proposal = build_semantic_c_mapping_proposal(
                original=original,
                candidate=candidate,
                source_map=source_map,
                implementation=implementation,
                candidate_linker_map=linker_map,
            )

            categories = proposal["counts"]["issues_by_category"]
            self.assertEqual(categories["duplicate_original_rva"], 1)
            self.assertEqual(proposal["blocks"], [])
            self._assert_actionable(proposal)

    def test_rejects_ambiguous_candidate_symbol_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(pe32_image(b"\xc3"))
            candidate.write_bytes(pe32_image(b"\xc3\xc3"))
            source_map, implementation = _write_manifests(root, [
                _transfer(
                    "semantic-transfer:return",
                    rva_start=0x1000,
                    symbol="stage_b_transfer_return",
                    contract_sha256="d" * 64,
                )
            ])
            linker_map = _write_map(
                root / "candidate.map",
                [
                    (0x1000, "_stage_b_transfer_return"),
                    (0x1001, "stage_b_transfer_return"),
                ],
                size=2,
            )

            proposal = build_semantic_c_mapping_proposal(
                original=original,
                candidate=candidate,
                source_map=source_map,
                implementation=implementation,
                candidate_linker_map=linker_map,
            )

            self.assertEqual(proposal["blocks"], [])
            self.assertEqual(
                proposal["counts"]["issues_by_category"],
                {"candidate_symbol_ambiguous": 1},
            )
            self._assert_actionable(proposal)

    def test_rejects_out_of_bounds_and_non_decoding_candidate_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(pe32_image(b"\xc3"))
            transfer = _transfer(
                "semantic-transfer:return",
                rva_start=0x1000,
                symbol="stage_b_transfer_return",
                contract_sha256="e" * 64,
            )
            source_map, implementation = _write_manifests(root, [transfer])

            out_of_bounds_candidate = root / "candidate-out-of-bounds.exe"
            out_of_bounds_candidate.write_bytes(pe32_image(b"\xc3"))
            out_of_bounds_map = _write_map(
                root / "candidate-out-of-bounds.map",
                [(0x2000, "_stage_b_transfer_return")],
                size=1,
            )
            out_of_bounds = build_semantic_c_mapping_proposal(
                original=original,
                candidate=out_of_bounds_candidate,
                source_map=source_map,
                implementation=implementation,
                candidate_linker_map=out_of_bounds_map,
            )

            undecodable_candidate = root / "candidate-undecodable.exe"
            undecodable_candidate.write_bytes(pe32_image(b"\xff"))
            undecodable_map = _write_map(
                root / "candidate-undecodable.map",
                [(0x1000, "_stage_b_transfer_return")],
                size=1,
            )
            undecodable = build_semantic_c_mapping_proposal(
                original=original,
                candidate=undecodable_candidate,
                source_map=source_map,
                implementation=implementation,
                candidate_linker_map=undecodable_map,
            )

            self.assertIn(
                "candidate_symbol_out_of_bounds",
                out_of_bounds["counts"]["issues_by_category"],
            )
            self.assertIn(
                "candidate_range_decode_incomplete",
                undecodable["counts"]["issues_by_category"],
            )
            self.assertEqual(out_of_bounds["blocks"], [])
            self.assertEqual(undecodable["blocks"], [])
            self._assert_actionable(out_of_bounds)
            self._assert_actionable(undecodable)

    def _assert_actionable(self, proposal: dict) -> None:
        self.assertTrue(proposal["issues"])
        for issue in proposal["issues"]:
            self.assertEqual(issue["status"], "incomplete")
            self.assertTrue(issue["blocker"])
            self.assertTrue(issue["next_action"])


if __name__ == "__main__":
    unittest.main()
