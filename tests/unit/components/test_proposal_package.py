from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import identity_bucket_v3
from spaghetti_extractor.components.formats import (
    COMPONENT_DISCOVERY_RESULT_V2_FORMAT,
)
from spaghetti_extractor.components.proposal_package import (
    ComponentProposalPackageError,
    load_component_proposal_package_v2,
    write_component_proposal_package_v2,
)
from spaghetti_extractor.util import json_dumps


class ProposalPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "package"
        self.proposal_ids = _proposal_ids_in_distinct_buckets(3)
        self.payload = _payload(self.proposal_ids)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_round_trip_keeps_selector_index_compact(self) -> None:
        manifest = write_component_proposal_package_v2(
            payload=self.payload, out=self.root
        )
        package = load_component_proposal_package_v2(self.root)

        self.assertEqual(manifest, package.manifest)
        self.assertEqual(package.index["counts"]["proposals"], 3)
        self.assertNotIn(
            "unit_ids", package.index["proposals"][0]["membership"]
        )
        selected = package.get_proposal(self.proposal_ids[1])
        self.assertEqual(
            selected["membership"]["unit_ids"], ["unit:00000001"]
        )
        package.validate_all_proposals()

    def test_seed_navigation_ignores_holes_in_enclosing_proposal_span(self) -> None:
        proposal = self.payload["proposals"][0]
        proposal["membership"]["rva_end"] = 0x1100
        _rehash_proposal(proposal)
        _rehash_discovery(self.payload)
        write_component_proposal_package_v2(payload=self.payload, out=self.root)
        package = load_component_proposal_package_v2(self.root)
        self.assertEqual([row["id"] for row in package.proposals_at_rva(0x1000)],
                         [self.proposal_ids[0]])
        self.assertEqual(package.proposals_at_rva(0x1005), [])
        self.assertEqual([row["id"] for row in package.proposals_at_rva(0x1010)],
                         [self.proposal_ids[1]])

    def test_seed_navigation_rejects_an_unrelated_indexed_proposal(self) -> None:
        self.payload["seed_index"][0]["proposal_ids"] = [self.proposal_ids[1]]
        _rehash_discovery(self.payload)
        write_component_proposal_package_v2(payload=self.payload, out=self.root)
        package = load_component_proposal_package_v2(self.root)
        with self.assertRaisesRegex(ValueError, "does not contain its unit"):
            package.proposals_at_rva(0x1000)

    def test_seed_navigation_uses_rank_for_requested_seed(self) -> None:
        first, second = self.payload["proposals"][:2]
        seed = self.payload["seed_index"][0]
        seed["proposal_ids"].append(second["id"])
        second["membership"].update({"unit_ids": ["unit:00000000", "unit:00000001"],
                                     "unit_count": 2, "rva_start": 0x1000})
        bindings = [{key: node[key] for key in
                     ("unit_id", "contract_sha256", "instruction_bytes_sha256")}
                    for node in self.payload["graph_facts"]["nodes"][:2]]
        second["bindings"]["membership_bindings_sha256"] = _sha256(bindings)
        for proposal, rank in ((first, 1), (second, 0)):
            proposal["score"]["seed_rankings"] = [
                {"seed_id": seed["seed_id"], "front": 0, "rank": rank}]
            _rehash_proposal(proposal)
        _rehash_discovery(self.payload)
        write_component_proposal_package_v2(payload=self.payload, out=self.root)
        package = load_component_proposal_package_v2(self.root)
        self.assertEqual([row["id"] for row in package.proposals_at_rva(0x1000)],
                         [second["id"], first["id"]])

    def test_seed_navigation_rechecks_modified_graph(self) -> None:
        write_component_proposal_package_v2(payload=self.payload, out=self.root)
        package = load_component_proposal_package_v2(self.root)
        path = self.root / "graph-facts.json"
        path.write_text(path.read_text().replace('4096', '4097'))
        with self.assertRaisesRegex(ValueError, "stale"):
            package.proposals_at_rva(0x1000)

    def test_index_corruption_fails_before_selection(self) -> None:
        write_component_proposal_package_v2(payload=self.payload, out=self.root)
        index_path = self.root / "proposal-index.json"
        index = json.loads(index_path.read_text(encoding="ascii"))
        index["counts"]["proposals"] += 1
        index_path.write_text(json_dumps(index) + "\n", encoding="ascii")

        with self.assertRaisesRegex(
            ComponentProposalPackageError, "sidecar proposal-index.json is stale"
        ):
            load_component_proposal_package_v2(self.root)

    def test_selected_lookup_does_not_decode_unrelated_pack(self) -> None:
        write_component_proposal_package_v2(payload=self.payload, out=self.root)
        package = load_component_proposal_package_v2(self.root)
        selected_id, corrupt_id = self.proposal_ids[:2]
        self.assertNotEqual(
            identity_bucket_v3(selected_id), identity_bucket_v3(corrupt_id)
        )
        corrupt_pack = next(
            row
            for row in package.records.manifest.packs
            if row.bucket == identity_bucket_v3(corrupt_id)
        )
        (self.root / "proposals" / corrupt_pack.path).write_bytes(b"corrupt")

        self.assertEqual(package.get_proposal(selected_id)["id"], selected_id)
        with self.assertRaisesRegex(ValueError, "corrupt_pack"):
            package.get_proposal(corrupt_id)

    def test_full_validation_checks_unrelated_diagnostic_packs(self) -> None:
        write_component_proposal_package_v2(payload=self.payload, out=self.root)
        package = load_component_proposal_package_v2(self.root)
        corrupt_id = self.proposal_ids[1]
        corrupt_pack = next(
            row
            for row in package.records.manifest.packs
            if row.bucket == identity_bucket_v3(corrupt_id)
        )
        (self.root / "proposals" / corrupt_pack.path).write_bytes(b"corrupt")

        with self.assertRaisesRegex(ValueError, "corrupt_pack"):
            package.validate_all_proposals()

    def test_proposal_record_must_match_index_hash(self) -> None:
        stale = copy.deepcopy(self.payload)
        stale["proposals"][0]["membership"]["rva_end"] += 1
        _rehash_discovery(stale)

        with self.assertRaisesRegex(
            ComponentProposalPackageError, "identity or self-hash is stale"
        ):
            write_component_proposal_package_v2(payload=stale, out=self.root)

    def test_index_summary_cannot_contradict_selected_record(self) -> None:
        write_component_proposal_package_v2(payload=self.payload, out=self.root)
        index_path = self.root / "proposal-index.json"
        index = json.loads(index_path.read_text(encoding="ascii"))
        index["proposals"][0]["membership"]["rva_end"] += 1
        _rewrite_hashed_package_file(
            self.root, "index", index_path, index, "index_sha256"
        )

        package = load_component_proposal_package_v2(self.root)
        with self.assertRaisesRegex(
            ComponentProposalPackageError, "contradicts its index summary"
        ):
            package.get_proposal(self.proposal_ids[0])

    def test_index_binding_must_match_record_artifact(self) -> None:
        write_component_proposal_package_v2(payload=self.payload, out=self.root)
        index_path = self.root / "proposal-index.json"
        index = json.loads(index_path.read_text(encoding="ascii"))
        index["bindings"]["machine_ir_sha256"] = "e" * 64
        _rewrite_hashed_package_file(
            self.root, "index", index_path, index, "index_sha256"
        )

        with self.assertRaisesRegex(
            ComponentProposalPackageError, "input binding contradicts its index"
        ):
            load_component_proposal_package_v2(self.root)

    def test_membership_binding_is_recomputed_from_unit_contracts(self) -> None:
        stale = copy.deepcopy(self.payload)
        stale["proposals"][0]["bindings"]["membership_bindings_sha256"] = "f" * 64
        _rehash_proposal(stale["proposals"][0])
        _rehash_discovery(stale)

        with self.assertRaisesRegex(
            ComponentProposalPackageError, "stale membership binding"
        ):
            write_component_proposal_package_v2(payload=stale, out=self.root)

    def test_malformed_sidecar_fails_after_transport_hash_check(self) -> None:
        write_component_proposal_package_v2(payload=self.payload, out=self.root)
        issues_path = self.root / "issues.json"
        _rewrite_hashed_package_file(
            self.root, "issues", issues_path, {"not": "an array"}, None
        )

        with self.assertRaisesRegex(
            ComponentProposalPackageError, "proposal issues must be an array"
        ):
            load_component_proposal_package_v2(self.root)

    def test_discovery_result_must_be_self_bound(self) -> None:
        stale = copy.deepcopy(self.payload)
        stale["limits"]["max_units_per_candidate"] += 1

        with self.assertRaisesRegex(
            ComponentProposalPackageError, "discovery result self-hash is stale"
        ):
            write_component_proposal_package_v2(payload=stale, out=self.root)


def _proposal_ids_in_distinct_buckets(count: int) -> list[str]:
    result: list[str] = []
    buckets: set[int] = set()
    index = 0
    while len(result) < count:
        identity = f"component-proposal:fixture-{index:08x}"
        bucket = identity_bucket_v3(identity)
        if bucket not in buckets:
            buckets.add(bucket)
            result.append(identity)
        index += 1
    return result


def _payload(proposal_ids: list[str]) -> dict[str, object]:
    proposals = []
    nodes = []
    for index, identity in enumerate(proposal_ids):
        unit_binding = {
            "unit_id": f"unit:{index:08x}",
            "contract_sha256": hashlib.sha256(
                f"contract:{index}".encode("ascii")
            ).hexdigest(),
            "instruction_bytes_sha256": hashlib.sha256(
                f"instructions:{index}".encode("ascii")
            ).hexdigest(),
        }
        nodes.append({**unit_binding, "rva_start": 0x1000 + index * 0x10,
                      "rva_end": 0x1001 + index * 0x10})
        proposal = {
            "id": identity,
            "status": "proposed",
            "proposal_kinds": ["singleton"],
            "membership": {
                "unit_ids": [f"unit:{index:08x}"],
                "unit_count": 1,
                "rva_start": 0x1000 + index * 0x10,
                "rva_end": 0x1001 + index * 0x10,
                "noncontiguous": False,
            },
            "reachability": {"classification": "exact"},
            "score": {"front": 0, "rank": index},
            "bindings": {
                "membership_bindings_sha256": _sha256([unit_binding])
            },
            "blockers": [],
        }
        proposal["proposal_sha256"] = _sha256(proposal)
        proposals.append(proposal)
    result = {
        "format": COMPONENT_DISCOVERY_RESULT_V2_FORMAT,
        "status": "proposed",
        "authority": {
            "class": "untrusted_component_discovery_proposals",
            "can_authorize_replacement": False,
            "requires_operator_selection": True,
            "requires_interface_refinement": True,
        },
        "executes_original_binary": False,
        "bindings": {
            "machine_ir_sha256": "a" * 64,
            "machine_ir_manifest_sha256": "b" * 64,
            "reconstruction_plan_sha256": "c" * 64,
            "original_binary_sha256": "d" * 64,
        },
        "limits": {
            "max_units_per_candidate": 512,
            "max_candidates_per_seed": 12,
            "path_search_depth": 64,
        },
        "graph_facts": {"nodes": nodes},
        "seed_index": [{"seed_id": "unit:" + row["membership"]["unit_ids"][0],
                        "proposal_ids": [row["id"]]} for row in proposals],
        "proposals": proposals,
        "coverage": {"exact": {"complete": True}},
        "issues": [],
    }
    _rehash_discovery(result)
    return result


def _rehash_proposal(proposal: dict[str, object]) -> None:
    proposal.pop("proposal_sha256", None)
    proposal["proposal_sha256"] = _sha256(proposal)


def _rehash_discovery(payload: dict[str, object]) -> None:
    payload.pop("discovery_result_sha256", None)
    payload["discovery_result_sha256"] = _sha256(payload)


def _rewrite_hashed_package_file(
    root: Path,
    descriptor_name: str,
    path: Path,
    value: object,
    self_hash_field: str | None,
) -> None:
    if self_hash_field is not None:
        assert isinstance(value, dict)
        value.pop(self_hash_field, None)
        value[self_hash_field] = _sha256(value)
    path.write_text(json_dumps(value) + "\n", encoding="ascii")
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    descriptor = manifest["files"][descriptor_name]
    data = path.read_bytes()
    descriptor["size"] = len(data)
    descriptor["sha256"] = hashlib.sha256(data).hexdigest()
    manifest.pop("package_sha256", None)
    manifest["package_sha256"] = _sha256(manifest)
    manifest_path.write_text(json_dumps(manifest) + "\n", encoding="ascii")


def _sha256(value: object) -> str:
    return hashlib.sha256(json_dumps(value).encode("ascii")).hexdigest()


if __name__ == "__main__":
    unittest.main()
