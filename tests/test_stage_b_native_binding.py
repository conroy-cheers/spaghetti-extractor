from __future__ import annotations

import copy
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.stage_b_native_binding import (
    NATIVE_RUNTIME_BINDING_FORMAT,
    build_stage_b_native_runtime_binding,
    write_stage_b_native_runtime_binding,
)
from spaghetti_extractor.util import sha256_file


STATE_MACHINE_SHA256 = "a" * 64
CONTRACT_SHA256 = "b" * 64


def _site(
    *,
    site_id: int,
    transfer_id: str,
    event_index: int,
    instruction_rva: int,
    site_kind: str,
    symbol: str = "Sleep",
) -> dict:
    return {
        "id": site_id,
        "transfer_id": transfer_id,
        "event_index": event_index,
        "instruction_rva": instruction_rva,
        "return_rva": instruction_rva + 6,
        "instruction_bytes": "ff159c214300",
        "disposition": "returns_here",
        "site_kind": site_kind,
        "import": (
            {"dll": "kernel32.dll", "symbol": symbol, "ordinal": None}
            if site_kind == "direct_import"
            else None
        ),
    }


def _plan() -> dict:
    sites = [
        _site(
            site_id=1,
            transfer_id="semantic-transfer:worker",
            event_index=0,
            instruction_rva=0x2000,
            site_kind="dynamic_target",
        ),
        _site(
            site_id=0,
            transfer_id="semantic-transfer:entry",
            event_index=0,
            instruction_rva=0x1000,
            site_kind="direct_import",
        ),
    ]
    return {
        "format": "stage-b-native-engine-plan-v1",
        "status": "ready",
        "state_machine_sha256": STATE_MACHINE_SHA256,
        "entry_rva": 0x1000,
        "counts": {
            "transfers": 4,
            "external_sites": len(sites),
            "indirect_calls": 1,
            "callback_targets": 0,
            "blockers": 0,
        },
        "external_sites": sites,
        "callback_targets": [],
        "blockers": [],
        "authority": "candidate generation only; candidate validation remains required",
    }


def _boundary(
    *,
    transfer_id: str,
    event_index: int,
    instruction_rva: int,
    kind: str,
    status: str,
    binding: str | None = None,
) -> dict:
    result = {
        "id": f"runtime-call:{transfer_id}:{event_index}",
        "status": status,
        "transfer_id": transfer_id,
        "contract_sha256": CONTRACT_SHA256,
        "rva_start": instruction_rva,
        "instruction_rva": instruction_rva,
        "event_index": event_index,
        "kind": kind,
        "next_action": "perform the exact runtime binding",
    }
    if binding is not None:
        result["binding"] = binding
    if kind == "external_call":
        result["identity"] = {
            "dll": "KERNEL32.dll",
            "symbol": "Sleep",
            "ordinal": None,
        }
    elif kind == "internal_call":
        result["target_rva"] = 0x4000
    elif kind == "indirect_call":
        result["target"] = {"op": "reg", "name": "eax", "width": 32}
    return result


def _obligations() -> dict:
    boundaries = [
        _boundary(
            transfer_id="semantic-transfer:rep",
            event_index=0,
            instruction_rva=0x4000,
            kind="rep_movsd",
            status="bound",
            binding="generated_semantic_rep_movsd_v1",
        ),
        _boundary(
            transfer_id="semantic-transfer:worker",
            event_index=0,
            instruction_rva=0x2000,
            kind="indirect_call",
            status="unbound",
        ),
        _boundary(
            transfer_id="semantic-transfer:internal",
            event_index=0,
            instruction_rva=0x3000,
            kind="internal_call",
            status="bound",
            binding="generated_nested_frame_engine_v1",
        ),
        _boundary(
            transfer_id="semantic-transfer:entry",
            event_index=0,
            instruction_rva=0x1000,
            kind="external_call",
            status="unbound",
        ),
    ]
    return {
        "format": "stage-b-runtime-call-obligations-v1",
        "status": "complete",
        "authority": "stage-a-semantic-transfer-contracts",
        "state_machine": {
            "path": "state-machine.jsonl",
            "sha256": STATE_MACHINE_SHA256,
        },
        "machine_call_catalog": None,
        "counts": _obligation_counts(boundaries),
        "call_boundaries": boundaries,
        "acceptance": "all runtime obligations must be bound and candidate assurance must qualify",
    }


def _obligation_counts(boundaries: list[dict]) -> dict:
    statuses = Counter(boundary["status"] for boundary in boundaries)
    unbound_kinds = Counter(
        boundary["kind"]
        for boundary in boundaries
        if boundary["status"] == "unbound"
    )
    return {
        "call_boundaries": len(boundaries),
        "unbound_obligations": statuses["unbound"],
        "by_status": dict(sorted(statuses.items())),
        "unbound_by_kind": dict(sorted(unbound_kinds.items())),
    }


class StageBNativeBindingTests(unittest.TestCase):
    def _write_inputs(
        self, root: Path, plan: dict, obligations: dict
    ) -> tuple[Path, Path]:
        root.mkdir(parents=True, exist_ok=True)
        plan_path = root / "native-engine-plan.json"
        obligations_path = root / "state-machine-runtime-obligations.json"
        plan_path.write_text(
            json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        obligations_path.write_text(
            json.dumps(obligations, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return plan_path, obligations_path

    def _build(self, root: Path, plan: dict, obligations: dict) -> dict:
        plan_path, obligations_path = self._write_inputs(root, plan, obligations)
        return build_stage_b_native_runtime_binding(
            native_engine_plan=plan_path,
            runtime_call_obligations=obligations_path,
        )

    def test_binds_exact_native_sites_and_inventories_bound_semantic_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self._build(root, _plan(), _obligations())

            self.assertEqual(result["format"], NATIVE_RUNTIME_BINDING_FORMAT)
            self.assertEqual(result["status"], "ready", result)
            self.assertIs(result["acceptance_authority"], False)
            self.assertEqual(result["counts"], {
                "call_boundaries": 4,
                "native_obligations": 2,
                "native_sites": 2,
                "bound_native_sites": 2,
                "unbound_native_obligations": 0,
                "outside_scope": 2,
                "blockers": 0,
            })
            self.assertEqual(
                [site["kind"] for site in result["sites"]],
                ["external_call", "indirect_call"],
            )
            self.assertEqual(
                result["sites"][0]["import"],
                {"dll": "kernel32.dll", "symbol": "Sleep", "ordinal": None},
            )
            self.assertEqual(
                {item["kind"] for item in result["outside_scope"]},
                {"internal_call", "rep_movsd"},
            )
            self.assertTrue(all(
                item["reason"] == "already_bound_semantic_runtime_event"
                for item in result["outside_scope"]
            ))

    def test_output_ids_are_order_independent_and_writer_is_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_plan = _plan()
            first_obligations = _obligations()
            first = self._build(root / "first", first_plan, first_obligations)

            second_plan = _plan()
            second_plan["external_sites"].reverse()
            second_obligations = _obligations()
            second_obligations["call_boundaries"].reverse()
            second = self._build(root / "second", second_plan, second_obligations)

            self.assertEqual(first["sites"], second["sites"])
            self.assertEqual(first["outside_scope"], second["outside_scope"])

            plan_path, obligations_path = self._write_inputs(
                root, first_plan, first_obligations
            )
            out = root / "native-runtime-binding.json"
            written = write_stage_b_native_runtime_binding(
                native_engine_plan=plan_path,
                runtime_call_obligations=obligations_path,
                out=out,
            )
            self.assertEqual(json.loads(out.read_text(encoding="utf-8")), written)
            self.assertTrue(out.read_bytes().endswith(b"\n"))
            self.assertEqual(
                written["sources"]["native_engine_plan"]["sha256"],
                sha256_file(plan_path),
            )
            self.assertEqual(
                written["sources"]["runtime_call_obligations"]["sha256"],
                sha256_file(obligations_path),
            )

    def test_dynamic_dispatch_preserves_a_checked_import_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan = _plan()
            dynamic = plan["external_sites"][0]
            dynamic["import"] = {
                "dll": "MSVCRT.dll",
                "symbol": "__p___argv",
                "ordinal": None,
            }

            result = self._build(Path(tmp), plan, _obligations())

            self.assertEqual(result["status"], "ready", result)
            dynamic_result = next(
                site for site in result["sites"]
                if site["kind"] == "indirect_call"
            )
            self.assertEqual(dynamic_result["site_kind"], "dynamic_target")
            self.assertEqual(dynamic_result["import"], {
                "dll": "msvcrt.dll",
                "symbol": "__p___argv",
                "ordinal": None,
            })

    def test_rejects_malformed_or_mismatched_state_machine_hashes(self) -> None:
        mutations = []
        malformed_plan = _plan()
        malformed_plan["state_machine_sha256"] = "A" * 64
        mutations.append((malformed_plan, _obligations(), "lowercase SHA-256"))
        malformed_obligations = _obligations()
        malformed_obligations["state_machine"]["sha256"] = "not-a-digest"
        mutations.append((_plan(), malformed_obligations, "lowercase SHA-256"))
        mismatched = _obligations()
        mismatched["state_machine"]["sha256"] = "c" * 64
        mutations.append((_plan(), mismatched, "different source state-machine"))

        for index, (plan, obligations, message) in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(StageAInputError, message):
                    self._build(Path(tmp), plan, obligations)

    def test_rejects_status_count_and_duplicate_mutations(self) -> None:
        cases = []
        bad_plan_status = _plan()
        bad_plan_status["status"] = "complete"
        cases.append((bad_plan_status, _obligations(), "plan status"))

        bad_obligation_status = _obligations()
        bad_obligation_status["status"] = "ready"
        cases.append((_plan(), bad_obligation_status, "obligations status"))

        bad_counts = _obligations()
        bad_counts["counts"]["unbound_obligations"] = 0
        cases.append((_plan(), bad_counts, "counts do not match"))

        duplicate_plan = _plan()
        duplicate_plan["external_sites"].append(
            copy.deepcopy(duplicate_plan["external_sites"][0])
        )
        duplicate_plan["counts"]["external_sites"] += 1
        duplicate_plan["counts"]["indirect_calls"] += 1
        cases.append((duplicate_plan, _obligations(), "duplicate site ids"))

        duplicate_obligations = _obligations()
        duplicate_obligations["call_boundaries"].append(
            copy.deepcopy(duplicate_obligations["call_boundaries"][0])
        )
        duplicate_obligations["counts"] = _obligation_counts(
            duplicate_obligations["call_boundaries"]
        )
        cases.append((_plan(), duplicate_obligations, "duplicate ids"))

        for index, (plan, obligations, message) in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(StageAInputError, message):
                    self._build(Path(tmp), plan, obligations)

    def test_identity_and_site_kind_mutations_fail_closed_with_actions(self) -> None:
        mutations = []
        identity_plan = _plan()
        identity_plan["external_sites"][1]["import"]["symbol"] = "ExitProcess"
        mutations.append((identity_plan, "direct_import_identity_mismatch"))

        kind_plan = _plan()
        dynamic = kind_plan["external_sites"][0]
        dynamic["site_kind"] = "direct_import"
        dynamic["import"] = {
            "dll": "kernel32.dll", "symbol": "Sleep", "ordinal": None
        }
        kind_plan["counts"]["indirect_calls"] = 0
        mutations.append((kind_plan, "native_site_kind_mismatch"))

        for index, (plan, category) in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as tmp:
                result = self._build(Path(tmp), plan, _obligations())
                self.assertEqual(result["status"], "incomplete")
                self.assertIn(category, {item["category"] for item in result["blockers"]})
                self.assertTrue(all(item["next_action"] for item in result["blockers"]))
                self.assertIs(result["acceptance_authority"], False)

    def test_missing_extra_and_remaining_source_blockers_are_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan = _plan()
            direct = plan["external_sites"][1]
            direct["transfer_id"] = "semantic-transfer:extra"
            result = self._build(Path(tmp), plan, _obligations())
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(
                {item["category"] for item in result["blockers"]},
                {"native_site_missing", "unexpected_native_site"},
            )

        with tempfile.TemporaryDirectory() as tmp:
            plan = _plan()
            plan["status"] = "incomplete"
            plan["blockers"] = [{
                "category": "entry_transfer_missing",
                "severity": "hard",
                "entry_rva": 0x1000,
                "next_action": "export the semantic entry transfer",
            }]
            plan["counts"]["blockers"] = 1
            result = self._build(Path(tmp), plan, _obligations())
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(
                result["blockers"][0]["category"], "native_engine_plan_blocker"
            )
            self.assertEqual(
                result["blockers"][0]["next_action"],
                "export the semantic entry transfer",
            )

    def test_prebound_native_or_unbound_outside_scope_cannot_become_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            obligations = _obligations()
            external = next(
                item
                for item in obligations["call_boundaries"]
                if item["kind"] == "external_call"
            )
            external["status"] = "bound"
            external["binding"] = "generated_machine_call_adapter_v1"
            obligations["counts"] = _obligation_counts(obligations["call_boundaries"])
            result = self._build(Path(tmp), _plan(), obligations)
            categories = {item["category"] for item in result["blockers"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("native_boundary_already_bound", categories)
            self.assertIn("unexpected_native_site", categories)

        with tempfile.TemporaryDirectory() as tmp:
            obligations = _obligations()
            internal = next(
                item
                for item in obligations["call_boundaries"]
                if item["kind"] == "internal_call"
            )
            internal["status"] = "unbound"
            del internal["binding"]
            obligations["counts"] = _obligation_counts(obligations["call_boundaries"])
            result = self._build(Path(tmp), _plan(), obligations)
            self.assertEqual(result["status"], "incomplete")
            self.assertIn(
                "outside_scope_boundary_unbound",
                {item["category"] for item in result["blockers"]},
            )

    def test_input_authority_claims_never_create_an_acceptance_shortcut(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan = _plan()
            obligations = _obligations()
            plan["acceptance_authority"] = True
            obligations["acceptance_authority"] = "whole_program_lean"
            result = self._build(Path(tmp), plan, obligations)
            self.assertEqual(result["status"], "ready")
            self.assertIs(result["acceptance_authority"], False)


if __name__ == "__main__":
    unittest.main()
