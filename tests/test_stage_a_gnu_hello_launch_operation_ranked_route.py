from __future__ import annotations

import dataclasses
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from spaghetti_extractor.relational.lean.gnu_hello_launch_operation_ranked_route import (
    GNU_HELLO_CALLBACK_BOUNDARY_RVA,
    GNU_HELLO_INTERPRETER_STEP_RVA,
    GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_MANIFEST,
    GNU_HELLO_TRANSFER_COUNT,
    GnuHelloLaunchOperationRankedRouteError,
    GnuHelloLaunchOperationRankedRouteSpec,
    build_gnu_hello_launch_operation_ranked_route_plan,
    gnu_hello_launch_operation_ranked_route_source,
    write_gnu_hello_launch_operation_ranked_route,
)


_IMAGE_BASE = 0x400000
_INSTRUCTIONS = {
    278627: bytes.fromhex("e810330000"),
    291943: bytes.fromhex("e860feffff"),
    291664: bytes.fromhex("e8d5f2ffff"),
    288395: bytes.fromhex("e832f4ffff"),
    289802: bytes.fromhex("8b45f4"),
    289855: bytes.fromhex("e8ddedffff"),
    289871: bytes.fromhex("8345f401"),
    289875: bytes.fromhex("b841160000"),
    289880: bytes.fromhex("3945f4"),
    289883: bytes.fromhex("72ad"),
    289892: bytes.fromhex("e8b8edffff"),
}


class _FakePe:
    def __init__(self, instructions: dict[int, bytes]) -> None:
        self.instructions = instructions
        self.closed = False

    def get_data(self, rva: int, size: int) -> bytes:
        return (self.instructions.get(rva, b"") + bytes(size))[:size]

    def close(self) -> None:
        self.closed = True


def _fake_binary(
    instructions: dict[int, bytes] | None = None,
) -> SimpleNamespace:
    pe = _FakePe(dict(instructions or _INSTRUCTIONS))
    return SimpleNamespace(
        machine="i386",
        bitness=32,
        image_base=_IMAGE_BASE,
        pe=pe,
    )


def _write_inputs(root: Path, candidate: bytes = b"candidate") -> tuple[Path, Path, Path]:
    candidate_path = root / "candidate.exe"
    launch_path = root / "launch.json"
    operation_path = root / "operation.json"
    candidate_path.write_bytes(candidate)
    digest = hashlib.sha256(candidate).hexdigest()
    launch_path.write_text(
        json.dumps(
            {
                "format": (
                    "stage-a-relational-interpreter-native-launch-graph-v1"
                ),
                "acceptance_authority": False,
                "candidate_sha256": digest,
                "cutpoints": [
                    {
                        "kind": "dispatch",
                        "rva": GNU_HELLO_CALLBACK_BOUNDARY_RVA,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    operation_path.write_text(
        json.dumps(
            {
                "format": (
                    "stage-a-relational-interpreter-kernel-"
                    "operation-instantiation-v1"
                ),
                "acceptance_authority": False,
                "proof_authority": False,
                "candidate": {"sha256": digest, "size": len(candidate)},
                "checked_native_route_inventory": {
                    "anchors": {
                        "step:entry": GNU_HELLO_INTERPRETER_STEP_RVA
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return candidate_path, launch_path, operation_path


class StageAGnuHelloLaunchOperationRankedRouteTests(unittest.TestCase):
    def test_plan_binds_exact_calls_loop_and_existing_inventories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate, launch, operation = _write_inputs(root)
            binary = _fake_binary()
            with mock.patch(
                "spaghetti_extractor.relational.lean."
                "gnu_hello_launch_operation_ranked_route._parse_stage_a_pe",
                return_value=binary,
            ):
                plan = build_gnu_hello_launch_operation_ranked_route_plan(
                    candidate_pe=candidate,
                    native_launch_graph_plan=launch,
                    operation_instantiation_manifest=operation,
                )

        self.assertTrue(binary.pe.closed)
        self.assertFalse(plan.complete)
        self.assertEqual(len(plan.direct_calls), 4)
        self.assertEqual(len(plan.loop_anchors), 7)
        self.assertEqual(plan.direct_calls[-1].target_rva, 285378)
        self.assertEqual(
            next(
                anchor
                for anchor in plan.loop_anchors
                if anchor.role == "outer-back-edge"
            ).target_rva,
            289802,
        )
        payload = plan.payload()
        self.assertFalse(payload["acceptance_authority"])
        self.assertFalse(payload["proof_authority"])
        self.assertFalse(payload["complete"])
        self.assertNotIn("status", payload)
        self.assertEqual(
            payload["transfer_validation_loop"]["record_count"],
            GNU_HELLO_TRANSFER_COUNT,
        )
        self.assertEqual(len(payload["remaining_proof_obligations"]), 5)
        self.assertEqual(
            payload["remaining_proof_obligations"][1]["id"],
            "launch-operation:callback-success-invariant",
        )
        self.assertEqual(
            payload["remaining_proof_obligations"][2]["id"],
            "launch-operation:replay-gap",
        )
        self.assertIn(
            "stage_b_program_lookup",
            payload["transfer_validation_loop"]["required_rank"],
        )

    def test_generator_rejects_stale_machine_call_anchor(self) -> None:
        corrupted = dict(_INSTRUCTIONS)
        corrupted[288395] = bytes.fromhex("e833f4ffff")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate, launch, operation = _write_inputs(root)
            with mock.patch(
                "spaghetti_extractor.relational.lean."
                "gnu_hello_launch_operation_ranked_route._parse_stage_a_pe",
                return_value=_fake_binary(corrupted),
            ):
                with self.assertRaisesRegex(
                    GnuHelloLaunchOperationRankedRouteError,
                    "runFunction-to-interpreterStep anchor targets",
                ):
                    build_gnu_hello_launch_operation_ranked_route_plan(
                        candidate_pe=candidate,
                        native_launch_graph_plan=launch,
                        operation_instantiation_manifest=operation,
                    )

    def test_generator_rejects_stale_transfer_loop_bound(self) -> None:
        corrupted = dict(_INSTRUCTIONS)
        corrupted[289875] = bytes.fromhex("b840160000")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate, launch, operation = _write_inputs(root)
            with mock.patch(
                "spaghetti_extractor.relational.lean."
                "gnu_hello_launch_operation_ranked_route._parse_stage_a_pe",
                return_value=_fake_binary(corrupted),
            ):
                with self.assertRaisesRegex(
                    GnuHelloLaunchOperationRankedRouteError,
                    "not the exact 5697 record bound",
                ):
                    build_gnu_hello_launch_operation_ranked_route_plan(
                        candidate_pe=candidate,
                        native_launch_graph_plan=launch,
                        operation_instantiation_manifest=operation,
                    )

    def test_generator_rejects_hash_or_inventory_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate, launch, operation = _write_inputs(root)
            launch_payload = json.loads(launch.read_text(encoding="utf-8"))
            launch_payload["candidate_sha256"] = "0" * 64
            launch.write_text(json.dumps(launch_payload), encoding="utf-8")
            with self.assertRaisesRegex(
                GnuHelloLaunchOperationRankedRouteError,
                "candidate hash mismatch",
            ):
                build_gnu_hello_launch_operation_ranked_route_plan(
                    candidate_pe=candidate,
                    native_launch_graph_plan=launch,
                    operation_instantiation_manifest=operation,
                )

    def test_source_exposes_ranked_proof_without_claiming_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate, launch, operation = _write_inputs(root)
            with mock.patch(
                "spaghetti_extractor.relational.lean."
                "gnu_hello_launch_operation_ranked_route._parse_stage_a_pe",
                return_value=_fake_binary(),
            ):
                plan = build_gnu_hello_launch_operation_ranked_route_plan(
                    candidate_pe=candidate,
                    native_launch_graph_plan=launch,
                    operation_instantiation_manifest=operation,
                )
        source = gnu_hello_launch_operation_ranked_route_source(plan)
        for required in (
            "ExactNativeDirectCallAnchor",
            "generatedGnuHelloLaunchOperationDirectCallsChecked",
            "ExactNativeControlAnchor",
            "generatedGnuHelloLaunchOperationLoopAnchorsChecked",
            "generatedGnuHelloCallbackBoundaryChecked",
            "generatedGnuHelloInterpreterStepEntryChecked",
            "GeneratedGnuHelloLaunchOperationRankedRouteCertificate",
            "candidatePeExact",
            "candidateImportsExact",
            "boundaryRvaExact",
            "operationEntryRvaExact",
            "ExactNativeLaunchOperationRankedRoute",
            "certificate.ranked.prefixExists",
        ):
            self.assertIn(required, source)
        for forbidden in (
            r"\bsorry\b",
            r"\badmit\b",
            r"\baxiom\b",
            r"\bnative_decide\b",
            r"\bstatus\b",
            r"\bverdict\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_writer_is_deterministic_and_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate, launch, operation = _write_inputs(root)
            output = root / "out"
            with mock.patch(
                "spaghetti_extractor.relational.lean."
                "gnu_hello_launch_operation_ranked_route._parse_stage_a_pe",
                side_effect=(_fake_binary(), _fake_binary()),
            ):
                first = write_gnu_hello_launch_operation_ranked_route(
                    output,
                    candidate_pe=candidate,
                    native_launch_graph_plan=launch,
                    operation_instantiation_manifest=operation,
                )
                first_source = (
                    output / "StageA" / f"{first.spec.module_name}.lean"
                ).read_bytes()
                first_manifest = (
                    output
                    / GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_MANIFEST
                ).read_bytes()
                second = write_gnu_hello_launch_operation_ranked_route(
                    output,
                    candidate_pe=candidate,
                    native_launch_graph_plan=launch,
                    operation_instantiation_manifest=operation,
                )
                second_source = (
                    output / "StageA" / f"{second.spec.module_name}.lean"
                ).read_bytes()
                second_manifest = (
                    output
                    / GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_MANIFEST
                ).read_bytes()

        self.assertEqual(first, second)
        self.assertEqual(first_source, second_source)
        self.assertEqual(first_manifest, second_manifest)
        payload = json.loads(first_manifest)
        self.assertFalse(payload["complete"])
        self.assertNotIn("status", payload)

    def test_spec_validation_fails_closed(self) -> None:
        base = GnuHelloLaunchOperationRankedRouteSpec()
        for change in (
            {"module_name": "StageA.Bad"},
            {"namespace": "StageA.Bad-Namespace"},
            {"launch_graph_module": "StageA.Bad"},
            {"boundary_rva": -1},
            {"operation_entry_rva": 2**32},
            {"boundary_rva": GNU_HELLO_INTERPRETER_STEP_RVA},
        ):
            with self.subTest(change=change):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    candidate, launch, operation = _write_inputs(root)
                    with self.assertRaises(ValueError):
                        build_gnu_hello_launch_operation_ranked_route_plan(
                            candidate_pe=candidate,
                            native_launch_graph_plan=launch,
                            operation_instantiation_manifest=operation,
                            spec=dataclasses.replace(base, **change),
                        )


if __name__ == "__main__":
    unittest.main()
