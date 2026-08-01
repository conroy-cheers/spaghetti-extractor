from __future__ import annotations

import copy
import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifact_formats import STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT
from spaghetti_extractor.relational.lean.gnu_hello_checked_response_family import (
    GNU_HELLO_CHECKED_RESPONSE_FAMILY_INPUT_FORMAT,
    GNU_HELLO_REACHABLE_EXTERNAL_SITE_COUNT,
    GNU_HELLO_REACHABLE_IMPORT_COUNT,
    GnuHelloCheckedResponseFamilyError,
    inspect_gnu_hello_checked_response_frontier,
    write_gnu_hello_checked_response_family,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="ascii")
    return path


def _input(root: Path) -> dict[str, object]:
    module = "StageA.CheckedGnuHelloResponseInputs"
    namespace = "StageA.CheckedGnuHelloResponseInputs"
    source = root / "CheckedGnuHelloResponseInputs.lean"
    source.write_text(
        """namespace StageA.CheckedGnuHelloResponseInputs
def context := ()
def ordinarySites := ()
def staticCompilation := ()
def staticAuthority := ()
def mixedContract := ()
def nestedFrames := ()
def machineSignatures := ()
def machineBoundaries := ()
def machineBoundaryContracts := ()
end StageA.CheckedGnuHelloResponseInputs
""",
        encoding="ascii",
    )
    imports = [
        f"library{index:02d}.dll!Import{index:02d}"
        for index in range(GNU_HELLO_REACHABLE_IMPORT_COUNT)
    ]
    registration_boundaries = {2, 16, 17, 18, 76}
    protocol_boundaries = {11, 13, 15, 27, 28, 29, 34, 181}
    termination_boundaries = {57, 173, 193}
    release_boundaries = {
        36,
        80,
        111,
        112,
        113,
        114,
        115,
        116,
        117,
        118,
        119,
        120,
        121,
        122,
        123,
        124,
        125,
        126,
        127,
    }
    boundary_signature_ids = []
    for index in range(GNU_HELLO_REACHABLE_EXTERNAL_SITE_COUNT):
        if index in registration_boundaries:
            boundary_signature_ids.append(0)
        elif index in protocol_boundaries:
            boundary_signature_ids.append(1)
        elif index in release_boundaries:
            boundary_signature_ids.append(2)
        elif index in termination_boundaries:
            boundary_signature_ids.append(len(imports) - 1)
        else:
            boundary_signature_ids.append(3 + (index % (len(imports) - 4)))
    sites = []
    footprint = {
        "access": "read",
        "base_argument": 0,
        "nullable": False,
        "offset": 0,
        "size": {"bytes": 1, "kind": "fixed"},
    }
    for index, import_index in enumerate(boundary_signature_ids):
        if import_index == 0:
            disposition = "returns"
            response_mode = "registration"
            callbacks = [{"kind": "registration", "argument_index": 0}]
            read_footprints = []
        elif import_index == 1:
            disposition = "protocol"
            response_mode = "nestedFrames"
            callbacks = [
                {"kind": "registered_nested_frames", "target_ids": [7, 8]}
            ]
            read_footprints = []
        elif import_index == 2:
            disposition = "returns"
            response_mode = "synchronous"
            callbacks = []
            read_footprints = []
        else:
            disposition = "terminates" if import_index == len(imports) - 1 else "returns"
            response_mode = "synchronous"
            callbacks = []
            read_footprints = [] if disposition == "terminates" else [footprint]
        sites.append(
            {
                "id": index,
                "import_identity": imports[import_index],
                "disposition": disposition,
                "response_mode": response_mode,
                "argument_sources": [{"kind": "stack_word", "offset": 4}],
                "read_footprints": read_footprints,
                "write_footprints": [],
                "callbacks": callbacks,
                "footprints_complete": True,
                "callbacks_complete": True,
            }
        )
    signatures = []
    for index, identity in enumerate(imports):
        dll, symbol = identity.split("!", 1)
        if index == 0:
            disposition = "returns"
            callback_mode = "registration"
            memory_effect = "none"
            world_effect = "callbackRegistration"
            footprints = []
        elif index == 1:
            disposition = "protocol"
            callback_mode = "nestedFrames"
            memory_effect = "relationalState"
            world_effect = "none"
            footprints = []
        elif index == 2:
            disposition = "returns"
            callback_mode = "none"
            memory_effect = "none"
            world_effect = "dynamicRangeRelease"
            footprints = []
        else:
            disposition = "terminates" if index == len(imports) - 1 else "returns"
            callback_mode = "none"
            memory_effect = "none" if disposition == "terminates" else "readOnly"
            world_effect = "none"
            footprints = [] if disposition == "terminates" else [footprint]
        signatures.append(
            {
                "id": index,
                "import": {"dll": dll, "symbol": symbol},
                "disposition": disposition,
                "callback_mode": callback_mode,
                "memory_effect": memory_effect,
                "world_effect": world_effect,
                "memory_footprints": footprints,
            }
        )
    boundaries = []
    for index, signature_id in enumerate(boundary_signature_ids):
        dll, symbol = imports[signature_id].split("!", 1)
        boundaries.append(
            {
                "id": index,
                "signature_id": signature_id,
                "import": {"dll": dll, "symbol": symbol},
                "argument_words": 1,
            }
        )
    report = root / "machine-import-report.json"
    _write(
        report,
        {
            "format": STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT,
            "status": "ready",
            "blockers": [],
            "counts": {
                "checked_boundary_proposals": len(boundaries),
                "required_reachable_imports": len(imports),
                "lean_profile_signatures": len(imports),
                "imports_with_boundary_proposals": len(imports),
            },
            "required_imports": [
                {
                    "dll": identity.split("!", 1)[0],
                    "symbol": identity.split("!", 1)[1],
                }
                for identity in imports
            ],
            "signatures": signatures,
            "boundaries": boundaries,
        },
    )
    refs = {
        name: {
            "module": module,
            "declaration": f"{namespace}.{declaration}",
        }
        for name, declaration in {
            "context": "context",
            "ordinary_sites": "ordinarySites",
            "static_compilation": "staticCompilation",
            "static_authority": "staticAuthority",
            "mixed_contract": "mixedContract",
            "nested_frames": "nestedFrames",
            "machine_signatures": "machineSignatures",
            "machine_boundaries": "machineBoundaries",
            "machine_boundary_contracts": "machineBoundaryContracts",
        }.items()
    }
    return {
        "format": GNU_HELLO_CHECKED_RESPONSE_FAMILY_INPUT_FORMAT,
        "candidate_sha256": "a" * 64,
        "reachable_external_site_ids": list(
            range(GNU_HELLO_REACHABLE_EXTERNAL_SITE_COUNT)
        ),
        "reachable_import_identities": imports,
        "lockstep_sites": sites,
        "machine_import_report": {
            "path": str(report),
            "sha256": _sha(report),
        },
        "lean": {
            "module_sources": [
                {
                    "module": module,
                    "path": str(source),
                    "sha256": _sha(source),
                }
            ],
            **refs,
        },
    }


class StageAGnuHelloCheckedResponseFamilyTests(unittest.TestCase):
    def test_emits_checked_static_family_and_truthful_completion_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outputs = write_gnu_hello_checked_response_family(
                root / "out", input_manifest=_write(root / "input.json", _input(root))
            )
            source = outputs.module.read_text(encoding="ascii")
            profile = json.loads(outputs.profile.read_text(encoding="ascii"))
            concrete = json.loads(
                outputs.concrete_pair_input.read_text(encoding="ascii")
            )
            report = json.loads(outputs.report.read_text(encoding="ascii"))
            needs = json.loads(outputs.artifact_needs.read_text(encoding="ascii"))

        self.assertIn("CheckedWorldNativeAdmittedProtocolResponseFamily", source)
        self.assertIn(
            "import StageA.RelationalNativeSourceResponseRequirements", source
        )
        self.assertIn("def completionRequirements", source)
        self.assertIn("abbrev PairRelated := responseFamily.Related", source)
        self.assertIn("intro admitted => exact admitted.responseSchedule", source)
        self.assertIn("checkedOriginalProtocolResponsesAt", source)
        self.assertIn("def classifiedSiteInventory", source)
        self.assertIn("checked := by native_decide", source)
        self.assertIn("completion : ResponseFamilyCompletion", source)
        self.assertIn(
            "abbrev ResponseFamilyCompletionDefinitions :=", source
        )
        self.assertIn("def responseFamilyCompletion", source)
        self.assertIn("def productionAcceptanceEvidence", source)
        self.assertIn(
            "theorem productionAdmittedEnvironmentFamilyEquivalent", source
        )
        self.assertIn("nestedAdmittedEnvironmentFamilyEquivalent", source)
        self.assertIn(
            "compiledNestedArtifactAdmittedEnvironmentFamilyEquivalent",
            source,
        )
        self.assertNotIn("canonicalAdmission", source)
        self.assertNotIn("declaration('nested_toolchain_correct_at')", source)
        self.assertNotIn("declaration('response_definitions')", source)
        self.assertIsNone(
            re.search(r"\b(?:axiom|opaque|sorry|admit)\b", source)
        )
        self.assertNotIn("sourceEnvironment =", source)
        self.assertEqual(len(profile["lockstep"]["sites"]), 194)
        self.assertEqual(profile["lean"]["source_family_scope"], "admitted_pairs")
        self.assertTrue(
            profile["lean"]["pair_relation"]["declaration"].endswith(
                ".PairRelated"
            )
        )
        self.assertTrue(
            profile["lean"]["nested_final_theorem_conditional"]["declaration"].endswith(
                ".nestedAdmittedEnvironmentFamilyEquivalent"
            )
        )
        self.assertTrue(
            profile["lean"]["completion_constructor"]["declaration"].endswith(
                ".responseFamilyCompletion"
            )
        )
        self.assertTrue(
            profile["lean"]["production_acceptance_theorem"]["declaration"].endswith(
                ".productionAdmittedEnvironmentFamilyEquivalent"
            )
        )
        self.assertTrue(
            concrete["lean"]["checked_static_family"].endswith(".responseFamily")
        )
        self.assertEqual(concrete["status"], "incomplete")
        self.assertTrue(
            concrete["lean"]["completion_constructor"].endswith(
                ".responseFamilyCompletion"
            )
        )
        self.assertEqual(
            concrete["blockers"][0]["category"],
            "dynamic_range_release_input_evidence_missing",
        )
        self.assertEqual(
            concrete["blockers"][0]["affected_site_ids"],
            [
                36,
                80,
                111,
                112,
                113,
                114,
                115,
                116,
                117,
                118,
                119,
                120,
                121,
                122,
                123,
                124,
                125,
                126,
                127,
            ],
        )
        self.assertEqual(
            concrete["blockers"][1]["affected_site_ids"], [2, 16, 17, 18, 76]
        )
        self.assertEqual(
            concrete["blockers"][-1]["category"],
            "reachable_response_domain_not_closed",
        )
        self.assertEqual(report["reachable_external_sites"], 194)
        self.assertEqual(report["reachable_imports"], 60)
        self.assertEqual(report["terminating_sites"], 3)
        self.assertEqual(report["registration_sites"], 5)
        self.assertEqual(report["protocol_sites"], 8)
        self.assertNotIn("canonical_admission", report["required_lean_inputs"])
        self.assertNotIn(
            "nested_toolchain_correct_at", report["required_lean_inputs"]
        )
        self.assertEqual(report["status"], "incomplete")
        self.assertTrue(report["completion_constructor_emitted"])
        self.assertTrue(report["production_acceptance_declarations_emitted"])
        self.assertTrue(
            report["production_acceptance_declaration"].endswith(
                ".productionAdmittedEnvironmentFamilyEquivalent"
            )
        )
        self.assertEqual(
            [premise["category"] for premise in report["remaining_premises"]],
            [
                "checked_response_completion_artifacts",
                "pinned_nested_compiler_stack_correctness",
            ],
        )
        self.assertEqual(
            report["remaining_premises"][0]["source"],
            "lean_checked_exact_artifacts_not_declaration_names",
        )
        self.assertEqual(
            report["remaining_premises"][0]["required_fields"],
            [
                "reachableBoundaryDomain",
                "protocolBoundaryDomain",
                "sourceEnvironment",
                "nativeEnvironment",
                "responseSchedule",
                "sourceAwaitingExternalResponses",
                "sourceFamily",
                "launchRealizable",
            ],
        )
        self.assertFalse(report["unapproved_axioms_allowed"])
        self.assertTrue(
            report["conditional_declaration"].endswith(
                ".nestedAdmittedEnvironmentFamilyEquivalent"
            )
        )
        self.assertEqual(
            report["formal_blockers"][0]["category"],
            "dynamic_range_release_input_evidence_missing",
        )
        self.assertEqual(
            report["formal_blockers"][-1]["category"],
            "reachable_response_domain_not_closed",
        )
        self.assertEqual(
            needs["format"],
            "stage-a-gnu-hello-response-completion-artifact-needs-v1",
        )
        self.assertEqual(
            len(needs["machine_contract_requirements"]["dynamic_range_release"]),
            19,
        )
        self.assertEqual(
            len(needs["machine_contract_requirements"]["callback_registration"]),
            5,
        )
        self.assertEqual(len(needs["required_checked_artifacts"]), 5)
        self.assertFalse(report["concrete_completion_emitted"])
        self.assertFalse(report["checked_protocol_responses_emitted"])
        self.assertEqual(report["admission_scope"], "all-checked-response-schedules")
        self.assertEqual(
            report["canonical_pair_role"],
            "required-checked-nonvacuity-completion",
        )

    def test_missing_site_or_import_fails_closed(self) -> None:
        for mutation, message in (
            (
                lambda value: (
                    value["reachable_external_site_ids"].pop(),
                    value["lockstep_sites"].pop(),
                ),
                "exactly 194",
            ),
            (
                lambda value: value["reachable_import_identities"].pop(),
                "exactly 60",
            ),
        ):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value = _input(root)
                mutation(value)
                with self.assertRaisesRegex(
                    GnuHelloCheckedResponseFamilyError, message
                ):
                    write_gnu_hello_checked_response_family(
                        root / "out",
                        input_manifest=_write(root / "input.json", value),
                    )

    def test_unknown_callbacks_and_incomplete_footprints_fail_closed(self) -> None:
        mutations = (
            (
                lambda value: value["lockstep_sites"][0]["callbacks"].append(
                    {"target": 7}
                ),
                "synchronous response cannot declare callbacks",
            ),
            (
                lambda value: value["lockstep_sites"][0].__setitem__(
                    "footprints_complete", False
                ),
                "incomplete memory footprints",
            ),
            (
                lambda value: value["lockstep_sites"][0].__setitem__(
                    "callbacks_complete", False
                ),
                "incomplete callback coverage",
            ),
        )
        for mutation, message in mutations:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value = _input(root)
                mutation(value)
                with self.assertRaisesRegex(
                    GnuHelloCheckedResponseFamilyError, message
                ):
                    write_gnu_hello_checked_response_family(
                        root / "out",
                        input_manifest=_write(root / "input.json", value),
                    )

    def test_ambiguous_site_or_unchecked_provider_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = _input(root)
            value["lockstep_sites"][1]["id"] = 0
            with self.assertRaisesRegex(
                GnuHelloCheckedResponseFamilyError, "unique"
            ):
                write_gnu_hello_checked_response_family(
                    root / "out", input_manifest=_write(root / "input.json", value)
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = _input(root)
            value["lean"].pop("machine_boundary_contracts")
            with self.assertRaisesRegex(
                GnuHelloCheckedResponseFamilyError, "missing=.*machine_boundary_contracts"
            ):
                write_gnu_hello_checked_response_family(
                    root / "out", input_manifest=_write(root / "input.json", value)
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = _input(root)
            value["lean"]["canonical_admission"] = value["lean"]["context"]
            with self.assertRaisesRegex(
                GnuHelloCheckedResponseFamilyError, "extra=.*canonical_admission"
            ):
                write_gnu_hello_checked_response_family(
                    root / "out", input_manifest=_write(root / "input.json", value)
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = _input(root)
            value["lean"]["response_definitions"] = value["lean"]["context"]
            with self.assertRaisesRegex(
                GnuHelloCheckedResponseFamilyError,
                "extra=.*response_definitions",
            ):
                write_gnu_hello_checked_response_family(
                    root / "out", input_manifest=_write(root / "input.json", value)
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = _input(root)
            source = Path(value["lean"]["module_sources"][0]["path"])
            source.write_text(source.read_text(encoding="ascii") + "axiom bad : True\n")
            value["lean"]["module_sources"][0]["sha256"] = _sha(source)
            with self.assertRaisesRegex(
                GnuHelloCheckedResponseFamilyError, "unchecked Lean declaration"
            ):
                write_gnu_hello_checked_response_family(
                    root / "out", input_manifest=_write(root / "input.json", value)
                )

    def test_import_identity_must_be_normalized_and_exactly_used(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = _input(root)
            value["lockstep_sites"][0]["import_identity"] = "Library00.dll!Import00"
            with self.assertRaisesRegex(
                GnuHelloCheckedResponseFamilyError, "normalized dll!symbol"
            ):
                write_gnu_hello_checked_response_family(
                    root / "out", input_manifest=_write(root / "input.json", value)
                )

    def test_machine_report_supported_protocol_partition_is_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = _input(root)
            report_path = Path(value["machine_import_report"]["path"])
            frontier = inspect_gnu_hello_checked_response_frontier(report_path)

        self.assertEqual(frontier["status"], "ready")
        self.assertEqual(frontier["supported_external_sites"], 194)
        self.assertEqual(frontier["supported_imports"], 60)
        self.assertEqual(
            frontier["response_modes"],
            {"synchronous": 181, "registration": 5, "nestedFrames": 8},
        )
        self.assertEqual(
            frontier["response_mode_site_ids"]["registration"],
            [2, 16, 17, 18, 76],
        )
        self.assertEqual(
            frontier["response_mode_site_ids"]["nestedFrames"],
            [11, 13, 15, 27, 28, 29, 34, 181],
        )
        self.assertEqual(frontier["completion_status"], "blocked")
        self.assertEqual(
            frontier["completion_blockers"][0]["affected_site_ids"],
            [
                36,
                80,
                111,
                112,
                113,
                114,
                115,
                116,
                117,
                118,
                119,
                120,
                121,
                122,
                123,
                124,
                125,
                126,
                127,
            ],
        )
        self.assertEqual(
            frontier["completion_blockers"][1]["affected_site_ids"],
            [2, 16, 17, 18, 76],
        )

    def test_release_effect_reports_exact_machine_sites_and_locations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = _input(root)
            report_path = Path(value["machine_import_report"]["path"])
            report = json.loads(report_path.read_text(encoding="ascii"))
            report["boundaries"][0]["source_rva"] = 4096
            report["boundaries"][0]["instruction_rva"] = 4100
            report["boundaries"][0]["signature_id"] = 2
            _write(report_path, report)
            frontier = inspect_gnu_hello_checked_response_frontier(report_path)

        release = next(
            blocker
            for blocker in frontier["completion_blockers"]
            if blocker["category"]
            == "dynamic_range_release_input_evidence_missing"
        )
        self.assertIn(0, release["affected_site_ids"])
        self.assertEqual(release["locations"][0]["source_rva"], 4096)
        self.assertEqual(release["locations"][0]["instruction_rva"], 4100)
        self.assertTrue(
            release["necessity_theorem"].endswith(
                ".machineCallResultConforms_inputAdmissible"
            )
        )

    def test_completion_artifact_needs_follow_machine_effect_classes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = _input(root)
            outputs = write_gnu_hello_checked_response_family(
                root / "out",
                input_manifest=_write(root / "input.json", value),
            )
            baseline = json.loads(outputs.artifact_needs.read_text(encoding="ascii"))

            report_path = Path(value["machine_import_report"]["path"])
            report = json.loads(report_path.read_text(encoding="ascii"))
            report["signatures"][3]["memory_effect"] = "none"
            report["signatures"][3]["memory_footprints"] = []
            for site_id in (0, 56, 168):
                value["lockstep_sites"][site_id]["read_footprints"] = []
            _write(report_path, report)
            value["machine_import_report"]["sha256"] = _sha(report_path)
            mutated = write_gnu_hello_checked_response_family(
                root / "mutated",
                input_manifest=_write(root / "mutated-input.json", value),
            )
            changed = json.loads(mutated.artifact_needs.read_text(encoding="ascii"))

        baseline_sites = baseline["machine_contract_requirements"][
            "runtime_memory_footprints"
        ]
        changed_sites = changed["machine_contract_requirements"][
            "runtime_memory_footprints"
        ]
        self.assertGreater(len(baseline_sites), len(changed_sites))
        self.assertEqual(
            {row["site_id"] for row in baseline_sites}
            - {row["site_id"] for row in changed_sites},
            {0, 56, 168},
        )

    def test_unknown_callback_protocol_combinations_fail_closed(self) -> None:
        mutations = (
            {"callback_mode": "mystery"},
            {"callback_mode": "registration", "world_effect": "none"},
            {"callback_mode": "nestedFrames", "disposition": "returns"},
            {"callback_mode": "nestedFrames", "memory_effect": "readOnly"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value = _input(root)
                report_path = Path(value["machine_import_report"]["path"])
                report = json.loads(report_path.read_text(encoding="ascii"))
                report["signatures"][1].update(mutation)
                _write(report_path, report)
                frontier = inspect_gnu_hello_checked_response_frontier(report_path)
            self.assertEqual(frontier["status"], "incomplete")
            self.assertEqual(frontier["blocked_external_sites"], 8)
            self.assertEqual(
                {blocker["category"] for blocker in frontier["blockers"]},
                {"unknown_callback_protocol_form"},
            )

    def test_callback_declarations_are_complete_and_bounded(self) -> None:
        mutations = (
            (
                lambda value: value["lockstep_sites"][2]["callbacks"].clear(),
                "registration response must return and declare one callback",
            ),
            (
                lambda value: value["lockstep_sites"][2]["callbacks"][0].__setitem__(
                    "argument_index", 1
                ),
                "callback argument is out of range",
            ),
            (
                lambda value: value["lockstep_sites"][11]["callbacks"][0].__setitem__(
                    "target_ids", []
                ),
                "must be a non-empty array",
            ),
        )
        for mutation, message in mutations:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value = _input(root)
                mutation(value)
                with self.assertRaisesRegex(
                    GnuHelloCheckedResponseFamilyError, message
                ):
                    write_gnu_hello_checked_response_family(
                        root / "out",
                        input_manifest=_write(root / "input.json", value),
                    )


if __name__ == "__main__":
    unittest.main()
