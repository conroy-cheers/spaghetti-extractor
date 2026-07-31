from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import subprocess
import textwrap
import unittest


class StageAISAQualificationGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).resolve().parents[1]
        cls.source = (
            cls.repo / "nix" / "stage-a-isa-qualification-graph.nix"
        ).read_text(encoding="utf-8")
        cls.layered_schema = cls._nix_string(
            "layeredArtifactSchemaPredicate ="
        )
        cls.schema_template = cls._nix_string(
            "mkArtifactSchemaPredicate ="
        )
        cls.qualified_template = cls._nix_string(
            "mkQualifiedArtifactPredicate ="
        )
        cls.usable_selection_template = cls._nix_string(
            "mkUsableSelectionArtifactPredicate ="
        )

    @classmethod
    def _nix_string(cls, anchor: str) -> str:
        anchor_index = cls.source.index(anchor)
        start = cls.source.index("''\n", anchor_index) + 3
        terminator = re.search(r"(?m)^\s*'';$", cls.source[start:])
        if terminator is None:
            raise AssertionError(f"unterminated Nix string after {anchor}")
        return textwrap.dedent(
            cls.source[start : start + terminator.start()]
        ).strip()

    @classmethod
    def _predicates(
        cls, legacy_format: str, layered_format: str
    ) -> tuple[str, str, str]:
        schema = (
            cls.schema_template.replace("${legacyFormat}", legacy_format)
            .replace("${layeredFormat}", layered_format)
            .replace(
                "${layeredArtifactSchemaPredicate}",
                cls.layered_schema,
            )
        )
        qualified = (
            cls.qualified_template.replace("${legacyFormat}", legacy_format)
            .replace("${layeredFormat}", layered_format)
            .replace("${schemaPredicate}", schema)
        )
        usable = (
            cls.usable_selection_template.replace(
                "${legacyFormat}", legacy_format
            )
            .replace("${layeredFormat}", layered_format)
            .replace("${schemaPredicate}", schema)
        )
        if "${" in schema or "${" in qualified or "${" in usable:
            raise AssertionError("unexpanded Nix interpolation in jq predicate")
        return schema, qualified, usable

    def _assert_jq(
        self, predicate: str, payload: dict, *, accepts: bool
    ) -> None:
        process = subprocess.run(
            ["jq", "-e", predicate],
            input=json.dumps(payload),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if accepts:
            self.assertEqual(process.returncode, 0, process.stderr)
        else:
            self.assertNotEqual(process.returncode, 0, process.stderr)

    @staticmethod
    def _layers(
        *,
        required_forms: int = 2,
        structural_status: str = "complete",
        oracle_status: str = "qualified",
    ) -> dict:
        structural_incomplete = int(structural_status == "incomplete")
        oracle_counts = {
            "qualified": 0,
            "incomplete": 0,
            "disputed": 0,
            "vetoed": 0,
        }
        if required_forms:
            oracle_counts[oracle_status] = 1
            oracle_counts["qualified"] += required_forms - 1
        return {
            "structural": {
                "status": structural_status,
                "counts": {
                    "required_forms": required_forms,
                    "complete": required_forms - structural_incomplete,
                    "incomplete": structural_incomplete,
                },
                "diagnostics": [],
            },
            "concrete_oracle": {
                "status": oracle_status,
                "counts": {
                    "required_forms": required_forms,
                    **oracle_counts,
                },
                "diagnostics": [],
            },
        }

    @classmethod
    def _payload(
        cls,
        artifact_format: str,
        *,
        status: str = "qualified",
        layers: dict | None = None,
    ) -> dict:
        payload = {
            "format": artifact_format,
            "status": status,
            "trust": {
                "proof_authority": False,
                "closes_stage_a_proof": False,
            },
        }
        if layers is not None:
            payload["qualification_layers"] = layers
        return payload

    def test_graph_wires_schema_and_qualified_predicates(self) -> None:
        for invocation in (
            "jq -e '${qualificationArtifactSchemaPredicate}'",
            "jq -e '${qualifiedQualificationArtifactPredicate}'",
            "jq -e '${selectionArtifactSchemaPredicate}'",
            "jq -e '${qualifiedSelectionArtifactPredicate}'",
            "jq -e '${usableSelectionArtifactPredicate}'",
        ):
            self.assertIn(invocation, self.source)

    def test_evidence_policy_is_emitted_by_the_usable_selection_gate(self) -> None:
        strict_start = self.source.index("selectionCheck =")
        evidence_start = self.source.index("selectionEvidenceCheck =")
        campaign_start = self.source.index("campaign =", evidence_start)
        strict_source = self.source[strict_start:evidence_start]
        evidence_source = self.source[evidence_start:campaign_start]

        self.assertNotIn('"$out/policy.json"', strict_source)
        self.assertIn('"$out/policy.json"', evidence_source)
        self.assertIn(
            '"stage-a-isa-selection-evidence-policy-v1"',
            evidence_source,
        )

    def test_gnu_proof_report_retains_non_authoritative_isa_policy(self) -> None:
        gnu_source = (
            self.repo / "nix" / "gnu-hello-roundtrip.nix"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'ln -s ${sideIsaQualificationBundle} '
            '\\\n      "$out/side-isa-qualification"',
            gnu_source,
        )
        self.assertIn(
            "${sideIsaQualificationBundle}/selection-policy.json",
            gnu_source,
        )
        self.assertIn(
            '"side_isa_qualification": side_isa_policy',
            gnu_source,
        )
        self.assertIn(
            'side_isa_policy.get("counts", {}).get("disputed") != 0',
            gnu_source,
        )
        self.assertIn(
            'side_isa_policy.get("counts", {}).get("vetoed") != 0',
            gnu_source,
        )

    def test_v1_and_v2_artifact_schema_checks(self) -> None:
        for legacy_format, layered_format in (
            (
                "stage-a-isa-kernel-qualification-v1",
                "stage-a-isa-kernel-qualification-v2",
            ),
            (
                "stage-a-isa-kernel-selection-v1",
                "stage-a-isa-kernel-selection-v2",
            ),
        ):
            with self.subTest(layered_format=layered_format):
                schema, _, _ = self._predicates(
                    legacy_format, layered_format
                )
                self._assert_jq(
                    schema,
                    self._payload(legacy_format, status="incomplete"),
                    accepts=True,
                )
                self._assert_jq(
                    schema,
                    self._payload(
                        layered_format, layers=self._layers()
                    ),
                    accepts=True,
                )
                self._assert_jq(
                    schema,
                    self._payload(layered_format),
                    accepts=False,
                )

                bad_counts = self._payload(
                    layered_format, layers=self._layers()
                )
                bad_counts["qualification_layers"]["structural"]["counts"][
                    "complete"
                ] = 1
                self._assert_jq(schema, bad_counts, accepts=False)

                bad_trust = self._payload(
                    layered_format, layers=self._layers()
                )
                bad_trust["trust"]["proof_authority"] = True
                self._assert_jq(schema, bad_trust, accepts=False)

    def test_v2_qualified_gate_requires_both_layers_to_close(self) -> None:
        for legacy_format, layered_format in (
            (
                "stage-a-isa-kernel-qualification-v1",
                "stage-a-isa-kernel-qualification-v2",
            ),
            (
                "stage-a-isa-kernel-selection-v1",
                "stage-a-isa-kernel-selection-v2",
            ),
        ):
            with self.subTest(layered_format=layered_format):
                schema, qualified, _ = self._predicates(
                    legacy_format, layered_format
                )
                self._assert_jq(
                    qualified,
                    self._payload(legacy_format),
                    accepts=True,
                )
                self._assert_jq(
                    qualified,
                    self._payload(legacy_format, status="incomplete"),
                    accepts=False,
                )
                complete = self._payload(
                    layered_format, layers=self._layers()
                )
                self._assert_jq(schema, complete, accepts=True)
                self._assert_jq(qualified, complete, accepts=True)

                structural_incomplete = self._payload(
                    layered_format,
                    layers=self._layers(structural_status="incomplete"),
                )
                self._assert_jq(
                    schema, structural_incomplete, accepts=True
                )
                self._assert_jq(
                    qualified, structural_incomplete, accepts=False
                )

                for oracle_status in ("incomplete", "disputed", "vetoed"):
                    oracle_blocked = self._payload(
                        layered_format,
                        layers=self._layers(oracle_status=oracle_status),
                    )
                    self._assert_jq(schema, oracle_blocked, accepts=True)
                    self._assert_jq(
                        qualified, oracle_blocked, accepts=False
                    )

                diagnosed = copy.deepcopy(complete)
                diagnosed["qualification_layers"]["concrete_oracle"][
                    "diagnostics"
                ] = [{"code": "unexpected"}]
                self._assert_jq(schema, diagnosed, accepts=True)
                self._assert_jq(qualified, diagnosed, accepts=False)

                empty = self._payload(
                    layered_format,
                    layers=self._layers(required_forms=0),
                )
                self._assert_jq(schema, empty, accepts=True)
                self._assert_jq(qualified, empty, accepts=False)

    def test_usable_selection_gate_allows_only_non_vetoed_oracle_gaps(
        self,
    ) -> None:
        schema, qualified, usable = self._predicates(
            "stage-a-isa-kernel-selection-v1",
            "stage-a-isa-kernel-selection-v2",
        )
        incomplete_oracle = self._payload(
            "stage-a-isa-kernel-selection-v2",
            status="incomplete",
            layers=self._layers(oracle_status="incomplete"),
        )
        self._assert_jq(schema, incomplete_oracle, accepts=True)
        self._assert_jq(qualified, incomplete_oracle, accepts=False)
        self._assert_jq(usable, incomplete_oracle, accepts=True)
        self._assert_jq(
            usable,
            self._payload(
                "stage-a-isa-kernel-selection-v1",
                status="incomplete",
            ),
            accepts=False,
        )
        legacy_qualified = self._payload(
            "stage-a-isa-kernel-selection-v1",
            status="qualified",
        )
        legacy_qualified["counts"] = {
            "disputed": 0,
            "vetoed": 0,
        }
        self._assert_jq(usable, legacy_qualified, accepts=True)

        for status in ("disputed", "vetoed"):
            blocked = self._payload(
                "stage-a-isa-kernel-selection-v2",
                status=status,
                layers=self._layers(oracle_status=status),
            )
            self._assert_jq(schema, blocked, accepts=True)
            self._assert_jq(usable, blocked, accepts=False)

        structural_incomplete = self._payload(
            "stage-a-isa-kernel-selection-v2",
            status="incomplete",
            layers=self._layers(structural_status="incomplete"),
        )
        self._assert_jq(usable, structural_incomplete, accepts=False)


if __name__ == "__main__":
    unittest.main()
