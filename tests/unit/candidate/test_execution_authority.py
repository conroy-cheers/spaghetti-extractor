from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.authority.root_closure import RootedControlEdgeV3
from spaghetti_extractor.candidate.authority.execution import (
    CandidateExecutionAuthorityError,
    CandidateExecutionAuthorityV3,
    CheckedIndirectDispatchV3,
    load_candidate_execution_authority_v3,
)


class CandidateExecutionAuthorityTests(unittest.TestCase):
    def test_checked_view_exposes_only_site_bound_control_facts(self) -> None:
        call = SimpleNamespace(
            source_unit_id="unit:a",
            event_index=2,
            preserved_registers=("ebx", "esi"),
        )
        summary = SimpleNamespace(
            status="complete",
            authorizing=True,
            member_unit_ids=("unit:a",),
            call_effects=(call,),
            covers_unit=lambda unit_id: unit_id == "unit:a",
        )
        dispatch = CheckedIndirectDispatchV3(
            exit_id="exit:a:2",
            source_unit_id="unit:a",
            source_event_index=2,
            transfer_kind="indirect_call",
            target_unit_ids=("unit:a",),
            external_targets=(),
            certificate_id="certificate:a",
        )
        authority = CandidateExecutionAuthorityV3(
            root_unit_ids=("unit:a",),
            reachable_unit_ids=("unit:a",),
            edges=(),
            indirect_dispatches=(dispatch,),
            summaries=(summary,),
            root_closure_manifest_sha256="a" * 64,
            target_certificates_manifest_sha256="b" * 64,
            parametric_summaries_manifest_sha256="c" * 64,
        )

        self.assertEqual(
            authority.internal_indirect_sites,
            frozenset({("unit:a", 2)}),
        )
        self.assertEqual(
            authority.call_preservation_by_site,
            {("unit:a", 2): frozenset({"ebx", "esi"})},
        )

    def test_checked_view_rejects_missing_or_ambiguous_summary_coverage(self) -> None:
        summary = SimpleNamespace(
            status="complete",
            authorizing=True,
            member_unit_ids=("unit:a",),
            call_effects=(),
            covers_unit=lambda unit_id: unit_id == "unit:a",
        )
        common = dict(
            root_unit_ids=("unit:a",),
            reachable_unit_ids=("unit:a",),
            edges=(),
            indirect_dispatches=(),
            root_closure_manifest_sha256="a" * 64,
            target_certificates_manifest_sha256="b" * 64,
            parametric_summaries_manifest_sha256="c" * 64,
        )
        with self.assertRaisesRegex(
            CandidateExecutionAuthorityError, "lack one checked parametric summary"
        ):
            CandidateExecutionAuthorityV3(summaries=(), **common)
        with self.assertRaisesRegex(
            CandidateExecutionAuthorityError, "lack one checked parametric summary"
        ):
            CandidateExecutionAuthorityV3(summaries=(summary, summary), **common)

    def test_loader_rejects_stale_rooted_indirect_edge(self) -> None:
        edge = RootedControlEdgeV3.create(
            "unit:a", "unit:b", "recovered_indirect", "certificate:stale"
        )
        root = SimpleNamespace(
            status="complete",
            authorizing=True,
            frontier_ids=(),
            root_unit_ids=("unit:a",),
            reachable_unit_ids=("unit:a", "unit:b"),
            edges=(edge,),
        )
        certificate = SimpleNamespace(
            status="complete",
            authorizing=True,
            source_unit_id="unit:a",
            target_unit_ids=("unit:b",),
            exit_id="exit:a",
            source_event_index=None,
            transfer_kind="indirect_jump",
            external_targets=(),
            certificate_id="certificate:current",
        )
        target_unit = SimpleNamespace(
            source_unit_id="unit:a", certificates=(certificate,)
        )
        summary_a = SimpleNamespace(
            record_id="summary:a",
            status="complete",
            authorizing=True,
            member_unit_ids=("unit:a",),
            call_effects=(),
            indirect_exits=(
                SimpleNamespace(
                    exit_id="exit:a",
                    source_unit_id="unit:a",
                    target_unit_ids=("unit:b",),
                ),
            ),
            covers_unit=lambda unit_id: unit_id == "unit:a",
        )
        summary_b = SimpleNamespace(
            record_id="summary:b",
            status="complete",
            authorizing=True,
            member_unit_ids=("unit:b",),
            call_effects=(),
            indirect_exits=(),
            covers_unit=lambda unit_id: unit_id == "unit:b",
        )
        paths = {
            Path("root"): self._reader("launch-root-closure-v3", (object(),), "a"),
            Path("targets"): self._reader(
                "indirect-target-certificates-v3", (object(),), "b"
            ),
            Path("summaries"): self._reader(
                "parametric-scc-summaries-v3", (object(), object()), "c"
            ),
        }
        summaries = iter((summary_a, summary_b))
        with (
            patch(
                "spaghetti_extractor.candidate.authority.execution.open_artifact_reader_v3",
                side_effect=lambda path: paths[path],
            ),
            patch(
                "spaghetti_extractor.candidate.authority.execution.LAUNCH_ROOT_CLOSURE_CODEC_V3",
                SimpleNamespace(read=lambda _record: SimpleNamespace(value=root)),
            ),
            patch(
                "spaghetti_extractor.candidate.authority.execution.INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3",
                SimpleNamespace(
                    read=lambda _record: SimpleNamespace(value=target_unit)
                ),
            ),
            patch(
                "spaghetti_extractor.candidate.authority.execution.PARAMETRIC_SCC_SUMMARY_CODEC_V3",
                SimpleNamespace(
                    read=lambda _record: SimpleNamespace(value=next(summaries))
                ),
            ),
        ):
            with self.assertRaisesRegex(
                CandidateExecutionAuthorityError, "lacks its exact checked certificate"
            ):
                load_candidate_execution_authority_v3(
                    root_closure=Path("root"),
                    target_certificates=Path("targets"),
                    parametric_summaries=Path("summaries"),
                )

    @staticmethod
    def _reader(kind: str, records: tuple[object, ...], digest: str) -> SimpleNamespace:
        return SimpleNamespace(
            manifest=SimpleNamespace(artifact_kind=kind),
            manifest_sha256=digest * 64,
            iter_records=lambda: iter(records),
        )


if __name__ == "__main__":
    unittest.main()
