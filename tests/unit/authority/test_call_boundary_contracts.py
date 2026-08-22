from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import ArtifactSetWriterV3
from spaghetti_extractor.artifacts.io import ArtifactSetReaderV3
from spaghetti_extractor.authority.call_boundary_contracts import (
    CALL_BOUNDARY_CONTRACT_CODEC_V3,
    CALL_BOUNDARY_CONTRACTS_PHASE_V3,
)
from spaghetti_extractor.authority.incoming_call_frames import (
    INCOMING_CALL_FRAMES_PHASE_V3,
)
from spaghetti_extractor.authority.normal_call_abi import (
    NORMAL_CALL_ABI_PREMISE_CODEC_V3,
    NORMAL_CALL_ABI_PREMISES_ARTIFACT_KIND_V3,
    NormalCallABIPremiseRecordV3,
)
from spaghetti_extractor.artifacts.machine_abi import (
    build_pe32_normal_call_abi_premise,
)
from tests.unit.authority import test_incoming_call_frames as incoming_fixture
from tests.unit.authority_inputs import test_external_site_evidence as fixture


def _premise(path: Path) -> Path:
    source = build_pe32_normal_call_abi_premise()
    record = NormalCallABIPremiseRecordV3(
        record_id=source.premise_id,
        content_sha256=source.content_sha256,
        preserved_registers=tuple(sorted(source.preserved_registers)),
        clobbered_registers=tuple(sorted(source.clobbered_registers)),
        transfer_kinds=tuple(sorted(source.transfer_kinds)),
    )
    ArtifactSetWriterV3(
        artifact_kind=NORMAL_CALL_ABI_PREMISES_ARTIFACT_KIND_V3,
        bindings=(fixture.BINDING,),
    ).write(path, (NORMAL_CALL_ABI_PREMISE_CODEC_V3.write(record.record_id, record),))
    return path


class CallBoundaryContractTests(unittest.TestCase):
    def test_exact_incoming_call_instantiates_conditional_abi_contract(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            semantic, transitions = incoming_fixture._inputs(root)
            incoming = INCOMING_CALL_FRAMES_PHASE_V3.run(
                output_directory=root / "incoming",
                inputs={
                    "semantic_index": semantic,
                    "transition_summaries": transitions,
                },
                bindings=(fixture.BINDING,),
            ).output_directory

            output = CALL_BOUNDARY_CONTRACTS_PHASE_V3.run(
                output_directory=root / "contracts",
                inputs={
                    "incoming_call_frames": incoming,
                    "normal_call_abi_premises": _premise(root / "premise"),
                },
                bindings=(fixture.BINDING,),
            ).output_directory

            records = tuple(ArtifactSetReaderV3(output).iter_records())
            self.assertEqual(len(records), 1)
            contract = CALL_BOUNDARY_CONTRACT_CODEC_V3.read(records[0]).value
            self.assertEqual(contract.record_id, "target:unit")
            self.assertEqual(
                contract.preserved_registers,
                ("ebp", "ebx", "edi", "esi"),
            )
            self.assertEqual(contract.applies_when, "call_returns_normally")
            self.assertTrue(contract.authorizing)

    def test_incomplete_caller_frame_does_not_authorize_contract(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            semantic, transitions = incoming_fixture._inputs(
                root, caller_status="incomplete"
            )
            incoming = INCOMING_CALL_FRAMES_PHASE_V3.run(
                output_directory=root / "incoming",
                inputs={
                    "semantic_index": semantic,
                    "transition_summaries": transitions,
                },
                bindings=(fixture.BINDING,),
            ).output_directory

            output = CALL_BOUNDARY_CONTRACTS_PHASE_V3.run(
                output_directory=root / "contracts",
                inputs={
                    "incoming_call_frames": incoming,
                    "normal_call_abi_premises": _premise(root / "premise"),
                },
                bindings=(fixture.BINDING,),
            ).output_directory
            contract = CALL_BOUNDARY_CONTRACT_CODEC_V3.read(
                next(ArtifactSetReaderV3(output).iter_records())
            ).value

            self.assertEqual(contract.status, "incomplete")
            self.assertFalse(contract.authorizing)
            self.assertEqual(
                contract.failure_code, "incoming_call_frame_incomplete"
            )


if __name__ == "__main__":
    unittest.main()
