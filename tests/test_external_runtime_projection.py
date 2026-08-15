from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import (
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    canonical_sha256_v3,
)
from spaghetti_extractor.authority.authority_common import PrimaryBlockerV3
from spaghetti_extractor.authority.external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    CanonicalExternalSiteRecordV3,
    CanonicalExternalSiteV3,
    ExternalContractV3,
    external_site_id_v3,
)
from spaghetti_extractor.errors import ToolkitInputError
from spaghetti_extractor.external.runtime_projection import (
    load_authoritative_external_sites,
)


SHA = hashlib.sha256(b"runtime-projection").hexdigest()


def _contract() -> ExternalContractV3:
    return ExternalContractV3.create(
        identity={"kind": "import", "dll": "kernel32.dll", "symbol": "ExitProcess"},
        transfer_kind="call",
        disposition="noreturn",
        profile_id="kernel32-exit-process",
        profile_sha256=SHA,
        argument_words=1,
        arguments=[{"kind": "stack", "offset": 0}],
        memory_effect="none",
        world_effect="process-exit",
        callback_effect="none",
        machine_contract={
            "abi_template": "pe32-stdcall-v1",
            "result_register_relations": [],
            "memory_footprints": [],
            "out_pointer_relations": [],
            "out_interface_relations": [],
        },
    )


def _write_artifact(root: Path, *, complete: bool) -> Path:
    unit_id = "unit-00401000"
    target = {"kind": "import", "dll": "kernel32.dll", "symbol": "ExitProcess"}
    target_sha256 = canonical_sha256_v3(target)
    site_id = external_site_id_v3(unit_id, 0, 0, target)
    contract = _contract() if complete else None
    blocker = None
    if not complete:
        blocker = PrimaryBlockerV3("incomplete", "external_contract_missing")
    site = CanonicalExternalSiteV3(
        site_id=site_id,
        unit_id=unit_id,
        event_index=0,
        alternative_index=0,
        event_sha256=SHA,
        target_sha256=target_sha256,
        identity=CanonicalValueV3.of(target),
        status="complete" if complete else "incomplete",
        authorizing=complete,
        contract=contract,
        primary_blocker=blocker,
    )
    record = CanonicalExternalSiteRecordV3(
        record_id=unit_id,
        unit_sha256=SHA,
        status="complete" if complete else "incomplete",
        authorizing=complete,
        sites=(site,),
        primary_blocker=blocker,
        dependencies=(),
    )
    output = root / ("complete" if complete else "incomplete")
    ArtifactSetWriterV3(
        artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
        bindings=(),
        status="complete" if complete else "incomplete",
    ).write(
        output,
        [
            ArtifactRecordV3.create(
                unit_id,
                CANONICAL_EXTERNAL_SITE_CODEC_V3.encode(record),
            )
        ],
    )
    return output


class ExternalRuntimeProjectionTests(unittest.TestCase):
    def test_projects_complete_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = load_authoritative_external_sites(
                _write_artifact(Path(directory), complete=True)
            )
        self.assertEqual(len(result.sites), 1)
        site = result.sites[0]
        self.assertEqual(site.unit_id, "unit-00401000")
        self.assertEqual(site.contract.argument_words, 1)
        self.assertEqual(site.contract.profile_disposition, "terminates")

    def test_rejects_non_authorizing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = _write_artifact(Path(directory), complete=False)
            with self.assertRaisesRegex(ToolkitInputError, "not authorizing"):
                load_authoritative_external_sites(path)


if __name__ == "__main__":
    unittest.main()
