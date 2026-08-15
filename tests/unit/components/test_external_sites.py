from __future__ import annotations

import hashlib
import json
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
from spaghetti_extractor.components.external_sites import (
    load_component_external_site_slice,
    project_component_external_sites,
)


SHA = hashlib.sha256(b"component-external-sites").hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _contract(symbol: str = "memcmp") -> ExternalContractV3:
    return ExternalContractV3.create(
        identity={"kind": "import", "dll": "msvcrt.dll", "symbol": symbol},
        transfer_kind="call",
        disposition="returns",
        profile_id="pe32-msvcrt-lockstep-v1",
        profile_sha256=SHA,
        argument_words=3,
        arguments=[
            {"kind": "stack", "offset": 0},
            {"kind": "stack", "offset": 4},
            {"kind": "stack", "offset": 8},
        ],
        memory_effect="readOnly",
        world_effect="none",
        callback_effect="none",
        machine_contract={
            "abi_template": "pe32-cdecl-v1",
            "result_register_relations": [
                {"register": "eax", "relation": "exact"}
            ],
            "memory_footprints": [],
            "out_pointer_relations": [],
            "out_interface_relations": [],
        },
    )


def _record(
    unit_id: str,
    *,
    complete: bool,
    symbol: str = "memcmp",
    rich_target: bool = False,
) -> ArtifactRecordV3:
    identity = {"kind": "import", "dll": "msvcrt.dll", "symbol": symbol}
    target = (
        {
            "kind": "external_call",
            "import": {"dll": "msvcrt.dll", "symbol": symbol},
            "arguments": [
                {"kind": "stack", "offset": 0},
                {"kind": "stack", "offset": 4},
                {"kind": "stack", "offset": 8},
            ],
        }
        if rich_target
        else identity
    )
    target_sha256 = canonical_sha256_v3(target)
    blocker = None if complete else PrimaryBlockerV3(
        "incomplete", "external_contract_missing"
    )
    site = CanonicalExternalSiteV3(
        site_id=external_site_id_v3(unit_id, 0, 0, target),
        unit_id=unit_id,
        event_index=0,
        alternative_index=0,
        event_sha256=target_sha256,
        target_sha256=target_sha256,
        identity=CanonicalValueV3.of(identity),
        status="complete" if complete else "incomplete",
        authorizing=complete,
        contract=_contract(symbol) if complete else None,
        primary_blocker=blocker,
    )
    value = CanonicalExternalSiteRecordV3(
        record_id=unit_id,
        unit_sha256=SHA,
        status="complete" if complete else "incomplete",
        authorizing=complete,
        sites=(site,),
        primary_blocker=blocker,
        dependencies=(),
    )
    return ArtifactRecordV3.create(
        unit_id, CANONICAL_EXTERNAL_SITE_CODEC_V3.encode(value)
    )


def _write_artifact(root: Path, *, complete: bool, unrelated_symbol: str) -> Path:
    output = root / f"artifact-{unrelated_symbol}"
    ArtifactSetWriterV3(
        artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
        bindings=(),
        status="complete",
    ).write(
        output,
        [
            _record("unit:a", complete=complete),
            _record("unit:unrelated", complete=True, symbol=unrelated_symbol),
        ],
    )
    return output


def _resolution() -> dict[str, object]:
    core: dict[str, object] = {
        "format": "spaghetti-extractor-component-resolution-slice-v1",
        "status": "checked",
        "program_id": "fixture",
        "executes_original_binary": False,
        "permitted_activation_profiles": ["bounded-equivalence-v1"],
        "bindings": {},
        "components": [
            {
                "kind": "component",
                "id": "a",
                "label": "A",
                "unit_ids": ["unit:a"],
            }
        ],
        "groups": [],
        "configurations": [],
    }
    return {**core, "resolution_sha256": _canonical_sha256(core)}


class ComponentExternalSiteTests(unittest.TestCase):
    def test_projects_and_loads_one_authorizing_component_slice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "slice.json"
            payload = project_component_external_sites(
                canonical_external_sites=_write_artifact(
                    root, complete=True, unrelated_symbol="strlen"
                ),
                resolution=_resolution(),
                lift_unit_id="a",
                out=output,
            )
            loaded = load_component_external_site_slice(output)
        self.assertEqual(payload["status"], "checked")
        self.assertEqual(loaded.status, "checked")
        self.assertEqual(len(loaded.sites), 1)
        self.assertEqual(loaded.sites[0].contract.argument_words, 3)
        self.assertEqual(loaded.sites[0].contract.identity.symbol, "memcmp")

    def test_loader_accepts_the_canonical_projection_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project_component_external_sites(
                canonical_external_sites=_write_artifact(
                    root, complete=True, unrelated_symbol="strlen"
                ),
                resolution=_resolution(),
                lift_unit_id="a",
                out=root / "external-sites.json",
            )
            loaded = load_component_external_site_slice(root)

        self.assertEqual(loaded.status, "checked")
        self.assertEqual(loaded.lift_unit_id, "a")

    def test_unrelated_authority_change_preserves_projected_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = project_component_external_sites(
                canonical_external_sites=_write_artifact(
                    root, complete=True, unrelated_symbol="strlen"
                ),
                resolution=_resolution(),
                lift_unit_id="a",
                out=root / "first.json",
            )
            second = project_component_external_sites(
                canonical_external_sites=_write_artifact(
                    root, complete=True, unrelated_symbol="strcmp"
                ),
                resolution=_resolution(),
                lift_unit_id="a",
                out=root / "second.json",
            )
        self.assertEqual(first, second)

    def test_non_authorizing_site_remains_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "slice.json"
            payload = project_component_external_sites(
                canonical_external_sites=_write_artifact(
                    root, complete=False, unrelated_symbol="strlen"
                ),
                resolution=_resolution(),
                lift_unit_id="a",
                out=output,
            )
            loaded = load_component_external_site_slice(output)
        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(loaded.status, "incomplete")
        self.assertFalse(loaded.sites[0].authorizing)
        self.assertIsNone(loaded.sites[0].contract)

    def test_full_target_hash_may_differ_from_normalized_identity_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            ArtifactSetWriterV3(
                artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
                bindings=(),
                status="complete",
            ).write(
                artifact,
                [_record("unit:a", complete=True, rich_target=True)],
            )
            output = root / "slice.json"
            payload = project_component_external_sites(
                canonical_external_sites=artifact,
                resolution=_resolution(),
                lift_unit_id="a",
                out=output,
            )
            loaded = load_component_external_site_slice(output)

        self.assertEqual(payload["status"], "checked")
        self.assertEqual(loaded.sites[0].identity["symbol"], "memcmp")
        self.assertNotEqual(
            loaded.sites[0].target_sha256,
            canonical_sha256_v3(loaded.sites[0].identity),
        )


if __name__ == "__main__":
    unittest.main()
