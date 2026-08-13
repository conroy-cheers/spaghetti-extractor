from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.external_site_proposals_v2 import (
    ExternalSiteProposalsV2Error,
    build_external_site_proposals_v2,
    derive_external_site_proposals_v2,
    parse_external_site_proposals_v2,
)
from spaghetti_extractor.external_profile_authority_v2 import (
    build_external_profile_authority_v2,
)
from spaghetti_extractor.authority_bindings_v2 import canonical_json_bytes
from tests.test_checked_external_site_contract import (
    _checked,
    _profile_entry,
    _write_profile,
)


class ExternalSiteProposalsV2Tests(unittest.TestCase):
    def test_exact_bound_proposal_replays(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            _write_profile(profile)
            site = {
                "unit_id": "unit:entry",
                "event_index": 0,
                "target_alternative_index": 0,
                "target_alternative_sha256": "c" * 64,
                "contract": _checked(profile).payload(),
            }

            result = build_external_site_proposals_v2(
                checked_sites=[site],
                pe_sha256="a" * 64,
                machine_ir_sha256="b" * 64,
            )

            self.assertEqual(result["status"], "complete")
            self.assertEqual(
                parse_external_site_proposals_v2(
                    result,
                    pe_sha256="a" * 64,
                    machine_ir_sha256="b" * 64,
                ),
                (site,),
            )

    def test_stale_binary_binding_is_rejected(self) -> None:
        result = build_external_site_proposals_v2(
            checked_sites=[],
            pe_sha256="a" * 64,
            machine_ir_sha256="b" * 64,
        )

        with self.assertRaisesRegex(
            ExternalSiteProposalsV2Error, "different binary"
        ):
            parse_external_site_proposals_v2(
                result,
                pe_sha256="c" * 64,
                machine_ir_sha256="b" * 64,
            )

    def test_corrupted_site_is_violated(self) -> None:
        result = build_external_site_proposals_v2(
            checked_sites=[{"unit_id": "unit", "event_index": 0, "contract": {}}],
            pe_sha256="a" * 64,
            machine_ir_sha256="b" * 64,
        )

        self.assertEqual(result["status"], "violated")
        corrupted = copy.deepcopy(result)
        corrupted["issues"] = []
        with self.assertRaisesRegex(ExternalSiteProposalsV2Error, "hash"):
            parse_external_site_proposals_v2(
                corrupted,
                pe_sha256="a" * 64,
                machine_ir_sha256="b" * 64,
            )

    def test_finite_indirect_targets_emit_one_site_per_alternative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            entries = []
            for symbol in ("First", "Second"):
                entry = _profile_entry()
                entry["id"] = f"fixture.dll!{symbol}"
                entry["import"] = {"dll": "fixture.dll", "symbol": symbol}
                entries.append(entry)
            profile.write_text(json.dumps({
                "format": "stage-a-static-machine-import-profile-v1",
                "id": "fixture-profile",
                "machine_import_signatures": entries,
            }, sort_keys=True), encoding="utf-8")
            profile_sha256 = hashlib.sha256(profile.read_bytes()).hexdigest()
            authority = build_external_profile_authority_v2([profile])
            target_rows = [
                {
                    "import": {"dll": "fixture.dll", "symbol": symbol},
                    "profile_binding": {
                        "profile_id": "fixture-profile",
                        "profile_sha256": profile_sha256,
                        "entry_key": "machine_import_signatures",
                        "entry_index": index,
                    },
                    "abi": {"template": "pe32-stdcall-v1"},
                    "argument_words": 2,
                }
                for index, symbol in enumerate(("First", "Second"))
            ]
            machine_row = {
                "id": "unit:dispatch",
                "semantics": {"external_events": [{
                    "kind": "indirect_call",
                    "register_inputs": {
                        "esp": {"op": "reg", "name": "esp", "width": 32}
                    },
                }]},
            }
            interprocedural = {"recovered_targets": [{
                "source_unit_id": "unit:dispatch",
                "source_event_index": 0,
                "status": "recovered",
                "external_targets": list(reversed(target_rows)),
            }]}

            result = derive_external_site_proposals_v2(
                machine_ir_rows=[machine_row],
                interprocedural=interprocedural,
                profile_authority=authority,
                pe_sha256="a" * 64,
                machine_ir_sha256="b" * 64,
                reachable_unit_ids=["unit:dispatch"],
            )

            expected_targets = sorted(
                target_rows,
                key=lambda row: hashlib.sha256(
                    canonical_json_bytes(row)
                ).hexdigest(),
            )
            self.assertEqual(result["status"], "complete", result["issues"])
            self.assertEqual(
                [row["target_alternative_index"] for row in result["sites"]],
                [0, 1],
            )
            self.assertEqual(
                [row["target_alternative_sha256"] for row in result["sites"]],
                [
                    hashlib.sha256(canonical_json_bytes(row)).hexdigest()
                    for row in expected_targets
                ],
            )

    def test_resolved_terminating_profile_does_not_require_embedded_abi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            entry = _profile_entry()
            entry["id"] = "fixture.dll!Stop"
            entry["import"] = {"dll": "fixture.dll", "symbol": "Stop"}
            entry["disposition"] = "terminates"
            profile.write_text(json.dumps({
                "format": "stage-a-static-machine-import-profile-v1",
                "id": "terminating-profile",
                "machine_import_signatures": [entry],
            }, sort_keys=True), encoding="utf-8")
            authority = build_external_profile_authority_v2([profile])
            machine_row = {
                "id": "unit:stop",
                "semantics": {"external_events": [{
                    "kind": "external_call",
                    "dll": "fixture.dll",
                    "symbol": "Stop",
                    "register_inputs": {
                        "esp": {"op": "reg", "name": "esp", "width": 32}
                    },
                }]},
            }

            result = derive_external_site_proposals_v2(
                machine_ir_rows=[machine_row],
                interprocedural={"recovered_targets": []},
                profile_authority=authority,
                pe_sha256="a" * 64,
                machine_ir_sha256="b" * 64,
                reachable_unit_ids=["unit:stop"],
            )

            self.assertEqual(result["status"], "complete", result["issues"])
            self.assertEqual(
                result["sites"][0]["contract"]["profile_disposition"],
                "terminates",
            )

    def test_omitted_profile_disposition_defaults_to_returning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            entry = _profile_entry()
            entry.pop("disposition")
            _write_profile(profile, entry)
            authority = build_external_profile_authority_v2([profile])
            machine_row = {
                "id": "unit:call",
                "semantics": {"external_events": [{
                    "kind": "external_call",
                    "dll": "fixture.dll",
                    "symbol": "Exact",
                    "register_inputs": {
                        "esp": {"op": "reg", "name": "esp", "width": 32}
                    },
                }]},
            }

            result = derive_external_site_proposals_v2(
                machine_ir_rows=[machine_row],
                interprocedural={"recovered_targets": []},
                profile_authority=authority,
                pe_sha256="a" * 64,
                machine_ir_sha256="b" * 64,
                reachable_unit_ids=["unit:call"],
            )

            self.assertEqual(result["status"], "complete", result["issues"])
            self.assertEqual(
                result["sites"][0]["contract"]["profile_disposition"],
                "returns",
            )


if __name__ == "__main__":
    unittest.main()
