from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.launch_assumption_inputs_v2 import (
    LAUNCH_ANALYSIS_ASSUMPTIONS_V2_FORMAT,
    LaunchAssumptionInputsV2Error,
    build_launch_analysis_assumptions_v2,
    parse_launch_analysis_assumptions_v2,
)


_PE_SHA256 = "a" * 64
_ASSUMPTIONS = {
    "initial_stack": {"kind": "fresh_pe32_stack"},
    "argv": {"kind": "windows_ansi_argv"},
    "environment": {"kind": "windows_ansi_environment"},
    "fs": {"kind": "pe32_teb"},
    "iat": {"kind": "loader_resolved_iat"},
    "relocations": {"kind": "preferred_or_relocated_image"},
}


def _template() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
        "schema_version": 1,
        "assumptions": copy.deepcopy(_ASSUMPTIONS),
        "feature_inventory": {
            "threads": [],
            "unmodelled_seh": [],
            "direct_syscalls": [],
            "executable_writes": [],
            "unknown_async_callbacks": [],
        },
    }


def _profile(*, callback_identity: str = "callback:one") -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-pe32-launch-profile-v2",
        "schema_version": 2,
        "authority": "conditional_exact_pe32_launch_profile_v2",
        "binary": {
            "pe_sha256": _PE_SHA256,
            "machine": "i386",
            "bitness": 32,
            "image_base": 0x400000,
            "size_of_image": 0x12000,
        },
        "assumptions": [
            {
                "kind": kind,
                "source": "explicit_profile_assumption",
                "value": copy.deepcopy(value),
            }
            for kind, value in _ASSUMPTIONS.items()
        ],
        # Root-specific content is intentionally outside this projection.
        "callback_roots": [{"identity": callback_identity}],
    }


def _build(value: object):
    return build_launch_analysis_assumptions_v2(
        value,
        pe_sha256=_PE_SHA256,
        image_base=0x400000,
        size_of_image=0x12000,
    )


class LaunchAssumptionInputsV2Tests(unittest.TestCase):
    def test_template_projects_exact_root_independent_assumptions(self) -> None:
        result = _build(_template())
        payload = result.to_payload()

        self.assertEqual(payload["format"], LAUNCH_ANALYSIS_ASSUMPTIONS_V2_FORMAT)
        self.assertFalse(payload["proof_authority"])
        self.assertEqual(result.assumption_map, _ASSUMPTIONS)
        self.assertEqual(parse_launch_analysis_assumptions_v2(payload), result)

    def test_callback_only_profile_change_preserves_projection_identity(self) -> None:
        first = _build(_profile(callback_identity="callback:one"))
        second = _build(_profile(callback_identity="callback:two"))

        self.assertEqual(first, second)
        self.assertEqual(first.projection_sha256, second.projection_sha256)

    def test_profile_must_bind_the_exact_structural_image(self) -> None:
        profile = _profile()
        profile["binary"]["pe_sha256"] = "b" * 64  # type: ignore[index]

        with self.assertRaisesRegex(
            LaunchAssumptionInputsV2Error, "different PE32 image"
        ):
            _build(profile)

    def test_assumption_change_invalidates_projection(self) -> None:
        changed = _template()
        changed["assumptions"]["argv"] = {"kind": "different_argv"}  # type: ignore[index]

        self.assertNotEqual(
            _build(_template()).projection_sha256,
            _build(changed).projection_sha256,
        )

    def test_corrupted_projection_fails_closed(self) -> None:
        payload = _build(_template()).to_payload()
        payload["assumptions"]["argv"] = {"kind": "corrupt"}

        with self.assertRaisesRegex(
            LaunchAssumptionInputsV2Error, "projection hash is stale"
        ):
            parse_launch_analysis_assumptions_v2(payload)


if __name__ == "__main__":
    unittest.main()
