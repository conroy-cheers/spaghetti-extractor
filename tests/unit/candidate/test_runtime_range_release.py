"""Whole-range release preserves lifetimes on failure and rejects partial calls."""

import json
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.module_runtime_plan import NativeExternalSite, normalized_external_site_inventory_v2
from spaghetti_extractor.candidate.runtime_external_range_validation import _external_range_rules
from spaghetti_extractor.candidate.runtime_canonical_common import _checked_contract
from spaghetti_extractor.candidate.runtime_canonical_errors import CanonicalRuntimeError
from spaghetti_extractor.candidate.runtime_range_release import release_tables, range_release_source
from spaghetti_extractor.candidate.runtime_render_core import _native_runtime_source_core
from spaghetti_extractor.external.contracts import (
    CheckedExternalSiteContractError, parse_checked_external_site_contract,
    require_profile_match,
)
from spaghetti_extractor.external.range_release import (
    RangeRelease, RangeReleaseError, machine_range_release, parse_range_release,
)
from spaghetti_extractor.external.machine_import_profiles import (
    MachineImportProfileError, load_machine_import_profile_set,
)
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from .test_runtime_allocation_lifetime import allocation_fixture_source, _function
from .test_runtime_canonical import _external_range_rule

TESTKIT = {
    "fixtures": ("cbmc", "compiler"),
    "resources": (
        "profiles/pe32-kernel32-runtime-v1.json",
        "profiles/pe32-kernel32-lockstep-v1.json",
        "profiles/pe32-msvcrt-lockstep-v1.json",
    ),
}
ROOT = Path(__file__).resolve().parents[3]


def release_profile(success="eax_nonzero", guards=()):
    return {
        "id": "fixture:release", "import": {"dll": "fixture.dll", "symbol": "release"},
        "abi_template": "pe32-stdcall-v1", "arity": {"kind": "fixed", "words": 3},
        "memory_effect": "none", "world_effect": "dynamicRangeRelease",
        "world_effect_argument": 0, "callback_effect": "none",
        "world_effect_release": RangeRelease(success, tuple(guards)).payload(),
    }


def checked(profile):
    return _checked_contract(row={
        "identity": {"dll": "fixture.dll", "symbol": "release", "ordinal": None},
        "boundary": {}, "contract": {"payload": profile, "profile_id": "fixture",
            "profile_sha256": "a" * 64, "entry_key": "contracts", "entry_index": 0},
    }, call=SimpleNamespace(argument_nodes=(), instruction_rva=0x1234), escape_index={})


def release_fixture(body, *, success="eax_nonzero", guards=(), mutant=None):
    rule = replace(_external_range_rule("fixture:release"), action="release_argument_range",
                   target_iat_rva=None, argument_count=3, argument=0,
                   release=RangeRelease(success, tuple(guards)))
    fields, table = release_tables((rule,))
    code, start, count = fields[0]
    prelude = '''
typedef struct {
  uint32_t instruction_rva, target_iat_rva, target_catalog_index;
  uint32_t argument_base_offset, argument_count, argument, action;
  uint32_t release_success, release_guard_start, release_guard_count;
  uint32_t ownership_family, ownership_owner_argument;
} spx_native_external_range_rule;
static const uint32_t spx_native_external_range_rule_count = 1U;
static const uint32_t spx_native_ownership_family_count = 0U;
static spx_native_external_range_rule spx_native_external_range_rules[] = {
''' + f'  {{ 4660U, 0U, 0U, 0U, 3U, 0U, 2U, {code}U, {start}U, {count}U }}' + '''
};
static uint32_t spx_native_external_range_rule_matches(
    const spx_native_external_range_rule *rule, const spx_call_event *event) {
  __CPROVER_assert(event->kind != SPX_CALL_INDIRECT, "fixture is a direct import");
  return rule->instruction_rva == event->instruction_rva;
}
'''
    core = _native_runtime_source_core(SimpleNamespace(ingress_descriptors=()))
    source = range_release_source()
    if mutant == "success":
        source = source.replace('if ((rule->release_success == 2U && output->eax != 0U) ||\n      (rule->release_success == 3U && output->eax == 0U))', 'if (0)')
    if mutant == "guard":
        source = source.replace('if (observed != guard->value)', 'if (0)')
    source += '''
static spx_call_status spx_native_add_external_range_for_rule(
    const spx_native_external_range_rule *rule, uint32_t start, uint32_t size) {
  __CPROVER_assert(0, "release fixture cannot allocate through an external call");
  return SPX_CALL_UNIMPLEMENTED;
}
'''
    setup = '''
static spx_call_event event;
static spx_external_call_snapshot snapshot;
static spx_machine_state output;
static void setup(void) {
  event.instruction_rva = 4660U;
  snapshot.instruction_rva = 4660U; snapshot.argument_count = 3U;
  snapshot.arguments[0] = 4096U; snapshot.arguments[1] = 0U;
  snapshot.arguments[2] = 32768U;
  __CPROVER_assert(allocate(4096U) == SPX_CALL_OK, "allocate input");
  __CPROVER_assert(allocate(8192U) == SPX_CALL_OK, "allocate unrelated input");
}
static spx_call_status apply(void) {
  return spx_native_apply_range_release(&spx_native_external_range_rules[0],
                                       &event, &snapshot, &output);
}
'''
    return allocation_fixture_source(prelude + table + source +
        _function(core, "spx_native_external_argument") + setup + body)


class RangeReleaseContractTests(unittest.TestCase):
    def test_active_converter_and_checked_codec_preserve_release_conditions(self):
        profile = release_profile(guards=((2, 32768), (1, 0)))
        contract = checked(profile)
        expected = RangeRelease("eax_nonzero", ((1, 0), (2, 32768)))
        self.assertEqual(contract.world_effect_release, expected)
        payload = contract.payload()
        parsed = parse_checked_external_site_contract(payload)
        self.assertEqual(parsed.world_effect_release, expected)
        self.assertEqual(parsed.profile_effect_payload()["world_effect_release"], expected.payload())
        require_profile_match(parsed, profile_contract=profile,
            profile_id="fixture", profile_sha256="a" * 64, entry_key="contracts",
            entry_index=0, context="test release binding")
        mutated = replace(parsed, world_effect_release=RangeRelease("always", ()))
        with self.assertRaises(CheckedExternalSiteContractError):
            require_profile_match(mutated, profile_contract=profile,
                profile_id="fixture", profile_sha256="a" * 64, entry_key="contracts",
                entry_index=0, context="test release binding")
        for bad in (None, {}, {"success": "always"},
                    {"success": [], "argument_equals": []},
                    {"success": "eax_nonzero", "argument_equals": [{"argument_index": 3, "value": 0}]},
                    {"success": "always", "argument_equals": [], "ignored": True}):
            with self.subTest(bad=bad):
                value = {**profile, "world_effect_release": bad}
                with self.assertRaises(CanonicalRuntimeError): checked(value)
                with self.assertRaises(CheckedExternalSiteContractError):
                    parse_checked_external_site_contract({**payload, "world_effect_release": bad})
        with self.assertRaises(RangeReleaseError):
            machine_range_release({**profile, "world_effect": "none"}, argument_words=3, context="test")

    def test_native_inventory_lowers_the_checked_release_condition(self):
        contract = checked(release_profile(guards=((1, 0), (2, 32768))))
        site = NativeExternalSite(
            id=0, transfer_id="semantic-transfer:fixture", event_index=0,
            instruction_rva=0x1234, return_rva=0x1239,
            source_instruction_sha256="b" * 64, site_kind="direct_import",
            dll="fixture.dll", symbol="release", ordinal=None,
            disposition="returns_here", iat_rva=0x3000, transfer_sha256="c" * 64,
            abi_metadata_sha256=canonical_sha256_v3(contract.profile_effect_payload()),
            checked_external_contract=contract,
            target_resolution_evidence={"kind": "resolved-external-environment-v1", "sha256": "d" * 64, "identity": ["fixture.dll", "symbol", "release"]},
        )
        catalog, domains, callbacks, sites, _ = normalized_external_site_inventory_v2((site,))
        plan = {"external_target_contracts": catalog, "external_contract_domains": domains,
                "callback_target_domains": callbacks, "external_sites": sites,
                "import_bindings": [{"dll": "fixture.dll", "symbol": "release", "ordinal": None,
                                     "iat_va": 0x403000, "iat_rva": 0x3000}],
                "implementation_dispatch_receipt": {"reachability": {"status": "complete"}}}
        rules, authorized, blocked = _external_range_rules(plan, None,
                                                         resolved_environment_sha256="d" * 64)
        self.assertEqual(blocked, ())
        self.assertEqual(authorized, (0x1234,))
        release = next(rule for rule in rules if rule.action == "release_argument_range")
        self.assertEqual(release.release, contract.world_effect_release)
        self.assertEqual(release.payload()["release"], contract.world_effect_release.payload())
        fields, declaration = release_tables(rules)
        self.assertEqual(fields[rules.index(release)], (3, 0, 2))
        self.assertIn("{ 2U, 32768U }", declaration)

    def test_guard_parser_rejects_ambiguous_or_non_word_constraints(self):
        for guards in ([{"argument_index": True, "value": 0}],
                       [{"argument_index": 0, "value": -1}],
                       [{"argument_index": 0, "value": 2**32}],
                       [{"argument_index": 0, "value": False}],
                       [{"argument_index": 0, "value": 0}] * 2):
            with self.subTest(guards=guards), self.assertRaises(RangeReleaseError):
                parse_range_release({"success": "always", "argument_equals": guards},
                                    argument_words=3, context="test")

    def test_repository_release_profiles_have_explicit_outcomes(self):
        seen = {}
        for name in ("pe32-kernel32-runtime-v1.json", "pe32-kernel32-lockstep-v1.json", "pe32-msvcrt-lockstep-v1.json"):
            profile_set = load_machine_import_profile_set([ROOT / "profiles" / name])
            for identity, contract in profile_set.by_identity().items():
                payload = contract.contract
                if payload.get("world_effect") == "dynamicRangeRelease":
                    seen[identity.value] = machine_range_release(payload,
                        argument_words=payload["argument_words"], context=name)
        self.assertEqual(set(seen), {"VirtualFree", "HeapFree", "FreeEnvironmentStringsA",
                                    "FreeEnvironmentStringsW", "UnmapViewOfFile", "free", "GlobalFree"})
        self.assertEqual(seen["VirtualFree"].argument_equals, ((1, 0), (2, 32768)))
        self.assertEqual(seen["free"].success, "always")
        self.assertTrue(all(rule.success == "eax_nonzero" for name,rule in seen.items() if name not in {"free", "GlobalFree"}))
        self.assertEqual(seen["GlobalFree"].success, "eax_zero")

    def test_profile_loader_rejects_missing_release_conditions(self):
        source = json.loads((ROOT / "profiles/pe32-msvcrt-lockstep-v1.json").read_text())
        source["machine_import_call_contracts"][0].pop("world_effect_release")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps(source))
            with self.assertRaisesRegex(MachineImportProfileError, "explicit release success"):
                load_machine_import_profile_set([path])


class RangeReleaseExecutionTests(unittest.TestCase):
    def check(self, body, **kwargs):
        cbmc = shutil.which("cbmc")
        if cbmc is None: self.skipTest("CBMC unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            path = root / "release.c"
            path.write_text(release_fixture(body, **kwargs))
            result = run_cbmc_properties(command=[cbmc, str(path), "--json-ui", "--trace",
                "--unwind", "6", "--unwinding-assertions", "--bounds-check", "--pointer-check",
                "--signed-overflow-check", "--sat-solver", "cadical"], timeout_seconds=30)
        return result

    def test_symbolic_result_controls_release_and_preserves_unrelated_lifetime(self):
        body = '''
extern uint32_t nondet_u32(void);
int main(void) {
  setup(); uint32_t address;
  spx_machine_reference_v1 old = borrow(4100U), other = borrow(8196U);
  output.eax = nondet_u32();
  __CPROVER_assert(apply() == SPX_CALL_OK, "admitted result");
  __CPROVER_assert(realize(old, &address) == EXPECTED, "release only on API success");
  __CPROVER_assert(realize(other, &address) == SPX_BOUNDARY_OK, "unrelated lifetime preserved");
}
'''
        for success, expected in (("eax_nonzero", '(output.eax ? SPX_BOUNDARY_EXPIRED : SPX_BOUNDARY_OK)'),
                                  ("eax_zero", '(output.eax ? SPX_BOUNDARY_OK : SPX_BOUNDARY_EXPIRED)'),
                                  ("always", 'SPX_BOUNDARY_EXPIRED')):
            with self.subTest(success=success):
                result = self.check(body.replace('EXPECTED', expected), success=success)
                self.assertEqual(result['status'], 'satisfied', result)
        result = self.check(body.replace('EXPECTED', '(output.eax ? SPX_BOUNDARY_EXPIRED : SPX_BOUNDARY_OK)'), mutant="success")
        self.assertEqual(result['status'], 'violated', result)

    def test_partial_release_is_rejected_at_capture_and_cannot_invalidate_range(self):
        body = '''
extern uint32_t nondet_u32(void);
int main(void) {
  setup(); uint32_t address;
  spx_machine_reference_v1 old = borrow(4100U);
  snapshot.arguments[1] = nondet_u32(); snapshot.arguments[2] = nondet_u32();
  uint32_t whole = snapshot.arguments[1] == 0U && snapshot.arguments[2] == 32768U;
  spx_call_status status = spx_native_validate_release_calls(&event, &snapshot);
  __CPROVER_assert(status == (whole ? SPX_CALL_OK : SPX_CALL_UNIMPLEMENTED), "only whole release reaches host call");
  output.eax = 1U;
  __CPROVER_assert(apply() == (whole ? SPX_CALL_OK : SPX_CALL_UNIMPLEMENTED), "record result repeats guard");
  __CPROVER_assert(realize(old, &address) == (whole ? SPX_BOUNDARY_EXPIRED : SPX_BOUNDARY_OK), "unsupported call cannot erase lifetime");
  if (!whole) __CPROVER_assert(spx_native_diagnostic_reason == 0x2206U, "actionable unsupported release diagnostic");
}
'''
        result = self.check(body, guards=((1, 0), (2, 32768)))
        self.assertEqual(result['status'], 'satisfied', result)
        result = self.check(body, guards=((1, 0), (2, 32768)), mutant="guard")
        self.assertEqual(result['status'], 'violated', result)

    def test_corrupt_rule_and_mismatched_argument_snapshot_fail_closed(self):
        body = '''
int main(void) {
  setup(); uint32_t address;
  spx_machine_reference_v1 old = borrow(4100U);
  output.eax = 1U;
  spx_native_external_range_rules[0].release_success = 0U;
  __CPROVER_assert(apply() == SPX_CALL_UNIMPLEMENTED, "missing condition rejected");
  spx_native_external_range_rules[0].release_success = 3U;
  spx_native_external_range_rules[0].release_guard_start = 0xffffffffU;
  __CPROVER_assert(apply() == SPX_CALL_UNIMPLEMENTED, "invalid guard table offset rejected");
  spx_native_external_range_rules[0].release_guard_start = 0U;
  snapshot.argument_count = 2U;
  __CPROVER_assert(apply() == SPX_CALL_UNIMPLEMENTED, "snapshot disagreement rejected");
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_OK, "rejection preserves lifetime");
}
'''
        result = self.check(body, guards=((1, 0), (2, 32768)))
        self.assertEqual(result['status'], 'satisfied', result)
