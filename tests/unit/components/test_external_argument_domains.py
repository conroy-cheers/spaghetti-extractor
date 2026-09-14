"""Selected service domains survive evidence binding and execute at both gates."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.external.argument_domains import checked_argument_domain
from spaghetti_extractor.external.machine_import_profiles import load_machine_import_profile_set
from spaghetti_extractor.external.environment_boundaries import lower_machine_import_boundary_v1
from spaghetti_extractor.external.resolved_contract import resolved_import_contract_behavior
from spaghetti_extractor.external.import_sites import bind_import_site
from spaghetti_extractor.external.contracts import parse_checked_external_site_contract, require_profile_match
from spaghetti_extractor.candidate.runtime_argument_domains import argument_domain_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from .test_bisimulation_call_ranges import buffer_binding, check_buffer_program

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "profiles/pe32-user32-resource-text-runtime-v1.json",)}
ROOT = Path(__file__).resolve().parents[3]


def selected_service():
    selected = load_machine_import_profile_set([ROOT/TESTKIT["resources"][0]]).contracts[0]
    boundary = lower_machine_import_boundary_v1(selected, abi_dialect="pe32-i386-ms-v1")
    row = {"identity": {**selected.contract["import"], "ordinal": None}, "boundary": boundary,
        "contract": {"payload": selected.contract, "profile_id": selected.profile_id,
            "profile_sha256": selected.profile_sha256, "entry_key": selected.entry_key,
            "entry_index": selected.entry_index}}
    return selected, resolved_import_contract_behavior(row)


class ExternalArgumentDomainTests(unittest.TestCase):
    def test_domain_validation_rejects_unknown_ambiguous_or_out_of_range_constraints(self):
        valid = [{"argument_index": 3, "minimum": 1, "maximum": 0x7fffffff}]
        self.assertEqual(list(checked_argument_domain(valid, argument_words=4)), valid)
        for value in (None, {}, [*valid, *valid], [{**valid[0], "minimum": True}],
                      [{**valid[0], "minimum": -1}], [{**valid[0], "maximum": 0}],
                      [{**valid[0], "argument_index": 4}], [{**valid[0], "when": "success"}]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                checked_argument_domain(value, argument_words=4)

    def test_selected_profile_and_site_identity_retain_the_domain(self):
        selected, behavior = selected_service()
        checked = bind_import_site(behavior, argument_nodes=[])
        self.assertEqual(checked.argument_domain, behavior.argument_domain)
        self.assertEqual(checked.identity_sha256(), behavior.identity_sha256())
        self.assertEqual(parse_checked_external_site_contract(checked.payload()), checked)
        keywords = {"profile_contract": selected.contract, "profile_id": selected.profile_id,
            "profile_sha256": selected.profile_sha256, "entry_key": selected.entry_key,
            "entry_index": selected.entry_index, "context": "selected LoadStringA"}
        require_profile_match(checked, **keywords)
        omitted = checked.payload(); omitted.pop("argument_domain")
        erased = parse_checked_external_site_contract(omitted)
        self.assertNotEqual(erased.identity_sha256(), checked.identity_sha256())
        with self.assertRaisesRegex(ValueError, "argument_domain"):
            require_profile_match(erased, **keywords)

    def test_real_positive_buffer_domain_is_checked_before_oracle_effects(self):
        selected, _ = selected_service()
        binding = buffer_binding()
        binding["external_effect_contract"] = dict(selected.contract)
        for size, status in ((500, "satisfied"), (0, "violated"), (0xffffffff, "violated")):
            result = check_buffer_program(f"original(0x413d20U, {size}U);", binding=binding)
            self.assertEqual(result["status"], status, result)
            if status == "violated": self.assertIn("call-argument-domain", result["detail"])
        # Domains also constrain services without memory effects.
        scalar = copy.deepcopy(binding)
        scalar["external_effect_contract"].update(memory_effect="none", memory_footprints=[])
        result = check_buffer_program("original(0x413d20U, 0U);", binding=scalar)
        self.assertEqual(result["status"], "violated", result)

    def test_native_bridge_domain_checks_stack_transport_and_faults(self):
        _, behavior = selected_service()
        sites = [SimpleNamespace(checked_external_contract=bind_import_site(behavior,
            argument_nodes=[], tail_jump=tail)) for tail in (False, True)]
        generated = argument_domain_source(sites)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_cbmc_stdint(root/'stdint.h')
            source = root/'domains.c'
            source.write_text('''#include <stdint.h>
void __CPROVER_assert(_Bool, const char *);
typedef struct { uint32_t esp; } spx_machine_state;
typedef struct { void *context; uint32_t (*read)(void *,uint32_t,uint32_t,uint32_t *); } spx_runtime;
typedef struct { uint32_t index; } spx_native_bridge_entry;
static spx_native_bridge_entry spx_native_bridges[2];
static uint32_t word, read_fault, expected_address;
static uint32_t read_word(void *context, uint32_t address, uint32_t width, uint32_t *fault) {
  (void)context;
  __CPROVER_assert(address == expected_address && width == 4U, "exact native argument transport");
  *fault = read_fault; return word;
}
''' + generated + '''
int main(void) {
  uint32_t arbitrary_word, arbitrary_esp, arbitrary_fault, arbitrary_tail;
  word = arbitrary_word; read_fault = arbitrary_fault;
  uint32_t tail = arbitrary_tail & 1U, offset = tail ? 16U : 12U;
  spx_machine_state input = {arbitrary_esp};
  spx_runtime runtime = {0, read_word};
  expected_address = input.esp + offset;
  uint32_t admitted = spx_native_arguments_admitted(&runtime, &spx_native_bridges[tail], &input);
  __CPROVER_assert(admitted == (input.esp <= UINT32_MAX - offset - 3U && read_fault == 0U &&
      word >= 1U && word <= 2147483647U), "native domain and readable frame required");
}
''')
            result = run_cbmc_properties(command=[shutil.which("cbmc"), str(source), "--json-ui",
                "--trace", "--unwind", "4", "--unwinding-assertions", "--bounds-check",
                "--pointer-check", "--signed-overflow-check", "--sat-solver", "cadical"], timeout_seconds=30)
            self.assertEqual(result["status"], "satisfied", result)
            for compiler in ("cc", "i686-w64-mingw32-gcc"):
                compiled = subprocess.run([shutil.which(compiler), "-c", str(source), "-o", str(root/'domains.o')],
                    text=True, capture_output=True, timeout=30)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)


if __name__ == "__main__":
    unittest.main()
