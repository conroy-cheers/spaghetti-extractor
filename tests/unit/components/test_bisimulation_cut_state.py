from __future__ import annotations

import shutil
import subprocess
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_cut_state import collect_cut_local_state
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from tests.unit.components.test_bisimulation import _intent


TESTKIT = {"fixtures": ("cbmc", "compiler")}


class SourceCutLocalStateTests(unittest.TestCase):
    def test_projected_invariants_preserve_the_full_unsigned_c_domain(self):
        from dataclasses import replace
        from spaghetti_extractor.components.bisimulation_harness import _incoming_scalar_invariant, _render_source_expression
        from tests.unit.components.test_bisimulation_refinement import _intent as scalar_intent
        cbmc, compiler = (shutil.which(name) for name in ('cbmc', 'goto-cc'))
        if cbmc is None or compiler is None:
            self.skipTest('CBMC tools are unavailable')
        sync = scalar_intent().operations[0].syncs[0]
        n, count = {'op': 'state_input', 'name': 'n'}, {'op': 'parameter', 'name': 'count'}
        constant = lambda value: {'op': 'const', 'width': 32, 'value': value}
        binary = lambda op, left, right: {'op': op, 'args': [left, right]}
        invariants = [binary('ult32', n, count), binary('ule32', n, count)]
        for op in ('add32', 'sub32', 'mul32', 'and32', 'or32', 'xor32'):
            invariants.append(binary('eq', binary(op, n, constant(7 if op == 'mul32' else 0xffffffff)), count))
        invariants += [binary('or_bool', invariants[0], invariants[2]),
                       binary('and_bool', invariants[1], invariants[3]),
                       {'op': 'not', 'args': [invariants[0]]},
                       binary('eq', {'op': 'ite', 'args': [invariants[0], n, count]}, count)]
        assertions = []
        for index, invariant in enumerate(invariants):
            early = _incoming_scalar_invariant(replace(sync, invariant=invariant), unsigned_words=['n', 'count'])
            projected = early[-1].strip().removeprefix('__CPROVER_assume(').removesuffix(');')
            source = _render_source_expression(invariant, memory='input')
            assertions.append(f'__CPROVER_assert(({source}) == ({projected}), "equivalent-{index}");')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            source = root / 'domain.c'
            prefix = '''#include "stdint.h"
struct { uint32_t ecx, edx; } spx_proof_exact_input;
int main(void) {
  __CPROVER_havoc_object(&spx_proof_exact_input);
  uint32_t n = spx_proof_exact_input.edx;
  unsigned long count = spx_proof_exact_input.ecx;
'''
            # Two arbitrary words span the entire identity relation. Assignment
            # avoids duplicating equal multiplication circuits in the SAT model;
            # the PE32 unsigned-long operand also exercises C's rank conversion.
            for wrong in (False, True):
                text = prefix + '\n'.join(assertions)
                if wrong:
                    text += '\n__CPROVER_assert((n < count) == (spx_proof_exact_input.edx <= spx_proof_exact_input.ecx), "wrong-bound");'
                source.write_text(text + '\nreturn 0; }\n')
                model = root / 'domain.goto'
                run = subprocess.run([compiler, '--i386-win32', '-I', str(root), str(source), '-o', str(model)],
                                     text=True, capture_output=True, timeout=30)
                self.assertEqual(run.returncode, 0, run.stderr)
                run = subprocess.run([cbmc, str(model), '--function', 'main', '--json-ui',
                                      '--bounds-check', '--pointer-check', '--signed-overflow-check', '--undefined-shift-check'],
                                     text=True, capture_output=True, timeout=30)
                self.assertEqual(run.returncode, 10 if wrong else 0, run.stdout[-3000:] + run.stderr)
                results = [item for row in json.loads(run.stdout) for item in row.get('result', [])]
                failed = [item['description'] for item in results if item['status'] == 'FAILURE']
                self.assertEqual(failed, ['wrong-bound'] if wrong else [])
                self.assertGreaterEqual(len(results), len(invariants))

    def _inventory(self, body: str, *, omit_limit=False, limit_type="uint32_t", words=False):
        compiler, instrument = (shutil.which(name) for name in ("goto-cc", "goto-instrument"))
        if compiler is None or instrument is None:
            self.skipTest("CBMC compiler tools are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            source = root / "source.c"
            source.write_text('#include "stdint.h"\nuint32_t run(uint32_t *input, ' + limit_type + ' limit) {\n' + body + '\n}\n')
            intent = _intent()
            if omit_limit:
                payload = intent.to_payload()
                sync = payload["operations"][0]["syncs"][0]
                sync["captures"] = [capture for capture in sync["captures"] if capture["id"] != "limit"]
                intent = ComponentBisimulationIntentV1.create(component_id=payload["component_id"], operations=payload["operations"])
            result = collect_cut_local_state(root=root, include_root=root, source_files=[source],
                operations=intent.operations, operation_symbols={"run": "run"},
                operation_parameter_ids={"run": ["limit"]},
                goto_cc=Path(compiler), goto_instrument=Path(instrument), timeout_seconds=30)
            return result.unsigned_words if words else result.havoc

    def test_early_invariant_inventory_uses_actual_unsigned_word_types(self):
        for typ, expected in [('uint32_t', ['limit', 'value']), ('int32_t', ['value']),
                              ('uint64_t', ['value']), ('volatile uint32_t', ['value']),
                              ('uint16_t', ['value'])]:
            with self.subTest(typ=typ):
                result = self._inventory('''
  SPX_PROOF_BEGIN(run);
  uint32_t value = 0;
  int32_t signed_value = 0;
  uint64_t wide_value = 0;
  volatile uint32_t volatile_value = 0;
  SPX_PROOF_SYNC(loop, 1);
  return value;
''', limit_type=typ, words=True)
                self.assertEqual(result, {'run': {'loop': expected}})

    def test_early_invariant_inventory_omits_shadowed_storage(self):
        result = self._inventory('''
  SPX_PROOF_BEGIN(run);
  { static int32_t limit = 0; SPX_PROOF_SYNC(loop, 1); return limit; }
''', words=True)
        self.assertEqual(result, {'run': {'loop': []}})

    def test_omitted_immutable_scalar_is_arbitrary_even_when_its_address_escapes(self) -> None:
        for prefix in ("", "uint32_t *alias = &limit;"):
            with self.subTest(prefix=prefix):
                result = self._inventory(prefix + '''
  SPX_PROOF_BEGIN(run);
  SPX_PROOF_SYNC(loop, 1);
  return 0;
''', omit_limit=True)
                self.assertEqual(result, {"run": {"loop": ["limit"]}})

    def test_omitted_pointer_is_not_a_scalar_argument(self) -> None:
        with self.assertRaisesRegex(BisimulationRefinementError, "only integer arguments"):
            self._inventory('SPX_PROOF_BEGIN(run); SPX_PROOF_SYNC(loop, 1); return 0;',
                            omit_limit=True, limit_type="uint32_t *")

    def test_shadowed_omitted_argument_cannot_escape_havoc(self) -> None:
        with self.assertRaisesRegex(BisimulationRefinementError, "shadowed omitted parameter limit"):
            self._inventory('''
  SPX_PROOF_BEGIN(run);
  { uint32_t limit = 7; SPX_PROOF_SYNC(loop, 1); return limit; }
''', omit_limit=True)

    def test_memory_initializers_are_forgotten_but_fixed_local_aliases_are_preserved(self) -> None:
        result = self._inventory('''
  uint32_t cached = *input, variable = 0, storage = 0, fixed = 7;
  uint32_t *alias = &storage;
  SPX_PROOF_BEGIN(run);
  variable = 1; *alias = 2;
  SPX_PROOF_SYNC(loop, 1);
  return cached + variable + *alias + fixed;
''')
        self.assertEqual(result, {"run": {"loop": ["cached", "storage", "variable"]}})

    def test_nested_block_locals_are_inventoried_in_the_cut_scope(self) -> None:
        result = self._inventory('''
  SPX_PROOF_BEGIN(run);
  if (*input) {
    uint32_t nested = 0;
    nested = 1;
    SPX_PROOF_SYNC(loop, 1);
    return nested;
  }
  return 0;
''')
        self.assertEqual(result, {"run": {"loop": ["nested"]}})

    def test_reassigned_and_address_exposed_parameters_are_not_preserved(self) -> None:
        for change in ("input = &storage;", "uint32_t **alias = &input; *alias = &storage;"):
            with self.subTest(change=change):
                result = self._inventory('''
  uint32_t storage = 0;
  SPX_PROOF_BEGIN(run);
  ''' + change + '''
  SPX_PROOF_SYNC(loop, 1);
  return *input;
''')
                self.assertIn("input", result["run"]["loop"])

    def test_fixed_alias_of_parameter_storage_keeps_its_address(self) -> None:
        result = self._inventory('''
  uint32_t storage = 0;
  uint32_t **alias = &input;
  SPX_PROOF_BEGIN(run);
  *alias = &storage;
  SPX_PROOF_SYNC(loop, 1);
  return *input;
''')
        self.assertEqual(result, {"run": {"loop": ["input", "storage"]}})

    def test_conditional_assignment_is_not_a_fixed_initializer(self) -> None:
        result = self._inventory('''
  uint32_t value;
  if (*input) value = 1;
  SPX_PROOF_BEGIN(run);
  SPX_PROOF_SYNC(loop, 1);
  return value;
''')
        self.assertEqual(result, {"run": {"loop": ["value"]}})

    def test_repeated_prefix_cannot_write_memory_or_bypass_begin(self) -> None:
        for prefix in ("*input = 1;", "if (*input) return 0;"):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(BisimulationRefinementError, "before BEGIN"):
                self._inventory(prefix + '''
  SPX_PROOF_BEGIN(run);
  SPX_PROOF_SYNC(loop, 1);
  return *input;
''')

    def test_shadowing_cannot_redirect_havoc_away_from_an_escaped_outer_object(self) -> None:
        with self.assertRaisesRegex(BisimulationRefinementError, "shadowed mutable local value"):
            self._inventory('''
  uint32_t value = 0;
  uint32_t *alias = &value;
  SPX_PROOF_BEGIN(run);
  {
    uint32_t value = 0;
    *alias = 1;
    SPX_PROOF_SYNC(loop, 1);
    return value + *alias;
  }
''')
