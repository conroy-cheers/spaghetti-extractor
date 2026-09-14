"""Compiled prefix matching checks effects, storage, branches and dependencies."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_entry_conformance import check_compiled_entry_prefix
from tests.unit.components.entry_fact_transport import check_compiled_entry_fact_transport
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError


TESTKIT = {"fixtures": ("cbmc", "compiler"),
           "resources": ("profiles/pe32-kernel32-runtime-v1.json",)}
_PREFIX = """
  goto cut;
  unsigned value = helper(p);
cut:
  __CPROVER_havoc_object(&value);
  if (mode) { state = value; } else { *p = value; }
  __CPROVER_assume(value < 10);
  if (probe) { witness(); __CPROVER_assume(0); }
"""
_FRONTIER = """
  __CPROVER_assert(0, "spx-source-entry:escaped-cut");
  __CPROVER_assume(0);
"""


class EntryConformanceTests(unittest.TestCase):
    def test_prefix_fact_consumption_and_unqualified_uses(self):
        prefix = _PREFIX.replace(" = helper(p)", "").replace(
            "if (probe) { witness(); __CPROVER_assume(0); }", "helper(p);")
        helper = '__CPROVER_assert(state < 10, "admission"); return *p;'
        consumed = helper.replace('return *p;', '__CPROVER_assume(state < 10); return *p;')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def models(*, tail="state = value + 1;", qualifier_helper=helper,
                       consumer_helper=consumed, declarations="unsigned state, probe;", lower=False,
                       prefix_declarations=""):
                actual_prefix = prefix_declarations + prefix
                original = self.compile(root, prefix=actual_prefix, tail=tail, helper=qualifier_helper, declarations=declarations, lower=lower)
                entry = self.compile(root, prefix=actual_prefix, tail=_FRONTIER, helper=qualifier_helper, declarations=declarations, lower=lower)
                consumer = self.compile(root, prefix=actual_prefix, tail=tail, helper=consumer_helper, declarations=declarations, lower=lower)
                return original, entry, consumer

            def check(original, entry, consumer):
                return check_compiled_entry_fact_transport(original_functions=original['functions'],
                    entry_functions=entry['functions'], consumer_functions=consumer['functions'],
                    original_symbols=original['symbols'], entry_symbols=entry['symbols'],
                    consumer_symbols=consumer['symbols'], function='run', fact_function='helper',
                    assertion_description='admission')

            original, entry, consumer = models()
            result = check(original, entry, consumer)
            self.assertEqual(result['status'], 'matched')
            self.assertFalse(result['authorizing'])
            self.assertFalse(result['entry_obligations_checked'])
            self.assertEqual(len(result['calls']), 2)
            grown = models(tail="for (unsigned k=100; k; --k) state += value;")
            self.assertEqual(check(*grown)['guard_sha256'], result['guard_sha256'])
            for operator in ['==', '!=']:
                self.assertEqual(check(*models(qualifier_helper=helper.replace('state <', 'state ' + operator),
                    consumer_helper=consumed.replace('state <', 'state ' + operator)))['status'], 'matched')
            for bad in [helper, consumed.replace('assume(state < 10)', 'assume(state < 9)'),
                        '__CPROVER_assume(state < 10); ' + helper,
                        consumed.replace('return *p;', 'state++; return *p;')]:
                with self.subTest(helper=bad), self.assertRaises(BisimulationRefinementError):
                    check(*models(consumer_helper=bad))
            with self.assertRaisesRegex(BisimulationRefinementError, 'outside the matched prefix'):
                check(*models(tail='helper(p); state = value;'))
            # A pointer use in the discarded suffix would let a callback use the
            # fact in a different context, even though prefix correspondence holds.
            with self.assertRaises(BisimulationRefinementError):
                check(*models(tail='unsigned (*callback)(unsigned *) = helper; state = callback(p);'))
            with self.assertRaisesRegex(BisimulationRefinementError, 'stable scalar'):
                check(*models(qualifier_helper=helper.replace('state <', '*p <'),
                              consumer_helper=consumed.replace('state <', '*p <')))
            with self.assertRaisesRegex(BisimulationRefinementError, 'stable scalar'):
                check(*models(declarations='volatile unsigned state; unsigned probe;'))
            changed = copy.deepcopy(consumer)
            instructions = changed['functions']['helper']['instructions']
            assertion = next(index for index, row in enumerate(instructions) if row['instructionId'] == 'ASSERT')
            instructions[0]['targets'] = [instructions[assertion + 1]['locationNumber']]
            with self.assertRaises(BisimulationRefinementError):
                check(original, entry, changed)
            indirect = models(tail='void (*callback)(void) = witness; callback(); state = value;')
            with self.assertRaisesRegex(BisimulationRefinementError, 'complete compiler function-pointer lowering'):
                check(*indirect)
            # Retain a common indirect helper in every model, so the compiler's
            # lowering support-symbol universe is the same on both sides.
            declarations = ('void witness(void); void invoke(void) { void (*f)(void) = witness; f(); } '
                            'unsigned state, probe;')
            lowered = models(tail='callback(); state = value;', declarations=declarations, lower=True,
                             prefix_declarations='void (*callback)(void) = witness;')
            self.assertTrue(check(*lowered)['direct_call_inventories_checked'])
            with self.assertRaises(BisimulationRefinementError):
                check(*models(tail='unsigned (*callback)(unsigned *) = helper; state = callback(p);', lower=True))

    def compile(self, root, *, prefix=_PREFIX, tail="state = value + 1;", helper="*p += 1; return *p;",
                declarations="unsigned state, probe;", lower=False):
        source = root / "source.c"
        source.write_text("void __CPROVER_assert(_Bool, const char *);\n" + declarations
            + "\nunsigned helper(unsigned *p) {" + helper + "}\n"
            "void witness(void) { __CPROVER_assert(1, \"shared\"); }\n"
            "void run(unsigned *p, unsigned mode) {" + prefix + tail + "}\n"
            "void main(void) { unsigned input; probe = 1; run(&input, input); }\n")
        model = root / "model.goto"
        compiler, instrument = (shutil.which(name) for name in ("goto-cc", "goto-instrument"))
        if compiler is None or instrument is None:
            self.skipTest("CBMC compiler tools unavailable")
        run = subprocess.run([compiler, "--i386-win32", "-I", str(root), str(source), "-o", str(model)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        if lower:
            resolved = root / 'resolved.goto'
            run = subprocess.run([instrument, '--remove-function-pointers', str(model), str(resolved)],
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            model = resolved
        inventory = {}
        for flag, field in [("--show-goto-functions", "functions"), ("--show-symbol-table", "symbolTable")]:
            run = subprocess.run([instrument, flag, "--json-ui", str(model)],
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            inventory[field] = next(row[field] for row in json.loads(run.stdout) if field in row)
        return {"functions": {row["name"]: row for row in inventory["functions"]},
                "symbols": inventory["symbolTable"]}

    def check(self, original, entry):
        return check_compiled_entry_prefix(original_functions=original["functions"],
            entry_functions=entry["functions"], original_symbols=original["symbols"],
            entry_symbols=entry["symbols"], function="run")

    def test_generated_view_owner_survives_nested_cut_extraction(self):
        from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
        from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
        from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
        from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
        from tests.unit.components.test_bisimulation_local_views import authored_view, GLOBALS
        from tests.unit.components.test_bisimulation_lifetime_admission import interface_fixture

        authored, specs, _, _ = authored_view()
        header = _render_proof_header(authored=authored, image_base=4194304,
            unit_rvas={authored.syncs[0].exact_unit_id: 0x1010}, active_start_sync_id="cut",
            active_target_sync_ids=set(), local_havoc={"cut": ["scratch"]}, local_view_specs=specs)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "stddef.h").write_text("typedef unsigned int size_t; typedef int ptrdiff_t;\n#define NULL ((void *)0)\n")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            for name, source in render_component_c_headers_v5(
                    interface_fixture(buffer_view=True), {"run": "authored_run"}).items():
                (root / name).write_text(source)
            declarations = ('#include "state-machine-runtime.h"\n#include "portable-component.h"\n'
                            + header + GLOBALS + "unsigned state, probe;")
            begin = "SPX_PROOF_BEGIN(run); spx_view_v5 scratch;"
            cut = "SPX_PROOF_SYNC(cut,1,scratch);"
            original = self.compile(root, declarations=declarations,
                prefix=begin + "for (;;) {" + cut + "break;}", tail="state = mode;")
            entry = self.compile(root, declarations=declarations, prefix=begin + cut, tail=_FRONTIER)
            result = self.check(original, entry)
            self.assertEqual(result["status"], "matched")
            # A changed owner assignment is a changed prefix, even with a
            # stable declaration and unchanged ordinary C signature.
            changed = declarations.replace(
                "? 0 : spx_proof_local_view_runtime();", "? 0 : (void *)1;")
            self.assertNotEqual(changed, declarations)
            corrupted = self.compile(root, declarations=changed, prefix=begin + cut, tail=_FRONTIER)
            with self.assertRaises(BisimulationRefinementError):
                self.check(original, corrupted)

    def test_compiled_skipped_initializers_and_post_cut_growth(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self.compile(root)
            entry = self.compile(root, prefix=_PREFIX.replace(" = helper(p)", ""), tail=_FRONTIER)
            result = self.check(original, entry)
            self.assertEqual(result["status"], "matched")
            self.assertFalse(result["source_conformance_checked"])
            self.assertFalse(result["entry_obligations_checked"])
            self.assertFalse(result["authorizing"])
            self.assertGreaterEqual(result["relation"]["unknown_branches"], 2)
            self.assertEqual(len(result["frontier_properties"]), 1)
            grown = self.compile(root, tail="for (unsigned k=100; k; --k) state += value;")
            self.check(grown, entry)
            discarded = self.compile(root, prefix="(void)p;" + _PREFIX)
            self.check(discarded, entry)

    def test_memory_effect_havoc_and_assumption_changes_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self.compile(root)
            prefix = _PREFIX.replace(" = helper(p)", "")
            changes = [prefix.replace("*p = value;", ""), prefix.replace("value < 10", "value < 11"),
                       prefix.replace("__CPROVER_havoc_object(&value);", "")]
            for changed in changes:
                with self.subTest(prefix=changed):
                    entry = self.compile(root, prefix=changed, tail=_FRONTIER)
                    with self.assertRaises(BisimulationRefinementError):
                        self.check(original, entry)

    def test_unskipped_initializer_and_silent_divergence_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entry = self.compile(root, prefix=_PREFIX.replace(" = helper(p)", ""), tail=_FRONTIER)
            for prefix in [_PREFIX.replace("goto cut;", "if (mode) goto cut;"),
                           "again: goto again;" + _PREFIX, "(void)*p;" + _PREFIX]:
                with self.subTest(prefix=prefix):
                    original = self.compile(root, prefix=prefix)
                    with self.assertRaises(BisimulationRefinementError):
                        self.check(original, entry)

    def test_helper_and_static_state_are_part_of_the_relation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self.compile(root)
            for options in [{"helper": "*p += 2; return *p;"}, {"declarations": "unsigned state = 7, probe;"}]:
                with self.subTest(options=options):
                    entry = self.compile(root, prefix=_PREFIX.replace(" = helper(p)", ""), tail=_FRONTIER, **options)
                    with self.assertRaises(BisimulationRefinementError):
                        self.check(original, entry)

    def test_frontier_must_be_false_and_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self.compile(root)
            for tail in [_FRONTIER.replace("assert(0,", "assert(1,"),
                         _FRONTIER.replace("__CPROVER_assume(0);", "")]:
                with self.subTest(tail=tail):
                    entry = self.compile(root, prefix=_PREFIX.replace(" = helper(p)", ""), tail=tail)
                    with self.assertRaises(BisimulationRefinementError):
                        self.check(original, entry)

    def test_storage_types_targets_and_unknown_inventory_fields_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self.compile(root)
            entry = self.compile(root, prefix=_PREFIX.replace(" = helper(p)", ""), tail=_FRONTIER)
            changed = copy.deepcopy(entry)
            local = next(row for row in changed["symbols"].values() if row["baseName"] == "value")
            local["type"]["namedSub"]["width"]["id"] = "64"
            with self.assertRaises(BisimulationRefinementError):
                self.check(original, changed)
            for field, value in [("targets", [999999]), ("unrecognizedEffect", True)]:
                changed = copy.deepcopy(entry)
                changed["functions"]["run"]["instructions"][0][field] = value
                with self.assertRaises(BisimulationRefinementError):
                    self.check(original, changed)
            changed = copy.deepcopy(entry)
            assertion = next(row for row in changed["functions"]["witness"]["instructions"]
                             if row["instructionId"] == "ASSERT")
            assertion["sourceLocation"]["pragma"] = "CPROVER check disable pointer-check"
            with self.assertRaises(BisimulationRefinementError):
                self.check(original, changed)
            changed = copy.deepcopy(entry)
            pointer = next(row for row in changed["symbols"].values() if row["baseName"] == "p")
            pointer["type"].setdefault("namedSub", {})["#failed_symbol"] = {"id": "another-object"}
            with self.assertRaises(BisimulationRefinementError):
                self.check(original, changed)
