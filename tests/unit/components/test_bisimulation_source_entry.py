"""Independent entry storage keeps types, aliases and unsupported prefixes visible."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_cut_state import collect_cut_local_state
from spaghetti_extractor.components.bisimulation_source_entry import check_compiled_entry_types
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from tests.unit.components.test_bisimulation import _intent


TESTKIT = {"fixtures": ("cbmc", "compiler")}


class SourceEntryTests(unittest.TestCase):
    def candidate(self, body, *, declarations="", changed_header=None):
        compiler, instrument = (shutil.which(name) for name in ("goto-cc", "goto-instrument"))
        if compiler is None or instrument is None:
            self.skipTest("CBMC compiler tools are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            header = root / "portable-component-implementation.h"
            header.write_text('#include "stdint.h"\n' + declarations)
            source = root / "source.c"
            source.write_text('#include "portable-component-implementation.h"\n'
                'uint32_t run(uint32_t *input, uint32_t limit) {\n' + body + '\n}\n')
            state = collect_cut_local_state(root=root, source_files=[source], include_root=root,
                operations=_intent().operations, operation_parameter_ids={"run": ["limit"]},
                operation_symbols={"run": "run"}, goto_cc=Path(compiler),
                goto_instrument=Path(instrument), timeout_seconds=30, prepare_entries=True)
            entry = state.entries["run"]["loop"]
            if entry["status"] != "prepared":
                return entry, None
            self.assertEqual(entry["binding"]["havoc"], state.havoc["run"]["loop"])
            if changed_header is not None:
                header.write_text('#include "stdint.h"\n' + changed_header)
            # The round trip is a compiler/type gate, not an entry proof. Use
            # inert markers here; semantic marker conformance is a separate gate.
            generated = root / "entry.c"
            generated.write_text('#define SPX_PROOF_BEGIN(...) ((void)0)\n'
                '#define SPX_PROOF_SYNC(...) ((void)0)\n' + entry["source"])
            model = root / "entry.goto"
            run = subprocess.run([compiler, "--i386-win32", "-I", str(root), str(generated), "-o", str(model)],
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            run = subprocess.run([instrument, "--show-symbol-table", "--json-ui", str(model)],
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            symbols = next(row["symbolTable"] for row in json.loads(run.stdout) if "symbolTable" in row)
            return entry, symbols

    def test_post_cut_logic_does_not_enter_the_storage_binding(self):
        prefix = 'SPX_PROOF_BEGIN(run); uint32_t value=0; SPX_PROOF_SYNC(loop,1,limit,value);'
        baseline, symbols = self.candidate(prefix + 'return value;')
        edited, _ = self.candidate(prefix + 'for(uint32_t k=100;k;--k) value+=k; return value;')
        self.assertEqual(baseline, edited)
        self.assertNotIn('for(', baseline['source'])
        check_compiled_entry_types(baseline, symbols)

    def test_prefix_constants_and_aliases_are_not_silently_discarded(self):
        for prefix in ['uint32_t value=7;', 'uint32_t value=0; uint32_t *alias=&value;',
                       'uint32_t value=*input;']:
            with self.subTest(prefix=prefix):
                entry, _ = self.candidate(prefix + 'SPX_PROOF_BEGIN(run); SPX_PROOF_SYNC(loop,1,limit,value); return value;')
                self.assertEqual(entry['status'], 'unsupported')
                self.assertIn('before BEGIN', entry['detail'])

    def test_discarded_parameter_is_erased_but_dereference_is_not(self):
        body = 'SPX_PROOF_BEGIN(run); uint32_t value=0; SPX_PROOF_SYNC(loop,1,limit,value); return value;'
        baseline, _ = self.candidate(body)
        discarded, symbols = self.candidate('(void)input;' + body)
        self.assertEqual(baseline, discarded)
        check_compiled_entry_types(discarded, symbols)
        for prefix in ['(void)*input;', '(void)(limit+1U);']:
            entry, _ = self.candidate(prefix + body)
            self.assertEqual(entry['status'], 'unsupported')

    def test_parameter_escape_changes_the_havoc_dependency(self):
        prefix = 'SPX_PROOF_BEGIN(run); uint32_t value=0; SPX_PROOF_SYNC(loop,1,limit,value);'
        baseline, _ = self.candidate(prefix + 'return value;')
        escaped, symbols = self.candidate(prefix + 'uint32_t **alias=&input; return **alias;')
        self.assertNotIn('input', baseline['binding']['havoc'])
        self.assertIn('input', escaped['binding']['havoc'])
        self.assertNotEqual(baseline['binding_sha256'], escaped['binding_sha256'])
        check_compiled_entry_types(escaped, symbols)

    def test_roundtrip_checks_recursive_records_and_layout_changes(self):
        declaration = 'typedef struct Box { uint32_t word; struct Box *next; } Box;'
        body = 'SPX_PROOF_BEGIN(run); uint32_t value=0; Box box; SPX_PROOF_SYNC(loop,1,limit,value); return value;'
        baseline, symbols = self.candidate(body, declarations=declaration)
        check_compiled_entry_types(baseline, symbols)
        for changed in [declaration.replace('uint32_t word', 'uint64_t word'),
                        declaration.replace('uint32_t word; struct Box *next;', 'struct Box *next; uint32_t word;')]:
            entry, changed_symbols = self.candidate(body, declarations=declaration, changed_header=changed)
            with self.assertRaisesRegex(BisimulationRefinementError, 'type or layout changed'):
                check_compiled_entry_types(entry, changed_symbols)

    def test_mutated_generated_source_is_not_a_checked_roundtrip(self):
        entry, symbols = self.candidate('SPX_PROOF_BEGIN(run); uint32_t value=0; SPX_PROOF_SYNC(loop,1,limit,value); return value;')
        changed = copy.deepcopy(entry)
        changed['source'] = changed['source'].replace('uint32_t value;', 'uint64_t value;')
        with self.assertRaisesRegex(BisimulationRefinementError, 'preparation binding differs'):
            check_compiled_entry_types(changed, symbols)
