"""Portable assembly bindings are independent of comparison entry generation."""
from pathlib import Path
import tempfile
import unittest

from spaghetti_extractor.candidate.source_assembly import assembly_binding, retain_assembly_binding, write_assembly_binding, definition_span, check_native_entries, assembly_delta
from spaghetti_extractor.candidate.source_replacements import reconcile_definitions

TESTKIT = {'fixtures': ()}


class AssemblyTests(unittest.TestCase):
    def test_all_declared_entries_need_one_provider_even_when_uncalled(self):
        with self.assertRaisesRegex(ValueError,'missing'):
            check_native_entries({'parser':['create','destroy']},['create'])
        with self.assertRaisesRegex(ValueError,'multiple components'):
            check_native_entries({'left':'create','right':['create']},['create'])
        self.assertEqual(check_native_entries({'parser':['create','destroy']},['create','destroy']),
                         {'create':'parser','destroy':'parser'})

    def test_grouped_adapters_reopen_from_the_delivered_project(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'adapter.c').write_text('/* operator entries */\n')
            value=dict(entries={'new_parser':['create'], 'drop_parser':['destroy']},
                sources={'entry.c':'adapter.c'}, headers={},
                replacements=[dict(file='src/parser.c',symbol='new_parser'),dict(file='src/parser.c',symbol='drop_parser')],
                lifetime='Parser instance persists from create through destroy.')
            spec=assembly_binding(value,base=root,operations={'create':'lifted_create','destroy':'lifted_destroy'})
            self.assertEqual(write_assembly_binding(spec,root/'project/bindings/parser'),['entry.c'])
            retained=retain_assembly_binding(spec,'bindings/parser')
            (root/'adapter.c').unlink()
            reopened=assembly_binding(retained,base=root/'project',operations={'create','destroy'})
            self.assertEqual(reopened['sources']['entry.c'].read_text(),'/* operator entries */\n')
            retained['entries']['new_parser']=['missing']
            with self.assertRaisesRegex(ValueError,'absent'):
                assembly_binding(retained,base=root/'project',operations={'create','destroy'})

    def test_backend_pointer_return_and_braces_in_literals(self):
        text='struct parser *new_parser(int mode) { const char *s="}"; /* { */ return allocate(mode, s); }\nint kept(void) { return 2; }\n'
        begin,end=definition_span(text,'new_parser')
        self.assertEqual(text[end:].strip(),'int kept(void) { return 2; }')
        self.assertEqual(begin,0)
        with self.assertRaisesRegex(ValueError,'expected one'):
            definition_span(text+text,'new_parser')

    def test_entry_refinement_and_provider_move_do_not_restore_shared_helpers(self):
        body=dict(file='state.c',symbol='helper')
        delta=assembly_delta({'old':['create'], 'neighbor':['read']},
            {'new':['create','destroy'], 'neighbor':['read']},
            {'old':[body], 'neighbor':[body]}, {'new':[body]})
        self.assertEqual(delta['added_entries'],{'destroy':'new'})
        self.assertEqual(delta['moved_entries'],{'create':dict(previous='old',desired='new')})
        self.assertEqual(delta['removed_components'],['old'])
        self.assertEqual(delta['retire'],[])
        self.assertEqual(delta['restore'],[])
        with self.assertRaisesRegex(ValueError,'multiple components'):
            assembly_delta({}, {'a':['create'],'b':['create']}, {}, {})

    def test_retirement_is_file_scoped_and_restores_exact_body_amid_local_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source='static int\nhelper(void) { return 3; }\nint kept(void) { return helper(); }\n'
            (root/'left.c').write_text(source);(root/'right.c').write_text(source)
            rows=[dict(file=name,symbol='helper') for name in ('left.c','right.c')]
            sources,records=reconcile_definitions(root,{},dict(retire=rows,restore=[]))
            self.assertEqual(len(records),2)
            for name,text in sources.items():(root/name).write_text(text+'/* operator note */\n')
            restored,remaining=reconcile_definitions(root,records,dict(retire=[],restore=[rows[0]]))
            self.assertEqual(restored['left.c'],source+'/* operator note */\n')
            self.assertEqual(list(remaining),['right.c:helper'])
            (root/'right.c').write_text(sources['right.c'].replace('int\nhelper(void);','int helper(int);'))
            with self.assertRaisesRegex(ValueError,'marker/declaration changed'):
                reconcile_definitions(root,records,dict(retire=[],restore=[rows[1]]))

    def test_legacy_restore_requires_matching_original_body(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'original').mkdir()
            source='int run(void) { return 2; }\n'
            (root/'state.c').write_text(source);(root/'original/state.c').write_text(source)
            row=dict(file='state.c',symbol='run');delta=dict(retire=[row],restore=[])
            sources,records=reconcile_definitions(root,{},delta)
            record=records['state.c:run'];del record['body'];del record['replacement'];del record['symbol']
            legacy={'run':record};(root/'state.c').write_text(sources['state.c'])
            with self.assertRaisesRegex(ValueError,'legacy retirement'):
                reconcile_definitions(root,legacy,dict(retire=[],restore=[row]))
            restored,remaining=reconcile_definitions(root,legacy,dict(retire=[],restore=[row]),restore_from=root/'original')
            self.assertEqual(restored['state.c'],source);self.assertEqual(remaining,{})
            (root/'original/state.c').write_text(source.replace('return 2','return 3'))
            with self.assertRaisesRegex(ValueError,'hash mismatch'):
                reconcile_definitions(root,legacy,dict(retire=[],restore=[row]),restore_from=root/'original')
