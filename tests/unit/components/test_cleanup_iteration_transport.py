"""Actual loop correspondence includes mutable state, both cuts and faults."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_cut_state import _symbol, _walk
from .cleanup_iteration import FIXTURE, compile_iteration, checked_transport, check_properties

TESTKIT = {'capabilities': ('cbmc',), 'fixtures': ('cbmc','compiler','z3'),
           'resources': ('tests/fixtures/metapad-cleanup-iteration',)}


class CleanupIterationTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root=Path(cls.directory.name)/'baseline'
        cls.models=compile_iteration(cls.root)

    def test_actual_compiled_loop_and_complete_paired_properties(self):
        with patch('subprocess.run',side_effect=AssertionError('import must not execute tools')):
            result=checked_transport(self.models)
        self.assertEqual(result['inert']['status'],'matched-inert-region-markers')
        transport=result['transport']
        self.assertEqual({tuple(row) for row in transport['exits'] if row[0]=='cut'},
                         {('cut','loop'),('cut','tail')})
        self.assertEqual(sum(row[0]=='return' for row in transport['exits']),4)
        self.assertTrue(transport['local_cut_observer_arguments_checked'])
        self.assertFalse(transport['runtime_contracts_checked'])
        checked=check_properties(self.root)
        self.assertEqual(checked['status'],'satisfied',checked.get('detail'))
        self.assertGreater(checked['properties'],1800)

    def test_wrong_actual_store_is_rejected_after_source_correspondence(self):
        source=(FIXTURE/'authored.c').read_text()
        old='      if (spx_view_write_u8(&scratch, output, a)) return UINT32_MAX;\n      ++output;'
        self.assertEqual(source.count(old),1)
        root=Path(self.directory.name)/'incorrect'
        models=compile_iteration(root,body=source.replace(old,
            '      if (spx_view_write_u8(&scratch, output, a+1U)) return UINT32_MAX;\n      ++output;'))
        self.assertEqual(checked_transport(models)['transport']['status'],'matched-source-region-transport')
        result=check_properties(root)
        self.assertEqual(result['status'],'violated',result.get('detail'))

    def test_wrong_restore_and_observer_cannot_inherit_correspondence(self):
        for mutation in ('restore','observer-value','observer-effect','entry-assumption','cut-ordinal','body-read','static-local'):
            with self.subTest(mutation=mutation):
                models=deepcopy(self.models)
                rows=models['pair']['functions']['cleanup']['instructions']
                if mutation=='restore':
                    row=next(r for r in rows if r['instructionId']=='ASSIGN'
                        and _symbol(r['code']['sub'][0])=='cleanup::1::input'
                        and r['code']['sub'][1].get('id')=='member')
                    row['code']['sub'][1]['namedSub']['component_name']['id']='output'
                elif mutation in ('observer-value','cut-ordinal'):
                    row=next(r for r in rows if r['instructionId']=='FUNCTION_CALL'
                        and _symbol(r['code']['sub'][1])=='observe_loop')
                    args=row['code']['sub'][2]['sub']
                    if mutation=='observer-value':
                        args[1]=deepcopy(args[2])
                    else:
                        args[0]['namedSub']['value']['id']='560D'
                elif mutation=='observer-effect':
                    observer=models['pair']['functions']['observe_loop']['instructions']
                    row=deepcopy(next(r for r in rows if r['instructionId']=='ASSIGN'))
                    row['locationNumber']=max(r['locationNumber'] for r in observer)+1
                    observer.insert(0,row)
                elif mutation=='entry-assumption':
                    row=next(r for r in rows if r['instructionId']=='ASSERT'
                        and r['sourceLocation'].get('comment')=='source-cut-invariant')
                    row['instructionId']='ASSUME'
                elif mutation=='static-local':
                    models['pair']['symbols']['cleanup::1::a']['isStaticLifetime']=True
                    # A real static object also loses its automatic lifetime
                    # ends. Retarget jumps past those removed instructions so
                    # the storage gate, rather than malformed control flow or
                    # an impossible static DEAD, must reject this change.
                    removed={i for i,r in enumerate(rows) if r['instructionId']=='DEAD'
                             and _symbol(r['code']['sub'][0])=='cleanup::1::a'}
                    redirects={rows[i]['locationNumber']:next(r['locationNumber']
                        for j,r in enumerate(rows[i+1:],i+1) if j not in removed) for i in removed}
                    rows[:]=[{**r,'targets':[redirects.get(t,t) for t in r.get('targets',[])]}
                             for i,r in enumerate(rows) if i not in removed]
                else:
                    entry=next(i for i,r in enumerate(rows) if r['instructionId']=='ASSERT'
                        and r['sourceLocation'].get('comment')=='source-cut-invariant')
                    row=next(r for r in rows[entry+1:] if r['instructionId']=='FUNCTION_CALL'
                        and _symbol(r['code']['sub'][1])=='spx_view_read_u8')
                    for node in _walk(row['code']['sub'][2]):
                        if _symbol(node)=='cleanup::1::input':
                            node['namedSub']['identifier']['id']='cleanup::1::output'
                with self.assertRaisesRegex(ValueError,'body operand storage differs' if mutation=='static-local' else '.'):
                    checked_transport(models)
