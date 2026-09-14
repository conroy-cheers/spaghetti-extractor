"""Full contextual proofs for register-relative scalar state."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from tests.unit.components.test_dynamic_state_storage import state_fixture, memory_projection
from tests.unit.components.test_inductive_relation import _unit
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import check_component_source_profile
from spaghetti_extractor.transfer.model import _Node, _Action, _Transfer

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def check_frame_state(root: Path, *, cbmc: Path, increment: int = 1) -> dict:
    unit_id='semantic-transfer:original-cutpoint-00001000-00001001'
    bundle,overlay=state_fixture(unit_id)
    interface=ProofKernelComponentInterface.parse({'id':'counter','types':[{'id':'u32','kind':'scalar','c_type':'uint32_t'}],
     'state':[{'id':'count','type_id':'u32','initial':0}], 'operations':[{'id':'run','kind':'operation','parameters':[],
     'results':[],'effect_ids':[],'allowed_service_ids':[],'pre_states':['ready'],'post_states':['ready']}],
     'effects':[],'services':[],'protocol':{'states':['ready'],'initial_state':'ready'}})
    operation={'operation_id':'run','entry_unit_ids':[unit_id],'exit_unit_ids':[unit_id],
     'machine_image':{'preferred_base':0x400000,'image_size':0x10000},'parameters':[],'results':[],
     'state':[{'id':'count','entry':memory_projection(),'exit':memory_projection('exit')}],
     'preserved_state_ids':[],'effects':[],'callback_operation_ids':[],
     'units':[_unit(unit_id,4096,[(4097,{'op':'true'})],[])]}
    intent=ComponentBisimulationIntentV1.create(component_id='counter',operations=[{'operation_id':'run','syncs':[]}])
    transfer=_Transfer(unit_id,'a'*64,'b'*64,4096,(
     _Node('reg',aux=6),_Node('const',immediate=4),_Node('sub32',(0,1)),_Node('load',(2,),aux=4),
     _Node('const',immediate=1),_Node('add32',(3,4))),(),(_Action('memory_write',(2,5),aux=4),_Action('outcome_fallthrough',(4097,))),(),())
    exact=write_component_exact_c_slice_v1(component_id='counter',transfers=[transfer],operations=[{'operation_id':'run',
     'unit_ids':[unit_id],'entry_rvas':[4096]}],intent=intent,executable_transfer_plan_sha256='c'*64,out=root/'exact')
    source_path=root/'authored.c'
    source_path.write_text('#include "portable-component-implementation.h"\nvoid authored_run(spx_counter_context_v5 *context) { SPX_PROOF_BEGIN(run); context->state.count += INCREMENT; }\n')
    source_path.write_text(source_path.read_text().replace('INCREMENT', f'{increment}U'))
    package=root/'source'
    source=build_component_source_package(lift_unit_id='counter',files={'authored.c':source_path},shared_inputs={},
     operation_symbols={'run':'authored_run'},out_dir=package)
    result=check_bisimulation_refinement(semantic_contract={'component_id':'counter','contract_sha256':'a'*64,'operations':[operation]},
     interface=interface,source_package=package,source_profile=check_component_source_profile(package=package),intent=intent,
     exact_c_root=root/'exact',exact_c_slice=exact,machine_overlay_source=overlay.source,machine_overlay_entries=overlay.entries,
     machine_projections={'run':{'operation':operation,'service_bindings':[]}},cbmc=cbmc,
     c_headers=render_component_c_headers_v5(bundle,{'run':'authored_run'}),timeout_seconds=30,diagnostic_root=root/'diagnostics')
    return result


class DynamicStateRefinementTests(unittest.TestCase):
    def test_arbitrary_frame_word_and_fault_outcomes(self) -> None:
        compiler = shutil.which("cbmc")
        if compiler is None:
            self.skipTest("CBMC unavailable")
        for increment in (1, 2):
            with self.subTest(increment=increment), tempfile.TemporaryDirectory() as temporary:
                result = check_frame_state(Path(temporary), cbmc=Path(compiler), increment=increment)
                self.assertEqual(result["status"], "satisfied" if increment == 1 else "violated", result["issues"])
                if increment == 2:
                    self.assertTrue(any(row.get("code") == "cbmc_counterexample" and
                        row.get("detail") == "spx-bisimulation-exit-observable:run:state:count" for row in result["issues"]), [(row.get("code"), row.get("detail")) for row in result["issues"]])
