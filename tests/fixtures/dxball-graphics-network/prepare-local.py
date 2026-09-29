"""Prepare the reviewed blit local check from its selected network inputs.

No original per-component package or declaration recipe is needed. The existing
retained-C oracle/runtime and blit driver are explicitly selected here; the tool
reuses the chosen component's boundary, shared inputs, service binding and C.
"""
import argparse
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_environment import retained_component_inputs
from spaghetti_extractor.components.comparison_package import (
    load_comparison_package, prepare_comparison_package, retained_comparison_environment,
)


def prepare(network, output):
    started=time.monotonic()
    plan,_=load_comparison_package(network)
    if (plan['target_id'],plan['component_id'],plan['original']['kind']) != (
            'dxball','graphics-initialize','retained-c'):
        raise ValueError('requires the reviewed retained-C graphics initializer network')
    unit=next((row for row in plan.get('dependencies',[]) if row['id']=='graphics-blit'),None)
    if unit is None:raise ValueError('the network must select graphics-blit')
    adapters={Path(name).name:network/name for name in plan['adapters']
              if name.startswith('adapters/behavioral-') or name in ('adapters/runtime.c','adapters/driver.c')}
    if len(unit['adapters'])!=1:
        raise ValueError('review the changed blit entry adapter before preparing its local check')
    adapters['bridge.c']=network/unit['adapters'][0]
    with retained_component_inputs(network,component_id='graphics-blit') as inputs:
        # The retained blit header selects the existing driver's local branch.
        # Do not inherit the enclosing initializer's case selection.
        if inputs['include_files']['case-unit.h'].read_text()!='#define DX_CASE_UNIT 2\n':
            raise ValueError('review the changed local blit driver selection')
        prepare_comparison_package(**inputs,adapter_files=adapters,
            original_files=list(plan['original']['files']),oracle_kind=plan['original']['kind'],
            cases=[dict(id='seed-7',arguments=['7','0','0','1','0','0'])],
            observation_fields=['results','state','banks','resources','windows','pixels','services'],
            scope='Independent blit with live sprite/backbuffer aliases and controlled graphics service; retained-C comparison.',
            export_adapters=['adapters/bridge.c'],output=output,
            **retained_comparison_environment(network))
    print(f'Prepared local blit in {time.monotonic()-started:.3f}s: {output}')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('network',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    prepare(args.network.resolve(),args.output.resolve())
