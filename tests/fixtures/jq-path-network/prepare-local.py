"""Prepare the reviewed value getter from the current selected path network.

The network supplies its boundary, C, selected suppliers and shared service inputs.
This recipe explicitly selects the retained native driver/oracle and one getter
case; no original per-component preparation folders or old selections are needed.
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
    if (plan['target_id']!='jq' or plan['original']['files'].get('runtime/libjq-1.dll')!=
            '50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'):
        raise ValueError('requires the pinned jq path comparison runtime')
    unit=next((row for row in plan.get('dependencies',[]) if row['id']=='value-get'),None)
    if unit is None or len(unit['adapters'])!=1:
        raise ValueError('review the selected getter and its entry adapter before preparing a local check')
    names=['allocation-observer.c','dispatch.c','driver.c','errors.c','slice.c','value-runtime.c']
    if any('adapters/'+name not in plan['adapters'] for name in names):
        raise ValueError('review the changed shared path fixture adapters')
    adapters={name:network/'adapters'/name for name in names}
    adapters['bridge.c']=network/unit['adapters'][0]
    with retained_component_inputs(network,component_id='value-get',retain_dependencies=True) as inputs:
        if inputs['include_files']['config.h'].read_text()!=(
                '#define PATH_IS_SET 0\n#define PATH_ENTRY fixture_value_get\n#define PATH_ORIGINAL jv_get\n'
                '#define PATH_NETWORK 0\n#define PATH_ALLOCATION_OBSERVER 1\n'):
            raise ValueError('review the changed getter driver configuration')
        prepare_comparison_package(**inputs,adapter_files=adapters,
            original_files=['runtime/libjq-1.dll'],oracle_kind='native-original',
            cases=[dict(id='negative',arguments=['[10,20,30]','-1','4','retained'])],
            observation_fields=['outcome','result','root_after','key_after','item_after','readback',
                'allocation_lifetime','allocation_failure','references','alias_matrix'],
            scope='Local value getter with retained aliases and the current selected storage/string suppliers.',
            export_adapters=['adapters/bridge.c'],output=output,
            **retained_comparison_environment(network))
    print(f'Prepared local getter in {time.monotonic()-started:.3f}s: {output}')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('network',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    prepare(args.network.resolve(),args.output.resolve())
