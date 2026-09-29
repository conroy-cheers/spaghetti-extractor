"""Bind an independently edited array search beneath the selected value getter."""
import argparse
from pathlib import Path

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import retained_component_inputs
from spaghetti_extractor.components.comparison_package import (
    comparison_preparation, load_comparison_package, prepare_comparison_package, retained_comparison_environment,
)


def connect(network,search,output):
    plan,_=load_comparison_package(network)
    supplier,_=load_comparison_package(search)
    if (plan['target_id']!='jq' or supplier['component_id']!='array-indexes'
            or plan['original']['files'].get('runtime/libjq-1.dll')!=supplier['original']['files'].get('runtime/libjq-1.dll')):
        raise ValueError('reviewed getter and search must use the same jq image')
    unit=next(u for u in plan['dependencies'] if u['id']=='value-get')
    if len(unit['adapters'])!=1:
        raise ValueError('review changed getter entry adapters')
    binding=bind_dependencies(services={'indexes':search})
    with comparison_preparation(output) as staged:
        bridge=staged/'get-bridge.c'
        text=(network/unit['adapters'][0]).read_text()
        marker='#include "comparison-service-bridge.h"'
        if text.count(marker)!=1:
            raise ValueError('review changed getter service binding')
        bridge.write_text(text.replace(marker,'#include "array-indexes-native.h"\n'+marker))
        with retained_component_inputs(network,component_id='value-get',retain_dependencies=True) as inputs:
            inputs['requirements']=[*inputs['requirements'],*binding['requirements']]
            inputs['dependencies']=[*inputs['dependencies'],*binding['dependencies']]
            inputs['service_bridge']['adapters']['indexes']['symbol']='fixture_array_indexes'
            inputs['include_files']['array-indexes-native.h']=search/'headers/array-indexes-native.h'
            names=['allocation-observer.c','dispatch.c','driver.c','errors.c','slice.c','value-runtime.c']
            adapters={name:network/'adapters'/name for name in names}
            adapters['bridge.c']=bridge
            prepare_comparison_package(**inputs,adapter_files=adapters,
                original_files=['runtime/libjq-1.dll'],oracle_kind='native-original',
                cases=[dict(id='indexes',arguments=['[1,2,1,2,3]','[1,2]','4','retained'])],
                observation_fields=['outcome','result','root_after','key_after','item_after','readback',
                    'allocation_lifetime','allocation_failure','references','alias_matrix'],
                scope='Existing array-index caller using the authored search and current storage selection.',
                export_adapters=['adapters/bridge.c'],output=staged/'value-get',
                **retained_comparison_environment(network))
    print(output/'value-get')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['network','search','output']:parser.add_argument(name,type=Path)
    args=parser.parse_args();connect(args.network.resolve(),args.search.resolve(),args.output.resolve())
