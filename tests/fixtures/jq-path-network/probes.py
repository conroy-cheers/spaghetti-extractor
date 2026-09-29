"""Check current scalar rendering and transitive selection without running Wine."""
import argparse
import copy
from pathlib import Path

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.comparison_package import load_comparison_package
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1,compile_component_interface_v5
from spaghetti_extractor.util import write_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packages',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args()
    plan,intent=load_comparison_package(args.packages/'value-get')
    headers=render_component_c_headers_v5(compile_component_interface_v5(intent),plan['operation_symbols'])
    assert 'double (*number)' in headers['portable-component.h']
    result={'binary64_renderer':{'status':'supported','scope':'C declarations; not floating proof'}}
    payload=copy.deepcopy(intent.to_payload());schema=payload['schema']
    value=next(t for t in schema['types'] if t['id']=='f64');value.update(format='binary16',value_bits=16)
    boundary=BoundarySchemaV1.create(schema_id=schema['schema_id'],types=schema['types'],signatures=schema['signatures'])
    unsupported=ComponentInterfaceIntentV1.create(component_id=payload['id'],schema=boundary,state=payload['state'],
        effects=payload['effects'],services=payload['services'],protocol_states=payload['protocol']['states'],
        initial_protocol_state=payload['protocol']['initial_state'],operations=payload['operations'])
    try:
        render_component_c_headers_v5(compile_component_interface_v5(unsupported),plan['operation_symbols'])
    except ValueError as error:result['binary16_renderer']={'status':'unsupported','detail':str(error)}
    else:raise AssertionError('update the binary16 capability expectation')
    network,_=load_comparison_package(args.packages/'path-set-network')
    identities={row['id'] for row in network['dependencies']}
    assert identities=={'value-get','value-set','path-get'},identities
    result['transitive_selection']={'status':'supported','graph':network['composition'],
        'scope':'declared requirements and selected bodies; not checked semantic summaries'}
    write_json(args.output,result)


if __name__=='__main__':main()
