"""Ordinary object storage operations sharing the existing jq value convention."""
from pathlib import Path
import runpy

from spaghetti_extractor.components.service_authoring import ServiceDefinition

ARRAY = runpy.run_path(str(Path(__file__).resolve().parent.parent/'jq-array-storage/declarations.py'))
TYPES = [row for row in ARRAY['TYPES'] if row['id'] != 'jq_memory'] + [
    dict(id='object_memory', kind='opaque', nominal_id='jq.object-allocation')]
SPECS = {
    'create': ([('capacity', 'u32'), ('output', 'jq_value')], 'unit'),
    'release': ([('input', 'jq_value')], 'unit'),
    'unshare': ([('input', 'jq_value'), ('output', 'jq_value')], 'unit'),
    'allocate': ([('capacity', 'u32')], 'object_memory'),
    'dispose': ([('memory', 'object_memory')], 'unit'),
}
UNITS = {'create': ['allocate'], 'release': ['release_value', 'dispose'],
         'unshare': ['create', 'release_object', 'copy']}


def definitions():
    shared = ARRAY['definitions']()
    result = {name: ServiceDefinition.create(identity='jq.object.storage.'+name, types=TYPES,
        parameters=parameters, result=output, resources=[], effects=['jq.object.storage.'+name],
        outcomes=['return'], nonlocal_outcomes=['nomem'] if name in ('allocate', 'create', 'unshare') else [],
        unobserved=['Live shared storage, reference ownership and non-reentrancy are reviewed C boundary premises.'])
        for name, (parameters, output) in SPECS.items()}
    result['copy'] = shared['copy']; result['release_value'] = shared['release']
    result['release_object'] = result['release']
    return result
