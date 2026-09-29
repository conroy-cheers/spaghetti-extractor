"""Manual stream boundary; reuse existing service and live-object facilities."""
from spaghetti_extractor.components.service_authoring import ServiceDefinition, component_interface

TYPES = [dict(id='io_stream', kind='opaque', nominal_id='runtime.stdio-stream'),
         dict(id='u32', kind='integer', signed=False, width_bits=32),
         dict(id='i32', kind='integer', signed=True, width_bits=32), dict(id='unit', kind='void')]
SPECS = {'pending': ([('stream','io_stream')], 'u32'),
         'error': ([('stream','io_stream')], 'i32'),
         'close': ([('stream','io_stream')], 'i32'),
         'bad_descriptor': ([], 'u32'), 'clear_errno': ([], 'unit')}


def definitions():
    return {name: ServiceDefinition.create(identity='runtime.stdio.'+name, types=TYPES,
        parameters=params, result=result,
        resources=([dict(root='parameter',value='stream',fields=[],
            transition='consume' if name=='close' else 'borrow_shared',
            kind='stdio-stream',domain='runtime')] if name in ('pending','error','close') else []),
        effects=['runtime.stdio.'+name], outcomes=['return'],
        unobserved=['Native FILE contents, close effects and error state are observed by the ordinary C adapter; declarations are not checked summaries.',
                    'No concurrent stream use, asynchronous callbacks, invalid FILE pointers or repeated close are admitted.'])
        for name,(params,result) in SPECS.items()}


def interface(services):
    return component_interface(component_id='stream-close', types=TYPES,
        parameters=[('stream','io_stream')], result='i32', services=services)
