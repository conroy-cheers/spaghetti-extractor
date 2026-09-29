"""Hand-defined responsibilities and services for the real jq array subsystem."""
from spaghetti_extractor.components.service_authoring import ServiceDefinition

V, M, U, I = 'jq_value', 'jq_memory', 'u32', 'i32'
TYPES = [dict(id=V,kind='opaque',nominal_id='jq.value-holder'),
         dict(id=M,kind='opaque',nominal_id='jq.array-allocation'),
         dict(id=U,kind='integer',width_bits=32,signed=False),
         dict(id=I,kind='integer',width_bits=32,signed=True),dict(id='unit',kind='void')]
SPECS = {
    'copy': ([('input',V),('output',V)],'unit'),
    'release': ([('input',V)],'unit'),
    'create': ([('capacity',U),('output',V)],'unit'),
    'length': ([('input',V)],I),
    'get': ([('input',V),('index',I),('output',V)],'unit'),
    'set': ([('input',V),('index',I),('item',V),('output',V)],'unit'),
    'slice': ([('input',V),('start',I),('end',I),('output',V)],'unit'),
    'allocate': ([('capacity',U)],M),
    'dispose': ([('memory',M)],'unit'),
    'foreign_release': ([('input',V)],'unit'),
    'error': ([('code',U),('output',V)],'unit'),
}
UNITS = {
    'copy': [],
    'release': ['release','foreign_release','dispose'],
    'create': ['allocate'],
    'length': ['release'],
    'get': ['copy','release'],
    'set': ['release','error','create','copy'],
    'slice': ['release','create','copy','get','set'],
}

def definitions():
    return {name:ServiceDefinition.create(identity='jq.storage.'+name,types=TYPES,
        parameters=params,result=result,resources=[],
        effects=['jq.storage.'+name],outcomes=['return'],
        nonlocal_outcomes=['nomem'] if name in ('allocate','create','set','slice','error') else [],
        unobserved=['C object applicability, aliases and lifetime are executable adapter premises',
                    'no checked memory summary; foreign object internals and arbitrary callback behavior are outside this comparison'])
            for name,(params,result) in SPECS.items()}
