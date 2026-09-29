"""Reviewed manual boundaries for the pinned DX-Ball graphics consumer."""
from spaghetti_extractor.components.service_authoring import ServiceDefinition

G, U, I = 'dx_graphics', 'u32', 'i32'
TYPES = [dict(id=G, kind='opaque', nominal_id='dxball.graphics-state'),
         dict(id=U, kind='integer', width_bits=32, signed=False),
         dict(id=I, kind='integer', width_bits=32, signed=True),
         dict(id='unit', kind='void')]
STATE = [('state', G)]
SPECS = {
    'reset': (STATE, 'unit'),
    'bind': (STATE + [('surface', U)], 'unit'),
    'blit': (STATE + [('index', U), ('x', U), ('y', U)], U),
    'initialize': (STATE, U),
    'create_draw': (STATE, I),
    'cooperative': (STATE + [('draw', U), ('window', U), ('flags', U)], I),
    'caps': (STATE + [('draw', U)], U),
    'create_surface': (STATE + [('draw', U), ('kind', U)], I),
    'create_clipper': (STATE + [('draw', U)], I),
    'clipper_window': (STATE + [('clipper', U), ('window', U)], I),
    'attach': (STATE + [('primary', U), ('clipper', U)], I),
    'hide': (STATE + [('window', U)], 'unit'),
    'message': (STATE + [('window', U), ('kind', U)], U),
    'destroy': (STATE + [('window', U)], 'unit'),
    'blit_fast': (STATE + [(key, U) for key in
        ('destination', 'x', 'y', 'source', 'left', 'top', 'right', 'bottom', 'flags')], U),
}
UNITS = {'reset': [], 'bind': [], 'blit': ['blit_fast'],
         'initialize': ['create_draw', 'cooperative', 'caps', 'create_surface',
             'create_clipper', 'clipper_window', 'attach', 'hide', 'message',
             'destroy', 'reset', 'bind']}

def definitions():
    return {name: ServiceDefinition.create(identity='dxball.graphics.' + name,
        types=TYPES, parameters=params, result=result, resources=[],
        effects=['dxball.graphics.' + name], outcomes=['return'],
        unobserved=['Logical live handles, pointee contents, aliases and synchronous window mutations are checked by the C adapter and observations.',
            'No checked heap summary or real DirectDraw driver behavior; arbitrary reentrancy and concurrency are outside this fixture.'])
        for name, (params, result) in SPECS.items()}
