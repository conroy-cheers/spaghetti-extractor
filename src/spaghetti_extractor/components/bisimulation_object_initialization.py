"""Normal-return initialization claims checked against actual byte writes.

A writable footprint permits writes; it does not establish initialization.
Only non-service write events in the current invocation witness these claims.
The enclosing complete original/source proof and its exact evidence are required
before a consumer may transport any resulting initialization fact.
"""

from .machine_binding import MachineProjectionV1
from .machine_overlay_result_views import checked_nullable_input_projection


def checked_object_parameter_projection(value, projection):
    if value.nullable and value.extent.get('kind') == 'none':
        return checked_nullable_input_projection(projection)
    row = MachineProjectionV1.parse(projection, 'object input view').payload
    extent = {'kind': 'constant', 'width': 32, 'value': value.extent.get('bytes')}
    if (value.nullable or value.extent.get('kind') != 'fixed'
            or row['kind'] != 'view' or row['at'] != 'entry'
            or row['extent'] != extent or row['requested_extent'] != extent):
        raise ValueError('fixed object input requires its exact nonnullable byte extent')
    return row


def checked_initialization_requests(rows, *, signature):
    if not isinstance(rows, list):
        raise ValueError('normal initialization requests must be a list')
    parameters = {v.identity: v for v in signature.parameters}
    previous = None
    result = []
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {'parameter', 'offset', 'extent'}
                or not isinstance(row['parameter'], str)):
            raise ValueError('normal initialization fields differ')
        value = parameters.get(row['parameter'])
        if (value is None or value.interpretation != 'view' or value.access not in {'write', 'read_write'}
                or value.nullable or value.extent.get('kind') != 'fixed'
                or any(type(row[k]) is not int for k in ('offset', 'extent'))
                or row['offset'] < 0 or row['extent'] <= 0
                or row['offset'] + row['extent'] > value.extent['bytes']):
            raise ValueError('normal initialization needs a nonempty writable fixed parameter span')
        key = (row['parameter'], row['offset'], row['extent'])
        if previous is not None and (key <= previous or
                key[0] == previous[0] and key[1] < previous[1] + previous[2]):
            raise ValueError('normal initialization spans must be ordered and nonoverlapping')
        previous = key
        result.append(dict(row))
    return result


def initialization_checks(rows, *, views, side):
    """Use one arbitrary address; every claimed byte must have an actual write."""
    if not rows:
        return []
    indices = {value.identity: i for i, (root, value) in enumerate(views) if root == 'parameter'}
    lines = []
    probe = f'world_{side}.observed_address'
    for row in rows:
        index = indices[row['parameter']]
        start = f'((uint64_t)input_{index}.address+UINT64_C({row["offset"]}))'
        end = f'({start}+UINT64_C({row["extent"]}))'
        lines += [f'  __CPROVER_assert({probe}<{start} ||',
            f'      (uint64_t){probe}>={end} || world_{side}.observed_initialized,',
            f'      "spx-object-initialized:{side}:{row["parameter"]}:{row["offset"]}:{row["extent"]}");']
    return lines
