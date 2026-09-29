"""Lower typed caller relations with path-sensitive definedness.

These are boundary expressions in the existing relation IR, not another program
language. Bindings and byte accessors are supplied by the checker. Public intent
cannot inject C expressions, function names or unproved readable-memory facts.
The returned definedness predicate is an obligation, never an implicit assumption
or an executable adapter. Consumers must check/admit it at the appropriate phase.
"""

from dataclasses import dataclass
from typing import Mapping

from .relation_ir import BOOL_SORT, MachinePlaceV1, RelationExpressionV1, RelationSortV1


@dataclass(frozen=True)
class ScalarBinding:
    sort: RelationSortV1
    expression: str


@dataclass(frozen=True)
class ViewBinding:
    """Checker-owned physical view at one explicit entry/call/exit phase.

    The accessor reads that phase's current memory. Its liveness, permission and
    backing-memory correspondence must be established by the enclosing rule.
    This binding itself does not establish them.
    """

    sort: RelationSortV1
    address: str
    extent: str
    byte_accessor: str


@dataclass(frozen=True)
class LoweredRelation:
    sort: RelationSortV1
    value: str
    defined: str

    def predicate(self) -> str:
        if self.sort != BOOL_SORT:
            raise ValueError('caller relation predicate is not Boolean')
        return f'(({self.defined}) && ({self.value}))'


def parameter(name: str, sort: RelationSortV1) -> RelationExpressionV1:
    return RelationExpressionV1.parse({
        'op': 'logical', 'sort': sort.to_payload(), 'args': [],
        'attributes': {'path': {'root': 'parameter', 'id': name, 'fields': []}},
    })


def constant(value: int, width: int = 32) -> RelationExpressionV1:
    return RelationExpressionV1.parse({
        'op': 'const', 'sort': {'kind': 'bitvector', 'width': width},
        'args': [], 'attributes': {'value': value},
    })


def expression(op: str, sort: RelationSortV1, *args: RelationExpressionV1) -> RelationExpressionV1:
    return RelationExpressionV1.parse({
        'op': op, 'sort': sort.to_payload(), 'args': [a.to_payload() for a in args], 'attributes': {},
    })


def lower_call_relation(
    value: object, *, parameters: Mapping[str, ScalarBinding | ViewBinding],
    machines: Mapping[str, ScalarBinding] | None = None,
) -> LoweredRelation:
    """Lower the implemented unsigned scalar/current-byte subset; reject the rest.

    Parameters are internal checker bindings, not values from target-authored C.
    Parsing on entry also validates manually constructed RelationExpressionV1s.
    Each operation below supplies both value semantics and definedness semantics.
    Boolean and/ or/ ite definedness follows actual short-circuit evaluation.
    """
    root = RelationExpressionV1.parse(value.to_payload() if isinstance(value, RelationExpressionV1) else value)

    def require(condition, detail):
        if not condition:
            raise ValueError('caller relation: ' + detail)

    def ctype(sort):
        require(sort.kind == 'bitvector' and sort.width in {8, 16, 32, 64},
                'only 8/16/32/64-bit unsigned values are implemented')
        return f'uint{sort.width}_t'

    def view(node):
        require(node.op == 'logical', 'view must name a bound parameter')
        binding = logical(node)
        require(isinstance(binding, ViewBinding), 'view binding is absent')
        return binding

    def logical(node):
        path = node.attributes['path']
        require(path['root'] == 'parameter' and not path['fields'], 'unimplemented logical path')
        binding = parameters.get(path['id'])
        require(isinstance(binding, (ScalarBinding, ViewBinding)) and binding.sort == node.sort,
                'parameter binding or sort differs: ' + path['id'])
        return binding

    def lower(node):
        op, sort = node.op, node.sort
        if op == 'machine':
            place = MachinePlaceV1.parse(node.attributes['place'])
            binding = (machines or {}).get(place.key)
            require(isinstance(binding, ScalarBinding) and binding.sort == sort,
                    'machine place binding or sort differs: ' + place.key)
            cast = '_Bool' if sort == BOOL_SORT else ctype(sort)
            return LoweredRelation(sort, f'(({cast})({binding.expression}))', '1U')
        if op in {'true', 'false'}:
            return LoweredRelation(sort, '1U' if op == 'true' else '0U', '1U')
        if op == 'logical':
            binding = logical(node)
            require(isinstance(binding, ScalarBinding), 'a view needs an explicit projection')
            require(sort == BOOL_SORT or sort.kind == 'bitvector', 'unimplemented scalar sort')
            cast = '_Bool' if sort == BOOL_SORT else ctype(sort)
            return LoweredRelation(sort, f'(({cast})({binding.expression}))', '1U')
        if op == 'const':
            return LoweredRelation(sort, f'(({ctype(sort)})UINT64_C({node.attributes["value"]}))', '1U')
        if op in {'view_address', 'view_extent'}:
            binding = view(node.arguments[0])
            field = binding.address if op == 'view_address' else binding.extent
            maximum = (1 << int(sort.width or 0)) - 1
            # A 2^32-byte extent does not fit in a 32-bit value. Do not silently
            # turn such a view into an empty view through narrowing conversion.
            return LoweredRelation(sort, f'(({ctype(sort)})({field}))',
                                   f'((uint64_t)({field}) <= UINT64_C({maximum}))')
        if op == 'byte_read':
            binding = view(node.arguments[0]); offset = lower(node.arguments[1])
            require(bool(binding.byte_accessor), 'current-memory accessor is absent')
            ctype(offset.sort)
            # Check with subtraction so even a 64-bit arbitrary offset cannot
            # wrap the address calculation and pass admission.
            address = f'((uint64_t)({binding.address}))'
            index = f'((uint64_t)({offset.value}))'
            valid = (f'(({offset.defined}) && {address} <= UINT64_C(4294967295) && '
                     f'{index} < (uint64_t)({binding.extent}) && '
                     f'{index} <= UINT64_C(4294967295) - {address})')
            read = f'{binding.byte_accessor}((uint32_t)({address} + {index}))'
            return LoweredRelation(sort, read, valid)
        args = [lower(a) for a in node.arguments]
        if op in {'and', 'or'}:
            left, right = args
            operator = '&&' if op == 'and' else '||'
            guard = f'!({left.value})' if op == 'and' else left.value
            defined = f'(({left.defined}) && (({guard}) || ({right.defined})))'
            return LoweredRelation(sort, f'(({left.value}) {operator} ({right.value}))', defined)
        if op == 'ite':
            condition, left, right = args
            defined = (f'(({condition.defined}) && (({condition.value}) ? '
                       f'({left.defined}) : ({right.defined})))')
            return LoweredRelation(sort,
                f'(({condition.value}) ? ({left.value}) : ({right.value}))', defined)
        defined = ' && '.join(f'({arg.defined})' for arg in args) or '1U'
        if op == 'concat':
            # Existing IR orders the most significant operand first. Explicit
            # unsigned promotion also handles a top byte with its sign bit set.
            ctype(sort)
            shift=0;parts=[]
            for arg in reversed(args):
                ctype(arg.sort)
                parts.append(f'((uint64_t)({arg.value}) << {shift}U)')
                shift+=arg.sort.width
            return LoweredRelation(sort,f'(({ctype(sort)})('+ ' | '.join(parts)+'))',defined)
        operators = {'eq': '==', 'ult': '<', 'ule': '<=', 'add': '+', 'sub': '-',
                     'bit_and': '&', 'bit_or': '|', 'bit_xor': '^'}
        if op in operators:
            left, right = args
            if op == 'eq':
                require(left.sort == BOOL_SORT or left.sort.kind == 'bitvector',
                        'structured equality needs a checked transport rule')
            # Explicit unsigned promotion prevents signed overflow for small
            # integer sorts. Narrow after the operation to implement bitvectors.
            if sort.kind == 'bitvector':
                result = f'(({ctype(sort)})((uint64_t)({left.value}) {operators[op]} (uint64_t)({right.value})))'
            else:
                result = f'(({left.value}) {operators[op]} ({right.value}))'
            return LoweredRelation(sort, result, defined)
        if op in {'not', 'bit_not'}:
            result = f'(!({args[0].value}))' if op == 'not' else f'(({ctype(sort)})(~(uint64_t)({args[0].value})))'
            return LoweredRelation(sort, result, defined)
        if op in {'zero_extend', 'truncate', 'bitcast'}:
            ctype(args[0].sort)
            return LoweredRelation(sort, f'(({ctype(sort)})({args[0].value}))', defined)
        raise ValueError('caller relation: unsupported operation ' + op)

    return lower(root)
