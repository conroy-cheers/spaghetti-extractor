"""Numbers at the C API boundary and through normal parser/interpreter consumers."""


def consumer_cases():
    return [
        ('precision', '[., tostring, .+0, -., abs]', '9007199254740993'),
        ('precision-negative', '[., tostring, .+0, -., abs]', '-9007199254740993'),
        ('decimal-zeros', 'map([., tostring, -., abs])', '[0,-0,0.00,-0.00,1.23000]'),
        ('decimal-order', '[sort,unique,min,max]', '[9007199254740993,9007199254740992,9007199254740994]'),
        ('exponents', 'map([.,tostring,.+0])', '[1e308,1e309,1e-308,1e-324,1e-9999]'),
        ('overflow', 'map([., -., abs])', '[1e9999999999,-1e9999999999]'),
        ('numeric-strings', 'map(try tonumber catch .)', '["1.2300","NaN","Infinity","-Infinity","nan123","1e","bad",""]'),
        ('mixed-compare', '[.[0]==.[1],.[0]<.[1],(.[0]+0)==.[1]]', '[9007199254740993,9007199254740992]'),
        ('shared-number', '. as $n | [$n,$n|tostring, -$n, ($n|abs),$n]', '-12345678901234567890.123456789'),
        ('number-stream', '.[] | [., -., abs, (.+0)]', '[1,-2,0.1,999999999999999999999999999999]'),
        ('nonfinite', '[(nan|isnan), (infinite|isinfinite),(-infinite|isinfinite),(nan|abs)]', 'null'),
    ]


def cases():
    rows = []
    literals = ['0', '-0', '0.0000', '-0.0000', '1.23000', '-1.23000',
                '9007199254740993', '123456789012345678901234567890.123456789',
                '1e308', '1e309', '-1e309', '5e-324', '1e-325', '1e-9999',
                '1e9999999999', 'NaN', 'sNaN', 'NaN123', 'Infinity', '-Infinity',
                '', 'bad', '1e', '+12', ' 12']
    for index, literal in enumerate(literals):
        rows.append(dict(id=f'literal-{index}', arguments=['literal', literal, '1.00']))
    bits = ['0000000000000000', '8000000000000000', '0000000000000001',
            '3fb999999999999a', '7fefffffffffffff', '7ff0000000000000',
            'fff0000000000000', '7ff8000000000042', 'fff8000000000042']
    for index, value in enumerate(bits):
        rows.append(dict(id=f'binary-{index}', arguments=['binary', value, '1.00']))
    for index, (first, second) in enumerate([
        ('9007199254740993', '9007199254740992'),
        ('9007199254740992', '9007199254740993'),
        ('1.00', '1'), ('-0', '0.00'), ('1e-9999', '0'),
        ('1e9999999999', 'Infinity'), ('NaN', 'NaN'),
        ('-12345678901234567890', '-12345678901234567891'),
    ]):
        rows.append(dict(id=f'compare-{index}', arguments=['literal', first, second]))
    for name, program, value in consumer_cases():
        rows.append(dict(id='consumer-' + name, arguments=['consumer', program, value]))
    return rows
