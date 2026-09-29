"""Normal --run-tests use and meaningful malformed-test diagnostics."""


def files():
    basic = b'. + 1\n1\n2\n\n.[]\n[1,2]\n1\n2\n\n'
    return {
        'basic.tests': basic,
        'crlf.tests': basic.replace(b'\n', b'\r\n'),
        'ctrlz.tests': basic + b'\x1anonsense\n',
        'wrong.tests': b'. + 1\n1\n3\n\n',
        'short.tests': b'empty\nnull\n1\n\n',
        'extra.tests': b'1,2\nnull\n1\n\n',
        'bad-input.tests': b'.\n{\nnull\n\n',
        'bad-expected.tests': b'.\nnull\n{\n\n',
        'compile.tests': b'def broken: ;\nnull\nnull\n\n',
        'expect-failure.tests': b'%%FAIL IGNORE MSG\ndef broken: ;\nignored\n\n',
        'unexpected-success.tests': b'%%FAIL IGNORE MSG\n.\nignored\n\n',
        'empty.tests': b'# comment\n \t\n',
    }


def cases():
    rows = [dict(id=name.removesuffix('.tests'), arguments=['--run-tests', name]) for name in files()]
    for name, args in [
        ('skip-take', ['--skip', '1', '--take', '1', 'basic.tests']),
        ('skip-past', ['--skip', '20', 'basic.tests']),
        ('take-zero', ['--take', '0', 'basic.tests']),
        ('missing-file', ['missing.tests']),
    ]:
        rows.append(dict(id=name, arguments=['--run-tests', *args]))
    rows.append(dict(id='verbose', arguments=['--debug-dump-disasm', '--run-tests', 'basic.tests']))
    rows.append(dict(id='binary-named-file', arguments=['--binary', '--run-tests', 'crlf.tests']))
    return rows
