"""Actual CLI arguments; no output or line-ending normalization."""


def cases():
    rows = [
        ('help', ['--help']), ('version', ['--version']), ('configuration', ['--build-configuration']),
        ('binary-help', ['--binary', '--help']), ('binary-version', ['--binary', '-V']),
        ('unknown-long', ['--no-such-option']), ('unknown-short', ['-Q']),
        ('binary-unknown', ['--binary', '--no-such-option']), ('missing-arg', ['--arg', 'x']),
        ('invalid-argjson', ['--argjson', 'x', '{']), ('missing-path', ['-L']),
        ('missing-indent', ['--indent']), ('bad-indent', ['--indent', '8']),
        ('raw', ['-nr', r'"a\nb"']), ('raw-binary', ['-bnr', r'"a\nb"']),
        ('raw-crlf', ['-nr', r'"a\r\nb\rc"']), ('join', ['-njr', r'"a\nb", "tail"']),
        ('raw-zero', ['-n', '--raw-output0', r'"a\nb", "tail"']),
        ('raw-zero-error', ['-n', '--raw-output0', r'"a\u0000b"']),
        ('unicode', ['-ncr', r'"café日本🙂\nnext"']),
        ('ascii', ['-nar', '"café日本🙂"']),
        ('pretty', ['-n', '{z:[1,2],a:{x:true}}']),
        ('sorted', ['-nS', '--indent', '4', '{z:[1,2],a:{x:true}}']),
        ('tab', ['-n', '--tab', '{z:[1,2],a:{x:true}}']),
        ('color', ['-nC', '[1,"x",null,true]']), ('monochrome', ['-nCM', '{x:1}']),
        ('unbuffered', ['-ncr', '--unbuffered', 'range(0;8)']),
        ('seq', ['-nc', '--seq', '[1,2],{x:3}']),
        ('debug', ['-nc', '[1,2] | debug | .']),
        ('stderr', ['-nc', r'"error\nline" | stderr | empty']),
        ('halt', ['-n', 'halt']), ('halt-error', ['-nr', r'"error\nline" | halt_error(5)']),
        ('runtime-error', ['-nc', 'error("message")']),
        ('compile-error', ['-nc', 'def broken: ;']),
        ('exit-false', ['-ne', 'false']), ('exit-null', ['-ne', 'null']),
        ('exit-empty', ['-ne', 'empty']), ('exit-true', ['-ne', 'true']),
        ('named', ['-nc', '--arg', 'name', 'café🙂', '--argjson', 'v', '{"x":[1,2]}', '[$name,$v,$ARGS]']),
        ('args', ['-nc', '--args', '$ARGS', 'a b', '"x"', 'café🙂']),
        ('jsonargs', ['-nc', '--jsonargs', '$ARGS', '{"x":1}', '[2,3]']),
        ('file', ['-c', '.', 'values.json']),
        ('slurp', ['-cs', 'map(.x)|add', 'values.json']),
        ('raw-file', ['-Rsr', '.', 'text.txt']),
        ('rawfile-arg', ['-ncr', '--rawfile', 's', 'text.txt', '$s']),
        ('slurpfile-arg', ['-nc', '--slurpfile', 'v', 'values.json', '$v']),
        ('filter-file', ['-ncf', 'filter.jq']),
        ('stream', ['-c', '--stream', '.', 'values.json']),
    ]
    return [dict(id='cli-' + name, arguments=args) for name, args in rows]


def files():
    return {'values.json': b'{"x":[1,2]}\r\n{"x":[3,4]}\r\n',
            'text.txt': 'first\r\ncafé🙂\nlast\x1aignored\n'.encode(),
            'filter.jq': b'{sum:([range(0;40)]|add), s:"from file"}\r\n'}
