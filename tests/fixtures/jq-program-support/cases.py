"""Bounded direct inputs and real compiler consumers, without pilot rebuilds."""
import json


def cases():
    rows = []
    samples = [('empty', b'', 0), ('ascii', b'a\0b\n', 127),
        ('utf8', 'aé中🙂'.encode(), 0x1f642), ('all-bytes', bytes(range(256)), 0x10ffff),
        ('continuations', b'\x80\x81\x82\x83', 0x800), ('truncated', b'\xf0\x9f', 0x7ff),
        ('broken', b'\xf0\x9fa\x80', 0x80), ('overlong', b'\xc0\xaf\xe0\x80\x80', 0xd800),
        ('surrogate', b'\xed\xa0\x80', 0xffff), ('too-high', b'\xf4\x90\x80\x80', 0x110000),
        ('negative', b'\xff', -1)]
    samples += [('space-' + str(value), bytes([32]), value) for value in
        [8, 9, 13, 14, 32, 0x85, 0xa0, 0x1680, 0x2000, 0x200a, 0x200b, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000]]
    for name, data, value in samples:
        rows.append(dict(id=name, arguments=['unicode', data.hex(), str(value)]))
    for name, data in [('empty', b''), ('one', b'x'), ('lines', b'first\nsecond\nlast'),
                       ('trailing', b'a\n\n'), ('unicode', 'café🙂\nnext'.encode()),
                       ('nul-cr', b'a\0b\r\nc\r')]:
        rows.append(dict(id='locations-' + name, arguments=['locations', data.hex(), '']))
    rows.append(dict(id='opcodes', arguments=['opcodes', '', '']))
    programs = [
        ('identity', '.', {'a': [1, 2]}),
        ('closure', 'def f(x): x as $v | map(.+$v); def g(y): f(y+1); g(3)', [1, 2, 3]),
        ('recursive', 'def f: if .<1 then . else .-1|f end; [3|f, [range(0;8)]|map(.+1)]', None),
        ('reduce', 'reduce .[] as $x ({n:0,s:0}; .n+=1|.s+=$x)', [1, 2, 3]),
        ('alternatives', '[.[] | (.a? // .b? // "missing")]', [{'a': 1}, {'b': 2}, {}]),
        ('unicode', '[.,explode,.[1:3],length,utf8bytelength]', 'aé中🙂'),
        ('diagnostic', 'def f(x):\n x+;\nf(1)', None),
        ('location-error', 'def f: .;\nunknown_filter(1)', None),
        ('debug', '. as $v | debug | ($v+1)', 3),
        ('destructure', '. as {a:[$x,$y]} | [$y,$x]', {'a': [1, 2]}),
    ]
    for name, program, value in programs:
        rows.append(dict(id='consumer-' + name, arguments=['compiler', program.encode().hex(),
            json.dumps(value, ensure_ascii=False).encode().hex()]))
    for mode in range(5):
        rows.append(dict(id=f'home-precedence-{mode}', arguments=['environment', b'~/library'.hex(), str(mode)]))
    for name, path in [('empty', b''), ('tilde', b'~'), ('named-user', b'~user/a'),
                       ('backslash', b'~\\a'), ('binary', b'~/a\0ignored')]:
        rows.append(dict(id='expand-' + name, arguments=['environment', path.hex(), '1']))
    for index, (haystack, needle) in enumerate([(b'', b''), (b'a', b''), (b'', b'a'),
            (b'abababa', b'aba'), (b'a\0b\xffa', b'\0b'), (b'abc', b'd'),
            (b'ab', b'abcd'), (bytes(range(256)), b'\xfd\xfe\xff')]):
        rows.append(dict(id=f'memory-{index}', arguments=['memory', haystack.hex(), needle.hex()]))
    paths = [b'', b'.', b'..', b'missing', b'a\\..\\b', b'/tmp//missing',
        b'Z:/tmp/./x/../missing', b'z:\\tmp\\abc', b'\\tmp', b'C:missing', b'Q:missing',
        b'Q:\\x', b'\\\\server\\share\\x\\..\\y', b'foo/', b'foo/.', b'foo/..',
        b'foo...', b'foo   ', b'a./b. ', b'a\\.\\', b'a\\..\\..\\..\\..', b'C:',
        b'/', b'//', b'///x', b'. .', b'   ', b'NUL', b'aux.txt', b'conin$',
        b'\\\\?\\Z:\\a\\..\\b', b'\\\\.\\NUL', b'a\0ignored', 'café/🙂'.encode(),
        b'x'*259, b'x'*260, b'x'*300+b'/../short']
    for index, path in enumerate(paths):
        rows.append(dict(id=f'path-{index}', arguments=['paths', path.hex(), '0']))
    for index, path in enumerate([b'.', b'Z:relative', b'\\rooted', b'Q:relative']):
        rows.append(dict(id=f'path-drive-context-{index}', arguments=['paths', path.hex(), '1']))
    rows.append(dict(id='path-null-parts',arguments=['paths','','2']))
    return rows
