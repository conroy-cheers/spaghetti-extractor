"""Exercise connected value operations, shared storage and real consumers."""


def consumer_cases():
    return [
        ('unicode', '[.,explode,(explode|implode),(.+.),(.*3),split("é")]', '"aé🙂\\u0000z"'),
        ('object-growth', 'reduce range(100) as $i ({}; .["key-"+($i|tostring)]=$i) | [length,keys,.["key-99"]]', 'null'),
        ('object-alias', '. as $old|.["new"]={x:1}|.a=9|del(.b)|[$old,.,keys,has("a")]', '{"a":1,"b":2}'),
        ('object-iteration', 'to_entries|map(.value+=1)|from_entries', '{"z":0,"a":1,"é":2}'),
        ('binary-keys', '[keys,has("a\\u0000b"),.["a\\u0000b"],del(.["a\\u0000b"])]', '{"a\\u0000b":1,"a":2}'),
        ('string-cow', '. as $old|. += "x"|[$old,.,(.+.),(.*0),(.*(-1))]', '"é"'),
        ('arrays', '. as $old|. += [4,5]|. += .|[$old,.,(.[1:4]+.[0:2])]', '[1,2,3]'),
        ('invalid-values', '[try .a catch .,try .+1 catch .,try error({code:1}) catch .]', '"text"'),
        ('kinds', 'map([type,tostring])', '[null,false,true,0,"",[],{}]'),
        ('formatting', 'map([tojson,@text])', '[1e-300,9007199254740993,"é",{"a":1}]'),
        ('path-cow', '. as $old|setpath(["a",1,"x"];8)|[$old,.,getpath(["a",1,"x"])]', '{"a":[{"x":1},{"x":2}]}'),
        ('error-format', '[try (.["x"]=1) catch .,try .[1:3] catch .,try (.|implode) catch .]', '123'),
    ]


def cases():
    rows = [dict(id='immediate-and-errors', arguments=['primitive', '', '', '0'])]
    for index, value in enumerate([b'', b'a', b'ab', b'abc', b'abcd', b'abcde',
                                  b'a\0b', 'é🙂'.encode(), b'\xff', b'\xc0\xaf',
                                  b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'a\xe2\x82',
                                  b'\x80\xbf\xffZ', b'x' * 257]):
        rows.append(dict(id=f'string-{index}', arguments=['string', value.hex(), 'é\0z'.encode().hex(), '3']))
    for count in (-1, 0, 1, 9, 2147483647):
        rows.append(dict(id=f'repeat-{count}', arguments=['string', b'ab'.hex(), b'Z'.hex(), str(count)]))
    for count in (0, 1, 8, 9, 17, 65, 129):
        rows.append(dict(id=f'objects-{count}', arguments=['object', '{"a":1,"nested":[1,2]}', '', str(count)]))
    rows.append(dict(id='invalid-object-slot', arguments=['invalid-slot', '', '', '0']))
    rows.append(dict(id='release-shared-graph', arguments=['release', '', '', '0']))
    for index, (text, number, integer) in enumerate([
        ('short', '1.25', '7'), ('é\t\n', '-0.0', '-123'),
        ('x' * 2500, '1e308', '2147483647'), ('', '5e-324', '-2147483648'),
        ('infinity', 'inf', '0'), ('nan', 'nan', '0'),
    ]):
        encoded='repeat:2500:78' if text=='x' * 2500 else text.encode().hex()
        rows.append(dict(id=f'format-{index}', arguments=['format', encoded, number, integer]))
    for name, program, value in consumer_cases():
        rows.append(dict(id='consumer-' + name, arguments=['consumer', program.encode().hex(), value.encode().hex(), '0']))
    for index,(value,slice_spec,aliases) in enumerate([
        ('[0,1,2,3,4]', '{"start":null,"end":null}', 0),
        ('[0,1,2,3,4]', '{"start":1.5,"end":3.2}', 0),
        ('[0,1,2,3,4]', '{"start":-3.5,"end":-0.5}', 0),
        ('[0,1,2,3,4]', '{"start":-100,"end":100}', 0),
        ('[0,1,2,3,4]', '{"start":3,"end":1}', 0),
        ('[0,1,2,3,4]', '{"start":NaN,"end":NaN}', 0),
        ('[0,1,2,3,4]', '{"start":-Infinity,"end":Infinity}', 0),
        ('[0,1,2,3,4]', '{"start":Infinity,"end":-Infinity}', 0),
        ('[]', '{"start":null,"end":null}', 0),
        ('"aé🙂z"', '{"start":1,"end":3}', 0),
        ('[0,1,2,3,4]', '{"start":1,"end":4}', 1),
        ('[0,1,2]', '{"start":"bad","end":2}', 0),
        ('[0,1,2]', '{}', 0),
        ('{}', '{"start":0,"end":2}', 0),
        ('null', '{"start":0,"end":2}', 1),
    ]):
        rows.append(dict(id='slice-' + str(index),arguments=['slice',value.encode().hex(),slice_spec.encode().hex(),str(aliases)]))
    return rows
