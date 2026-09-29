"""Additional real compiler/interpreter workloads for the builtin boundary."""
import json
from pathlib import Path


def cases():
    rows=json.loads((Path(__file__).resolve().parent.parent/'jq-compiler-ir/cases.json').read_text())
    examples=[
        ('registry','builtins|sort',None),
        ('numbers','[.[0]+.[1],.[0]-.[1],.[0]*.[1],.[0]/.[1],.[0]%.[1],-.[0]]',[19,3]),
        ('strings','[.[0]+.[1],.[0]*3,.[0]/.[1]]',['a,b,é',',']),
        ('arrays','[.[0]+.[1],.[0]-.[1]]',[[1,2,1,{'a':1}],[1]]),
        ('objects','[.[0]+.[1],.[0]*.[1]]',[{'a':{'x':1},'b':2},{'a':{'y':2},'c':3}]),
        ('null','[. + null,null + .]',[1,2]),
        ('zero-divide','try (./0) catch .',7),
        ('zero-mod','try (.%0) catch .',7),
        ('mod-fraction','[5.9%2.1,-5.9%2.1,5.9%(-2.1)]',None),
        ('binary-errors','[try (. + 1) catch .,try (. - 1) catch .,try (. * 1) catch .,try (. / 1) catch .,try (. % 1) catch .]',{}),
        ('binary-order','[.[0]==.[1],.[0]!=.[1],.[0]<.[1],.[0]<=.[1],.[0]>.[1],.[0]>=.[1]]',[{'a':[1,2]},{'a':[1,3]}]),
        ('lengths','map([type,(try length catch .),(try utf8bytelength catch .)])',[None,False,{},[],123,-7,'é🙂\u0000']),
        ('conversions','map([try tonumber catch .,tostring,try toboolean catch .])',['123','1e4','false','true','bad','null',True,None,[],{}]),
        ('contains','.[1] as $b|.[0]|contains($b)',[[1,2,3],[1,3]]),
        ('prefix','[startswith("é"),endswith("🙂"),startswith(""),endswith("")]', 'éabc🙂'),
        ('encode-json','[tojson,(@json)]',{'é':[1,True,None]}),
        ('decode-json','[fromjson,try ("{"|fromjson) catch .]','{"a":[1,2]}'),
        ('formats','[(@text),(@html),(@uri),(@urid),(@sh),(@base64),(@base64|@base64d)]','é <>&\'"/+%20\u0000'),
        ('csv','[@csv,@tsv]',[None,True,1,'a,"b\t\n','é']),
        ('base64','map([@base64,(@base64|@base64d)])',['','a','ab','abc','é🙂','a\u0000b']),
        ('bad-formats','[try @unknown catch .,try @csv catch .,try @base64d catch .]',{'x':1}),
        ('bad-base64','map(try @base64d catch .)',['?','a','abc=','YWJj=','ab!cd']),
        ('keys','[keys,keys_unsorted,has("a"),has("missing")]',{'z':0,'a':1,'é':2}),
        ('sorting','[sort,unique,min,max,reverse]',[3,1,3,2]),
        ('grouping','[sort_by(.a),group_by(.a),unique_by(.a),min_by(.a),max_by(.a)]',[{'a':2,'i':0},{'a':1,'i':1},{'a':2,'i':2}]),
        ('search','[bsearch(1),bsearch(3),bsearch(4),bsearch(9)]',[1,2,3,7]),
        ('unicode','[explode,(explode|implode),split("é"),indices("é")]','aéé🙂'),
        ('trim','[trim,ltrim,rtrim]',' \t\r\naé\u00a0'),
        ('paths','[getpath(["a",0]),setpath(["a",1];7),delpaths([["a",0]])]',{'a':[1,2]}),
        ('nonfinite','[(nan|isnan),(infinite|isinfinite),(1|isnormal),(0|isnormal)]',None),
        ('errors','try error({a:1}) catch .',None),
        ('input','[inputs]',None,[1,{'a':2}]),
        ('debug','debug|stderr',{'a':1}),
        ('halt','halt_error(4)',{'message':'halt'}),
        ('calendar','[gmtime,(gmtime|mktime),strftime("%Y-%m-%dT%H:%M:%SZ")]',1709210096),
        ('calendar-epoch','[gmtime,(gmtime|mktime)]',0),
        ('calendar-negative','[try gmtime catch .,try strftime("%Y-%m-%d") catch .]',-1),
        ('calendar-future','[try gmtime catch .]',2147483648),
        ('calendar-boundaries','map(try gmtime catch .)',[-0.5,0.5,2147483647,2147483647.5,2147483648]),
        ('mktime-boundaries','map(try mktime catch .)',[[1969,11,31,23,59,59],[1970,0,1,0,0,0],[2038,0,19,3,14,7],[2038,0,19,3,14,8]]),
        ('calendar-fields','strftime("%Y-%m-%d %H:%M:%S %w %j")',[2024,1,29,12,34,56,0,0]),
        ('date-parse','strptime("%Y-%m-%dT%H:%M:%SZ")','2024-02-29T12:34:56Z'),
        ('date-invalid','try strptime("%Y-%m-%d") catch .','not-a-date'),
        ('date-junk','try strptime("%Y-%m-%d") catch .','2024-02-29 extra'),
        ('date-errors','[try gmtime catch .,try mktime catch .,try strftime("%Y") catch .]',{}),
        ('feature-errors','[try exp10 catch .,try gamma catch .,try significand catch .,try lgamma_r catch .,try scalb(1;2) catch .,try drem(3;2) catch .]',2),
        ('math','[sqrt,sin,cos,tan,exp,log,floor,ceil,round,trunc,fabs]',0.5),
        ('math-binary','[pow(2;3),atan2(1;2),hypot(3;4),fmod(7;3),remainder(7;3),copysign(3;-1),fma(2;3;4)]',None),
        ('math-errors','[try sqrt catch .,try pow(1;"x") catch .]',{}),
        ('now-sanity','now|type',None),
        ('regex-captures','match("(?<word>é+)([0-9]+)";"g")','xéé12 é3'),
        ('regex-empty','[match("";"g")]', 'é🙂'),
        ('regex-test','[test("a.*z"),test("^é";"i"),test("\\u0000")]', 'éa\u0000z'),
        ('regex-sub','[sub("(?<a>[a-z]+)";"X\\(.a)"),gsub("[0-9]";"!")]', 'abc12def3'),
        ('regex-split','[splits("[,;]+"),capture("(?<a>[a-z]+)(?<b>[0-9]+)")]', 'abc12,def3;z4'),
        ('regex-errors','[try match("(") catch .,try match(2) catch .,try match("a";"bad") catch .]','abc'),
    ]
    for name,program,value,*callbacks in examples:
        rows.append(dict(id='builtin-'+name,arguments=[program.encode().hex(),
            json.dumps(value,ensure_ascii=False).encode().hex(),
            json.dumps(callbacks[0] if callbacks else []).encode().hex(),'100','7b7d']))
    return rows


if __name__=='__main__':
    print(json.dumps(cases(),indent=2,ensure_ascii=False))
