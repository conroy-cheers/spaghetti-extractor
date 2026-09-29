"""Source navigation for a comparison workspace, without compiler or proof claims.

These are lexical definition candidates and call spellings in selected files.
Preprocessing, linkage and indirect dispatch still require C/compiler inspection.
"""
from __future__ import annotations

from pathlib import Path
import re

from ..components.comparison_package import package_file
from ..util import sha256_file


_NAME = r'[A-Za-z_][A-Za-z0-9_]*'
_COMMENTS_AND_LITERALS = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
_CALL = re.compile(r'\b('+_NAME+r'(?:\s*(?:->|\.)\s*'+_NAME+r')*)\s*\(')
_KEYWORDS = {'if','for','while','switch','sizeof','_Alignof','alignof','return',
             '_Static_assert','static_assert','__attribute__','__declspec','typeof','__typeof__'}


def _closing(text: str, start: int, opening: str, closing: str) -> int | None:
    depth=0
    for match in re.finditer('['+re.escape(opening+closing)+']',text[start:]):
        depth += 1 if match[0]==opening else -1
        if depth==0:return start+match.end()
    return None


class _SourceIndex:
    def __init__(self, root: Path, names: set[str]):
        # Preserve separators as well as lines: return/**/helper() still calls helper.
        self.sources={name:_COMMENTS_AND_LITERALS.sub(lambda m:re.sub(r'[^\n]',' ',m[0]),
                      package_file(root,name).read_text(errors='replace'))
                      for name in sorted(names)}
        self.fingerprints={name:sha256_file(package_file(root,name)) for name in sorted(names)}
        self.cache={}

    def definitions(self, symbol: str) -> list[dict]:
        if symbol in self.cache:return self.cache[symbol]
        found=[]
        if re.fullmatch(_NAME,symbol):
            pattern=re.compile(r'\b'+re.escape(symbol)+r'\s*\(')
            for name,text in self.sources.items():
                for match in pattern.finditer(text):
                    end=_closing(text,match.end()-1,'(',')')
                    if end is None:continue
                    body=end+len(text[end:])-len(text[end:].lstrip())
                    if body==len(text) or text[body]!='{':continue
                    stop=_closing(text,body,'{','}')
                    if stop is None:continue
                    calls=[]
                    seen=set()
                    for call in _CALL.finditer(text,body+1,stop-1):
                        expression=re.sub(r'\s+','',call[1])
                        if expression in _KEYWORDS or expression in seen:continue
                        seen.add(expression)
                        calls.append(dict(expression=expression,line=text.count('\n',0,call.start())+1))
                    found.append(dict(path=name,line=text.count('\n',0,match.start())+1,
                                      end_line=text.count('\n',0,stop)+1,calls=calls))
        self.cache[symbol]=found
        return found

    def describe(self, symbol: str) -> dict:
        definitions=[]
        for row in self.definitions(symbol):
            calls=[{**call,'definitions':[{k:r[k] for k in ('path','line','end_line')}
                    for r in self.definitions(call['expression'])]} for call in row['calls']]
            definitions.append({**row,'calls':calls})
        return dict(symbol=symbol,definitions=definitions)


def workspace_source_navigation(root: Path, units: list[dict]) -> dict[str,str]:
    """Attach navigation to existing authoring views and return scanned file hashes."""
    names=set()
    for unit in units:
        names.update(unit['sources']+unit['adapters'])
        for directory in unit['include_directories']:
            for path in (root/directory).rglob('*'):
                if path.is_file() and path.suffix in ('.c','.h'):
                    names.add(path.relative_to(root).as_posix())
    index=_SourceIndex(root,names)
    for unit in units:
        bridge=unit['service_bridge'] or {}
        unit['source_navigation']=dict(
            operations={name:index.describe(symbol) for name,symbol in unit['operation_symbols'].items()},
            services={name:index.describe(adapter['symbol']) for name,adapter in bridge.get('adapters',{}).items()})
    return index.fingerprints
