"""Expose the assembled source selection's unresolved C bindings, without stubs.

This target recipe is a linker census, not executable or reachability evidence.
Run the existing source-project make first so all selected objects are current.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from spaghetti_extractor.candidate.source_export_bindings import load_source_export


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(project,output,ld,nm,assembly_libraries=()):
    manifest=load_source_export(project/'lifted')
    if manifest['target_id']!='dxball':raise ValueError('requires the DX-Ball source assembly recipe')
    output.mkdir(parents=True,exist_ok=False)
    objects=[project/'build'/(cid+'.o') for cid in sorted(manifest['components'])]
    archive=project/'lifted/liblifted.a'
    for p in [*objects,archive,*assembly_libraries]:
        if not p.is_file():raise ValueError('build the selected source and bridge first: '+str(p))
    command=[ld,'-r',*[str(p) for p in objects],'--whole-archive',str(archive),*[str(p) for p in assembly_libraries],'--no-whole-archive','-o',str(output/'source-network.o')]
    ran=subprocess.run(command,capture_output=True,text=True)
    (output/'link.stdout').write_text(ran.stdout);(output/'link.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('component bridge/link collision; inspect link.stderr')
    text=subprocess.check_output([nm,'-u',str(output/'source-network.o')],text=True)
    (output/'unresolved.txt').write_text(text)
    symbols={line.split()[-1] for line in text.splitlines() if line.strip()}
    bindings={}
    for cid,unit in manifest['components'].items():
        for reference in unit['comparison_binding_references']:
            for name,definition in (reference['service_bridge'] or {}).get('adapters',{}).items():
                symbol=definition.get('symbol')
                if symbol not in symbols:continue
                row={'component':cid,'service':name}
                if row not in bindings.setdefault(symbol,[]):bindings[symbol].append(row)
    # Entry counters are fixture observation hooks; their names are checked by
    # inspecting each bridge, not treated as application services or definitions.
    counters={s for s in symbols-bindings.keys() if s.endswith('_enter') and any(
        s+'(' in (project/'bridges'/cid/'bridge.c').read_text() for cid in manifest['components'])}
    scope='Relocatable link of all exported operations and their existing bridges. No main, service implementations, data initialization, platform backend, or reachability claim.'
    if assembly_libraries:
        scope='Relocatable link of all exported operations, existing bridges and explicitly supplied program assembly libraries. No desktop entry, complete backend, reachability or equivalence claim.'
    result={'authorizing':False,'scope':scope,
        'source_export_sha256':sha(project/'lifted/source-export.json'),'components':len(manifest['components']),
        'operations':sum(len(u['operation_symbols']) for u in manifest['components'].values()),
        'command':command,'inputs':{str(p.relative_to(project)):sha(p) for p in [*objects,archive,*assembly_libraries]},
        'unresolved_count':len(symbols),'service_bindings':dict(sorted(bindings.items())),
        'observation_hooks':sorted(counters),'runtime_or_unclassified':sorted(symbols-bindings.keys()-counters)}
    (output/'inventory.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:result[k] for k in ['components','operations','unresolved_count']},sort_keys=True))
    print(str(len(bindings))+' declared service binding symbols, '+str(len(counters))+' entry observation hooks, '+str(len(result['runtime_or_unclassified']))+' runtime or unclassified symbols')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('project',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--ld',default='ld');p.add_argument('--nm',default='nm')
    p.add_argument('--assembly-library',type=Path,action='append',default=[])
    a=p.parse_args();audit(a.project.resolve(),a.output.resolve(),a.ld,a.nm,[v.resolve() for v in a.assembly_library])
