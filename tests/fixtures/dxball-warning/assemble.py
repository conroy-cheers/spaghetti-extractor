"""Add warning and real portable caller-history consumers to the existing source project."""
import argparse
import json
from pathlib import Path
import re
import runpy
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))
FIELDS=['mode','incoming_ebp_esi','entry_words','queue','queue_within_grid','queue_address','explosion','warning_calls','drawing_calls']

def history_stubs():
    implemented=set(re.findall(r'^(?:void|uint32_t) ((?:play|paddle|pickup|particle|warning)_\w+)\(', (HERE/'history-runtime.c').read_text(),re.MULTILINE))
    empty={'play_'+n for n in ['refresh_score','move_paddle','move_balls','move_shots','move_pickups','move_trails',
        'wait','restore_damage','advance_brick_effects','draw_explosions','draw_last_brick','present','advance_stage']}
    empty|={'warning_stop_sound','warning_play_sound','warning_loop_sound'}
    text='/* Controlled service boundary; unexpected calls fail explicitly. */\n'
    for prefix,folder in [('play','dxball-gameplay'),('paddle','dxball-paddle'),('pickup','dxball-pickups'),('particle','dxball-particles'),('warning','dxball-warning')]:
        api=runpy.run_path(str(HERE.parent/folder/'prepare.py'))
        for name,params in api['PARAMETERS'].items():
            symbol=prefix+'_'+name
            if symbol in implemented:continue
            result=api['RESULTS'][name];ctype=api['C_TYPES'][result]
            args=[('u','void *'),*[(n,api['C_TYPES'][t]) for n,t in params]]
            text+=ctype+' '+symbol+'('+','.join(t+' '+n for n,t in args)+') { '
            text+=''.join('(void)'+n+';' for n,_ in args)
            if symbol not in empty:text+='REQUIRE(0);'
            if result!='unit':text+='return 0;'
            text+=' }\n'
    return text

def assemble(project,comparison,provenance):
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    if not (project/'check-bricks.py').is_file():raise ValueError('requires the existing DX-Ball source project')
    render=render_source_service_bridges(project/'lifted',bindings={'last-brick-warning':AUTHOR['bridge_spec']()})
    write('bridges/last-brick-warning/comparison-service-bridge.h',render['last-brick-warning'][0])
    write('bridges/last-brick-warning/bridge.c',AUTHOR['bridge']())
    for name in ['warning-state.h','history.h','runtime.c','history-runtime.c']:
        write('common/'+('warning-runtime.c' if name=='runtime.c' else 'warning-history-runtime.c' if name=='history-runtime.c' else name),(HERE/name).read_text())
    write('common/warning-runtime.h',AUTHOR['runtime_header']());write('common/history-stubs.h',history_stubs())
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='last-brick-warning':raise ValueError('requires matching warning comparison')
    native=json.loads(provenance.read_text())
    if native['original_sha256']!=AUTHOR['PE_SHA256'] or native['kind']!='native-warning-provenance-experiment':raise ValueError('requires retained pinned native frame traces')
    review=runpy.run_path(str(HERE/'probe-frame.py'))['review_result'](native)
    if review['native_cases']!=8:raise ValueError('requires all retained producers')
    direct=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    history=[dict(id=c['id'],arguments=list(map(str,[c['observation']['mode'],*c['observation']['incoming_ebp_esi']])),
        expected={k:c['observation'][k] for k in FIELDS}) for c in native['cases']]
    for name,cases in [('warning',direct),('warning-history',history)]:
        write(name+'-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
        write('check-'+name+'.py',f'''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/{(name+'-cases.json')!r}).read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/{name!r}),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': '+json.dumps(dict(expected=case['expected'],observed=observed)))
print(str(len(cases))+' {name} cases match retained original x86 observations')
''')
    marker='# Last-brick warning and historical input consumers\n';base,found,tail=(project/'Makefile').read_text().partition(marker)
    suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: warning warning-history
warning: build/warning-runtime.o build/last-brick-warning.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/warning-runtime.o build/last-brick-warning.o lifted/liblifted.a -o $@
warning-history: build/warning-history-runtime.o build/last-brick-warning.o build/gameplay-frame.o build/paddle-control.o build/pickup-lifecycle.o build/particle-lifecycle.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/warning-runtime.o: common/warning-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/warning-history-runtime.o: common/warning-history-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -MMD -MP -c $< -o $@
build/last-brick-warning.o: bridges/last-brick-warning/bridge.c bridges/last-brick-warning/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/last-brick-warning -Ilifted/components/last-brick-warning/sources/generated -Ilifted/components/last-brick-warning/sources/source -Ilifted/components/last-brick-warning/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    note='\nWarning preparation/drawing: `python check-warning.py`. Historical inputs through actual lifted frame, paddle, pickup, particle and warning code: `python check-warning-history.py`. Both accept `--runner`; the latter replays retained original x86 producer traces with explicit original-environment register inputs. Rendering/audio and queue requests remain controlled services.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)
    write('warning-history-native.json',json.dumps(native,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison','provenance'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve(),a.provenance.resolve())
