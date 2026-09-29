"""Install the checked WAV component into the existing normal game selection."""
import argparse
from pathlib import Path
import runpy
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend

HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    headers.update({p.name:p for p in (game/'source').glob('*.h')})
    entries={**AUTHOR['RANGES'], 'allocate':(0xe2f0,0xe2f8),'free':(0xe2a0,0xe2a8),'create':(0x34f0,0x3543)}
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=AUTHOR['PE_SHA256'],module=None,entry_rva=lo,end_rva=hi,
        installer='install_wave_'+name) for name,(lo,hi) in entries.items()))
    headers.update({'native-image.h':output/'native-image.h','wave-runtime.h':package/'headers/wave-runtime.h',
        'setup-normal-runtime.c':HERE.parent/'dxball-audio-setup/normal-runtime.c',
        'audio-normal-runtime.c':HERE.parent/'dxball-audio/normal-runtime.c'})
    backend=wine_test_backend()
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={**backend['adapter_files'],'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},
        include_files={**headers,**backend['include_files']},remove_dependencies=['audio-bank'],
        **bind_dependencies(consumers={'shared-game':game,'shared-bank':dict(id='audio-bank',package=game)}),
        runner=Path(plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-wave-normal.dll',symbol='dx_normal_anchor',process=plan['program_driver']['process']),
        scope='Normal game execution with WAV loading, shared bank/setup and the preceding component selection; previous observations retained.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'Native file loading, allocator, Win32/DirectDraw/DirectSound and remaining application functions are retained. This mixed executable is not a standalone portable game.',
            'Record allocation and free events establish live/retired identities; slot equality never reanimates a retired record. Typed bank callers still require live records when dereferenced.',
            'The sound-bank caller-history and display output premises of the preceding selection remain: complete successful GetStatus and GetCaps outputs. WAV metadata query failures preserve record bytes.',
            'Local original/C comparisons independently cover loader failure, allocation, parser partial output, buffer contents and shared-root callbacks. Normal execution supplies additional real-consumer evidence.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('package','game','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
