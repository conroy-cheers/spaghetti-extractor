"""Select the music controller in the retained normal program composition."""
import argparse
from pathlib import Path
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend

HERE=Path(__file__).resolve().parent

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    headers.update({p.name:p for p in (game/'source').glob('*.h')})
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+(package/'headers/native-image.h').read_text())
    headers.update({'native-image.h':output/'native-image.h','music-runtime.h':package/'headers/music-runtime.h',
        'reader-normal-runtime.c':HERE.parent/'dxball-file-reader/normal-runtime.c',
        'power-normal-runtime.c':HERE.parent/'dxball-powerups/normal-runtime.c'})
    backend=wine_test_backend()
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={**backend['adapter_files'],'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},
        include_files={**headers,**backend['include_files']},**bind_dependencies(consumers={'shared-game':game}),
        runner=Path(plan['tools']['runner']['path']),runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-music-normal.dll',symbol='dx_normal_anchor',process=plan['program_driver']['process']),
        scope='Normal game with music controller, actual retained MDS library services and preceding 39 selected components; all prior observations retained.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'MDS loading/streaming and WinMM MIDI callbacks remain native. Native successful allocation creates tracked eight-byte controller records; retired records are not read back.',
            'The normal observer compares outer controller calls, root identity/live/playing state and allocation/disposal counts; local cases independently cover service arguments and callback root changes.',
            *plan['assumptions']])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('package','game','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
