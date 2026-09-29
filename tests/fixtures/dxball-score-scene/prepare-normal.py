"""Install the score-screen bodies into the existing normal-game consumer."""
import argparse
import importlib.util
from pathlib import Path

from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package
from spaghetti_extractor.util import sha256_file

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('screen_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def prepare(package,game,menu_game,output):
    output.mkdir(parents=True,exist_ok=False);game_plan,_=load_comparison_package(game)
    includes={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name:p for p in (game/'source').glob('*.h')})
    header=(game/'headers/native-image.h').read_text();original=package/'runtime/DXBall.exe'
    for name,(lo,hi) in preparation.RANGES.items():
        header+='\n'+native_entry_header(original=original,expected_sha256=sha256_file(original),module=None,
            entry_rva=lo,end_rva=hi,installer='install_screen_'+name)
    (output/'native-image.h').write_text(header)
    includes.update({'native-image.h':output/'native-image.h','screen-runtime.h':package/'headers/screen-runtime.h',
        'screen-common.h':package/'headers/screen-common.h','screen-native.h':HERE/'screen-native.h',
        'scores-normal-runtime.c':preparation.SCORES/'normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        refine_requirements={'table-consumer':game,'menu-consumer':menu_game},
        runner=Path(game_plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=game_plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-screen-normal.dll',symbol='dx_normal_anchor',process=dict(exit_codes=[0],drive='P')),
        scope='Normal DX-Ball with all selected C components and score-screen entries installed; the retained counted workload does not reach game over.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),*game_plan['assumptions'],
            'Normal game startup, title, menu and initial gameplay exercise the existing network. The score-screen functions remain installed but are not reached by this workload; their exercised evidence is the separate local native consumer. Up to 64 outer screen records retain name/table bytes, state and pixels if invoked. Absolute clock values are diagnostic; effects remain observed.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','menu_game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.menu_game.resolve(),a.output.resolve())
