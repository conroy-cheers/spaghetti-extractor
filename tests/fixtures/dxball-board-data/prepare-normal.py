"""Exercise board storage through existing actual startup and gameplay callers."""
import argparse
import importlib.util
from pathlib import Path

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package
from spaghetti_extractor.util import sha256_file

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('board_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);game_plan,_=load_comparison_package(game)
    includes={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name:p for p in (game/'source').glob('*.h')})
    original=package/'runtime/DXBall.exe';header=(game/'headers/native-image.h').read_text()
    for name,(lo,hi) in preparation.RANGES.items():
        header+='\n'+native_entry_header(original=original,expected_sha256=sha256_file(original),module=None,
            entry_rva=lo,end_rva=hi,installer='install_board_'+name)
    (output/'native-image.h').write_text(header)
    includes.update({'native-image.h':output/'native-image.h','board-runtime.h':package/'headers/board-runtime.h',
        'screen-normal-runtime.c':HERE.parent/'dxball-score-scene/normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        **bind_dependencies(consumers={'game-consumer':game}),runner=Path(game_plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=game_plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-board-normal.dll',symbol='dx_normal_anchor',process=dict(exit_codes=[0],drive='P')),
        scope='Actual board collection startup, board selection and tile mapping in normal DX-Ball with the existing C component network.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),*game_plan['assumptions'],
            'Real CRT services use the actual filename and full board byte backing. Closed file tokens preserve native equality without permission to access closed streams. Retain up to 32 complete current/collection records and 4096 sprite-map results. The counted-input controller is unchanged; editor saves and full game completion are not exercised.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
