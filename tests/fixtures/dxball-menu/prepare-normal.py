"""Select main menu operations through the existing counted normal-game workload."""
import argparse
import importlib.util
from pathlib import Path

from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package, revise_comparison_package
from spaghetti_extractor.util import sha256_file

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('menu_preparation', HERE/'prepare.py')
preparation = importlib.util.module_from_spec(spec); spec.loader.exec_module(preparation)


def prepare(package, game, output):
    output.mkdir(parents=True, exist_ok=False); game_plan, _ = load_comparison_package(game)
    includes = {p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    original = package/'runtime/DXBall.exe'; header = (game/'headers/native-image.h').read_text()
    for name,(lo,hi) in preparation.RANGES.items():
        header += '\n'+native_entry_header(original=original,expected_sha256=sha256_file(original),module=None,
            entry_rva=lo,end_rva=hi,installer='install_menu_'+name)
    (output/'native-image.h').write_text(header)
    includes.update({'native-image.h':output/'native-image.h','menu-runtime.h':package/'headers/menu-runtime.h',
        'menu-common.h':package/'headers/menu-common.h','menu-native.h':HERE/'menu-native.h',
        'scene-normal-runtime.c':preparation.SCENE/'normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},
        include_files=includes,refine_requirements={'scene-consumer':game},
        runner=Path(game_plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},
        cases=game_plan['cases'],observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-menu-normal.dll',
            symbol='dx_normal_anchor',process=dict(exit_codes=[0],drive='P')),
        scope='Normal DX-Ball main menu with existing C scene/animation/graphics/assets/frame network and actual platform services.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),*game_plan['assumptions'],
            'Retain 32 outer menu operation records including input/state, dot and offset backing, pixels and palette storage. Absolute clock inputs remain diagnostics; all resulting state and pixel effects compare. Additional read locks assume quiescent eight-bit surfaces. The counted-input controller is unchanged. Bounded observations do not establish full playthrough or audio equivalence.'])


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'): parser.add_argument(name,type=Path)
    args=parser.parse_args(); prepare(args.package.resolve(),args.game.resolve(),args.output.resolve())
