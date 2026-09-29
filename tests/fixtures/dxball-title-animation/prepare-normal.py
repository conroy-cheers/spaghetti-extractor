"""Select the authored animations within the counted normal-game workload."""
import argparse
import importlib.util
from pathlib import Path

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package, revise_comparison_package
from spaghetti_extractor.util import sha256_file

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('title_preparation', HERE/'prepare.py')
preparation = importlib.util.module_from_spec(spec); spec.loader.exec_module(preparation)


def prepare(package, game, output):
    output.mkdir(parents=True, exist_ok=False); game_plan, _ = load_comparison_package(game)
    includes = {p.relative_to(game/'headers').as_posix(): p for p in (game/'headers').rglob('*') if p.is_file()}
    original = package/'runtime/DXBall.exe'; header = (game/'headers/native-image.h').read_text()
    for name, (lo, hi) in preparation.RANGES.items():
        header += '\n'+native_entry_header(original=original, expected_sha256=sha256_file(original), module=None,
            entry_rva=lo, end_rva=hi, installer='install_title_'+name)
    (output/'native-image.h').write_text(header)
    includes.update({'native-image.h': output/'native-image.h', 'title-runtime.h': HERE/'title-runtime.h',
        'title-native.h': HERE/'title-native.h', 'pcx-normal-runtime.c': HERE.parent/'dxball-pcx/normal-runtime.c'})
    revise_comparison_package(package=package, output=output/'package',
        adapter_files={'normal-runtime.c': HERE/'normal-runtime.c', 'bridge.c': package/'adapters/bridge.c'},
        include_files=includes, **bind_dependencies(consumers={'game-consumer': game}),
        runner=Path(game_plan['tools']['runner']['path']),
        runtime_files={p.name: p for p in (game/'runtime').iterdir() if p.is_file()},
        cases=game_plan['cases'], observation_fields=['exit_code', 'stdout', 'stderr', 'state'],
        program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe', library='dx-title-normal.dll',
            symbol='dx_normal_anchor', process=dict(exit_codes=[0], drive='P')),
        scope='Normal DX-Ball with C title animations, shared sprite/frame/PCX network, actual graphics and counted inputs.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(), *game_plan['assumptions'],
            'The title adapter borrows the actual initialized message and sine table for the process lifetime; no buffer is invented from a pointer identity.',
            'Retain 24 post-operation title records including counters, offsets, palette state and visible back/display surface hashes. Each record adds read locks on both instrumented sides, assuming quiescent eight-bit surfaces. This is practical bounded observation, not proof of arbitrary frame/audio equivalence or full observer transparency.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'game', 'output'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); prepare(args.package.resolve(), args.game.resolve(), args.output.resolve())
