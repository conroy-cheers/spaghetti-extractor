"""Select PCX loading in the existing counted-input normal-game comparison."""
import argparse
import importlib.util
from pathlib import Path

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package, revise_comparison_package
from spaghetti_extractor.util import sha256_file

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pcx_preparation', HERE/'prepare.py')
preparation = importlib.util.module_from_spec(spec); spec.loader.exec_module(preparation)
RANGES = preparation.RANGES


def prepare(package, game, output):
    output.mkdir(parents=True, exist_ok=False)
    game_plan, _ = load_comparison_package(game)
    original = package/'runtime/DXBall.exe'
    includes = {p.relative_to(game/'headers').as_posix(): p for p in (game/'headers').rglob('*') if p.is_file()}
    header = (game/'headers/native-image.h').read_text()
    for name, (lo, hi) in RANGES.items():
        header += '\n'+native_entry_header(original=original, expected_sha256=sha256_file(original), module=None,
            entry_rva=lo, end_rva=hi, installer='install_pcx_'+name)
    (output/'native-image.h').write_text(header)
    includes.update({'native-image.h': output/'native-image.h', 'pcx-runtime.h': HERE/'pcx-runtime.h',
        'flow-normal-runtime.c': HERE.parent/'dxball-game-flow/normal-runtime.c'})
    revise_comparison_package(package=package, output=output/'package',
        adapter_files={'normal-runtime.c': HERE/'normal-runtime.c', 'bridge.c': package/'adapters/bridge.c'},
        include_files=includes, **bind_dependencies(consumers={'game-consumer': game}),
        runner=Path(game_plan['tools']['runner']['path']),
        runtime_files={p.name: p for p in (game/'runtime').iterdir() if p.is_file()},
        cases=game_plan['cases'], observation_fields=['exit_code', 'stdout', 'stderr', 'state'],
        program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe', library='dx-pcx-normal.dll',
            symbol='dx_normal_anchor', process=dict(exit_codes=[0], drive='P')),
        scope='Normal DX-Ball scenes with selected C PCX images/palettes, game control and sprite network; actual CRT/DirectDraw and counted input.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(), *game_plan['assumptions'],
            'PCX file views retain the actual CRT buffer, cursor and count across reads and refill/seek/close. Closed wrapper storage is freed, and buffers are never synthesized from pointer identities.',
            'The graphics adapter preserves the full native description across Lock retries using an owned lease; Unlock releases that descriptor and ends the pixel view lifetime.',
            'After each observed image, the original/source observers take one additional surface lock to hash visible pixel bytes. The untouched original has no such read lock. This relies on a quiescent eight-bit surface and does not prove observer transparency beyond the recorded control/output observations.',
            'Retain up to 24 image/palette records, including names, arguments, surface identities, dimensions and 64-bit pixel/palette hashes. Local comparisons retain complete pixel/palette bytes; live hashes are practical observations rather than collision-free proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'game', 'output'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); prepare(args.package.resolve(), args.game.resolve(), args.output.resolve())
