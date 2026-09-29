"""Select the checked region component through the existing editor workload."""
import argparse
import importlib.util
from pathlib import Path

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package, revise_comparison_package

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('regions_preparation', HERE/'prepare.py')
preparation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparation)


def prepare(package, game, output):
    output.mkdir(parents=True, exist_ok=False)
    game_plan, _ = load_comparison_package(game)
    includes = {p.relative_to(game/'headers').as_posix(): p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name: p for p in (game/'source').glob('*.h')})
    header = (game/'headers/native-image.h').read_text()
    for name, (lo, hi) in preparation.RANGES.items():
        header += '\n'+native_entry_header(original=package/'runtime/DXBall.exe', expected_sha256=preparation.PE_SHA256,
            module=None, entry_rva=lo, end_rva=hi, installer='install_regions_'+name)
    (output/'native-image.h').write_text(header)
    includes.update({'native-image.h': output/'native-image.h', 'regions-runtime.h': package/'headers/regions-runtime.h',
        'damage-normal-runtime.c': HERE.parent/'dxball-damage/normal-runtime.c'})
    revise_comparison_package(package=package, output=output/'package',
        adapter_files={'normal-runtime.c': HERE/'normal-runtime.c', 'bridge.c': package/'adapters/bridge.c'}, include_files=includes,
        **bind_dependencies(consumers={'game-consumer': game}), runner=Path(game_plan['tools']['runner']['path']),
        runtime_files={p.name: p for p in (game/'runtime').iterdir() if p.is_file()}, cases=game_plan['cases'],
        observation_fields=['exit_code', 'stdout', 'stderr', 'state'],
        program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe', library='dx-regions-normal.dll',
            symbol='dx_normal_anchor', process=game_plan['program_driver']['process']),
        scope='Real editor clear/save/close with the region table and existing nineteen-component network selected in C.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'The borrowed table is bound to the existing live editor backing. The surrounding consumer uses actual graphics, files, clocks and native platform services.',
            'Retain all three entry kinds, copied arguments, results, count and all 25 records for up to 128 calls. Preserve preceding editor, board, rendering, damage and saved-file observations.',
            'The counted editor workload is an integration check. Local direct and connected editor cases supply coverage without full game execution; complete gameplay and portable platform backends remain open.'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'game', 'output'):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    prepare(a.package.resolve(), a.game.resolve(), a.output.resolve())
