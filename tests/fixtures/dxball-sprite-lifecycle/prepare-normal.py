"""Select lifecycle, loading and drawing in the existing normal-game workflow."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
FONT = HERE.parent/'dxball-sprite-font'
DRAWING = HERE.parent/'dxball-sprite-drawing'
sys.path.insert(0, str(FONT))
spec = importlib.util.spec_from_file_location('font_normal_preparation', FONT/'prepare-normal.py')
normal = importlib.util.module_from_spec(spec); spec.loader.exec_module(normal)
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import revise_comparison_package
from spaghetti_extractor.util import sha256_file


def prepare(package, drawing_package, assets, output):
    normal.prepare(package, assets, output/'driver')
    base = output/'driver/package'
    environment = native_environment()
    subprocess.run([str(environment['compiler']), str(HERE/'probe-lifecycle.c'), '-o', str(output/'driver/probe.exe'),
                    '-luser32'], check=True)
    runner = output/'gui-runner'
    runner.write_text((output/'driver/gui-runner').read_text().replace('timeout=24', 'timeout=48'))
    runner.chmod(0o755)
    includes = {p.relative_to(base/'headers').as_posix(): p for p in (base/'headers').rglob('*') if p.is_file()}
    header = (base/'headers/native-image.h').read_text()
    original = package/'runtime/DXBall.exe'
    for name, lo, hi in (('sprite_destination', 0xbd60, 0xbd6a), ('sprite_transparent', 0xbd90, 0xbdcf),
                         ('sprite_opaque', 0xbdd0, 0xbe0f)):
        header += '\n'+native_entry_header(original=original, expected_sha256=sha256_file(original), module=None,
            entry_rva=lo, end_rva=hi, installer='install_'+name)
    (output/'native-image.h').write_text(header)
    includes.update({'native-image.h': output/'native-image.h', 'metrics-normal-runtime.c': FONT/'normal-runtime.c',
        'drawing-normal-runtime.c': DRAWING/'normal-runtime.c', 'drawing-runtime.h': DRAWING/'drawing-runtime.h'})
    binding = bind_dependencies(consumers={'drawing-consumer': drawing_package})
    binding['requirements'] += json.loads((base/'comparison-plan.json').read_text())['requirements']
    revise_comparison_package(package=base, output=output/'package',
        adapter_files={'normal-runtime.c': HERE/'normal-runtime.c', 'bridge.c': base/'adapters/bridge.c'},
        include_files=includes, **binding, runner=runner,
        runtime_files={p.name: (output/'driver/probe.exe' if p.name == 'probe.exe' else p)
                       for p in (base/'runtime').iterdir() if p.is_file()},
        scope='Normal DX-Ball execution with selected C capture/restoration, asset loading, sprite/text drawing and cleanup using actual native services.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'The live adapter retains actual native allocations, filenames, object identities and DirectDraw interfaces. Descriptor fields outside the flags accepted by these APIs are not observed.',
            'Reload uses the actual bank name address; ordinary C loader/file calls preserve its alias to shared metadata.',
            'Observe the first 24 lifecycle/loader calls, 128 outer graphics calls and 32 metric calls. Entry counts are diagnostics. All selected operations run synchronously on the game thread.',
            'The external controller reads the pinned image to wait for menu assets, holds a normal mouse-button message until the game transition, and observes capture initialization before close. It never writes application memory.',
            'Graphics destination identities are assigned at externally observed selection, preserving equality without depending on private transport view discovery. Address reuse lifetimes are not separately observed by this probe.',
            'Original startup/TLS and remaining game/platform services remain native. Readiness-based input still uses wall-clock polling and does not establish frame, audio or whole-playthrough equivalence.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'drawing_package', 'assets', 'output'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); prepare(*(getattr(args, name).resolve() for name in ('package', 'drawing_package', 'assets', 'output')))
