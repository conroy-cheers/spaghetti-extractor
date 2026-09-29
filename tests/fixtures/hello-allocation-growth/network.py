"""Replace the quoting fixture's simulated growth with complete authored xpalloc."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import time

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.util import sha256_file, write_json
from prepare import prepare as prepare_growth, ASSUMPTIONS as GROWTH_ASSUMPTIONS
from release_declarations import interface as release_interface

HERE = Path(__file__).resolve().parent
SLOTS = HERE.parent/'hello-quoting-state/slots'
spec = importlib.util.spec_from_file_location('quoting_package', SLOTS/'package.py')
quoting_package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quoting_package)
spec = importlib.util.spec_from_file_location('quoting_authoring', SLOTS/'prepare.py')
quoting_authoring = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quoting_authoring)


def checked_exact(root, entry, units):
    manifest = json.loads((root/'component-exact-c-slice-v1.json').read_text())
    assert manifest['slice_sha256'] == canonical_sha256_v3({k: v for k, v in manifest.items() if k != 'slice_sha256'})
    assert len(manifest['root_unit_ids']) == units and manifest['root_unit_ids'] == manifest['root_context_unit_ids']
    for row in manifest['files']:
        assert sha256_file(root/row['path']) == row['sha256']
    return root/('behavioral-fn-'+entry+'.c')


def prepare(retained, growth_exact, output, compiler):
    started = time.monotonic(); output.mkdir(parents=True, exist_ok=False)
    growth = prepare_growth(growth_exact, output/'allocation-grow', compiler)
    free_exact = retained/'rpl-free-exact'
    free_original = checked_exact(free_exact, '00001b34', 10)
    quote_original = checked_exact(retained/'exact', '00004eb3', 40)
    growth_original = checked_exact(growth_exact, '000063ac', 25)
    assert sha256_file(free_exact/'state-machine-runtime.h') == sha256_file(growth_exact/'state-machine-runtime.h')
    release = output/'preserve-errno-free'
    common = dict(target_id='gnu-hello', compiler=compiler, runner=None, server=None, link_files={}, runtime_files={})
    prepare_comparison_package(interface_package=release_interface(),
        source_files={'preserve-errno-free.c': HERE/'preserve-errno-free.c'},
        operation_symbols={'release': 'preserve_errno_free'},
        component_id='preserve-errno-free', output=release,
        adapter_files={'driver.c': HERE/'release-driver.c', 'release-bridge.c': SLOTS/'release-bridge.c',
            free_original.name: free_original, 'behavioral-support.c': free_exact/'behavioral-support.c'},
        include_files={name: free_exact/name for name in ('behavioral-c.h', 'state-machine-runtime.h', 'component-exact-c-slice-v1.json')},
        original_files=['adapters/'+free_original.name, 'adapters/behavioral-support.c', 'headers/component-exact-c-slice-v1.json'],
        oracle_kind='retained-c', cases=[dict(id='release-'+str(i), arguments=[str(i)]) for i in range(32)],
        observation_fields=['errno', 'lifetime', 'bytes', 'events'], assumptions=quoting_package.ASSUMPTIONS,
        scope='Complete free wrapper with actual changing errno cells, null/live blocks and observable controlled free effects.',
        export_adapters=['adapters/release-bridge.c'], **common)
    config = output/'growth-config.h'; config.write_text('#define HELLO_REAL_GROWTH 1\n#define HELLO_SCENARIOS 144\n')
    originals = {p.name: p for p in (free_original, quote_original, growth_original)}
    originals['behavioral-support.c'] = retained/'exact/behavioral-support.c'
    headers = {name: retained/'exact'/name for name in ('behavioral-c.h', 'state-machine-runtime.h')}
    headers.update({'quote-manifest.json': retained/'exact/component-exact-c-slice-v1.json',
        'release-manifest.json': free_exact/'component-exact-c-slice-v1.json',
        'growth-manifest.json': growth_exact/'component-exact-c-slice-v1.json',
        'runtime.h': HERE/'runtime.h', 'growth-config.h': config})
    bindings = bind_dependencies(services={'release_buffer': release, 'grow_slots': growth})
    assumptions = [*quoting_package.ASSUMPTIONS, *GROWTH_ASSUMPTIONS,
        'The actual quoting and xpalloc bodies execute together; only lower xrealloc/failure, quote engine, byte allocation, errno/free and clear services remain controlled.',
        'All represented table bytes are observed, including moved-block contents and liveness; no arbitrary heap serialization is claimed.']
    prepare_comparison_package(interface_package=quoting_authoring.interface(),
        source_files={name: SLOTS/name for name in ('quote-slots.c', 'quote-objects.h')},
        operation_symbols={'quote': 'quote_slots'},
        component_id='quote-slots', output=output/'quote-slots', adapter_files={'driver.c': SLOTS/'driver.c', **originals},
        include_files=headers, original_files=[*['adapters/'+name for name in originals],
            *['headers/'+name for name in headers if name.endswith('manifest.json')]],
        oracle_kind='retained-c', cases=[dict(id='scenario-'+str(i), arguments=[str(i)]) for i in range(144)],
        observation_fields=['invocations'], assumptions=assumptions,
        scope='Complete quoting/free/growth network; retained-C oracle and 144 stateful sequences with explicit remaining services.',
        **bindings, **common)
    write_json(output/'network-preparation.json', dict(seconds=time.monotonic()-started, cases=144,
        owned_original_units=75, eliminated_controlled_service_algorithm='xpalloc',
        new_formal_rules=False, shared_runtime_fixes=['nullable object declarations', 'unreached supplier observation'],
        formal_checks='not requested', whole_program_complete=False))
    return output/'quote-slots'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('retained', 'growth_exact', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(prepare(args.retained.resolve(), args.growth_exact.resolve(),
                  args.output.resolve(), Path(shutil.which('cc'))))
