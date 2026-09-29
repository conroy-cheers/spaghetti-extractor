"""Materialize the real quoting/free experiment in existing comparison packages."""
import argparse
import json
from pathlib import Path
import shutil

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.comparison_composition import requirement
from spaghetti_extractor.components.comparison_package import prepare_comparison_package, load_comparison_package
from spaghetti_extractor.util import sha256_file

HERE = Path(__file__).resolve().parent
ASSUMPTIONS = [
    'Controlled synchronous services; service applicability to the complete runtime remains unverified.',
    'Finite disjoint typed scalar/record objects; buffer identities may alias; partial record aliases are outside this fixture.',
    'Fixed arena: at most 16 slots, four table identities and 24 represented 64-byte buffer allocations.',
    'Growth preserves old slots and may relocate; release changes represented liveness/generation and poisons retained bytes.',
    'Errno returns one of three represented cells; terminal abort/allocation failures are fixture outcomes.',
    'The object/byte synchronization and scalar-token release bridge are tested adapters, not checked representation rules.',
    'No callback/reentrant/concurrent execution; no native qualification or portable whole-program claim.',
]


def prepare(authoring, retained, output, compiler):
    output.mkdir(parents=True)
    originals = {}
    includes = {}
    includes['growth-config.h'] = HERE/'growth-config.h'
    for directory, entry, count in [('exact', '00004eb3', 40), ('rpl-free-exact', '00001b34', 10)]:
        root = retained/directory
        manifest = json.loads((root/'component-exact-c-slice-v1.json').read_text())
        assert manifest['slice_sha256'] == canonical_sha256_v3({k: v for k, v in manifest.items() if k != 'slice_sha256'})
        assert len(manifest['root_unit_ids']) == count and manifest['root_unit_ids'] == manifest['root_context_unit_ids']
        for row in manifest['files']:
            assert sha256_file(root/row['path']) == row['sha256']
        name = 'behavioral-fn-'+entry+'.c'; originals[name] = root/name
        includes[directory+'-manifest.json'] = root/'component-exact-c-slice-v1.json'
    originals['behavioral-support.c'] = retained/'exact/behavioral-support.c'
    for name in ('behavioral-c.h', 'state-machine-runtime.h'):
        includes[name] = retained/'exact'/name
    # Keep the supplier's authored source and headers in its own existing unit
    # namespace. The bridge is selected explicitly as a dependency adapter.
    child = retained/'rpl-free-authoring'
    child_package = output/'release-supplier'
    prepare_comparison_package(interface_package=child/'interface', source_package=child/'source',
        target_id='gnu-hello', component_id='preserve-errno-free',
        adapter_files={'release-bridge.c': HERE/'release-bridge.c'}, include_files={}, link_files={}, runtime_files={},
        original_files=['adapters/release-bridge.c'], oracle_kind='fixture',
        cases=[{'id': 'selected-supplier', 'arguments': []}], observation_fields=['invocations'],
        assumptions=ASSUMPTIONS, scope='Supplier package for selection into the quoting fixture; no standalone executable.',
        compiler=compiler, runner=None, server=None, output=child_package,
        export_adapters=['adapters/release-bridge.c'])
    child_plan, _ = load_comparison_package(child_package)
    req = requirement(identity='release', supplier='preserve-errno-free', root=child_package, unit=child_plan,
                      kind='service', service='release_buffer')
    prepare_comparison_package(interface_package=authoring/'interface', source_package=authoring/'source',
        target_id='gnu-hello', component_id='quote-slots', adapter_files={'driver.c': HERE/'driver.c', **originals},
        include_files=includes, link_files={}, runtime_files={},
        original_files=[*['adapters/'+n for n in originals], *['headers/'+n for n in includes]], oracle_kind='retained-c',
        cases=[{'id': 'scenario-'+str(i), 'arguments': [str(i)]} for i in range(128)], observation_fields=['invocations'],
        assumptions=ASSUMPTIONS,
        scope='Complete retained Hello quoting/free bodies, 128 controlled sequences. Finite behavior/lifetime observations only.',
        compiler=compiler, runner=None, server=None, output=output/'quoting',
        dependencies=[{'id': 'preserve-errno-free', 'package': child_package}], requirements=[req])
    print(output/'quoting')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('authoring', type=Path)
    parser.add_argument('retained', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    prepare(args.authoring.resolve(), args.retained.resolve(), args.output.resolve(), Path(shutil.which('cc')))
