"""Prepare the complete quote engine against pinned native code and locale services."""
import argparse
import importlib.util
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_package import load_comparison_package, prepare_comparison_package
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.components.comparison_environment import native_environment
from declarations import interface

HERE = Path(__file__).resolve().parent
PE = '71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c'
ASSUMPTIONS = [
    'The complete original quote engine owns [36ea,4eb3) and the invalid-style cold region [14640,14645); all eleven styles are implemented by the C draft, with no original algorithm fallback.',
    'Native original execution uses the pinned Hello routine image with loader-header adaptation, driver CRT/argv and an explicitly requested locale. Original process startup/TLS callbacks are not executed.',
    'Borrowed buffers and delimiters remain live; the native adapter transports pointers to current contents without copying spans. Explicit-size cases also overlap output with input or live mask bytes, preserving actual write/read ordering. Input size/count arithmetic preserves target uint32_t behavior; fixtures are finite bounded objects.',
    'The mask is eight live uint32_t words. A null native mask maps to an all-zero private mask. The service conversion object relates a target four-byte state and a separate char32 result; this is not an assertion about host mbstate_t layout.',
    'Locale quotes, byte/wide printability, conversion reset/decode/initial-state, MB_CUR_MAX and invalid-style termination remain real pinned native services. They are synchronous; arbitrary reentrancy/concurrency or service side effects outside this environment are unobserved.',
    'The original strlen and byte-equality helpers are compared against ordinary C loops under valid readable spans and NUL-termination premises. Their native bodies remain pinned dependencies of these comparisons.',
    'Cases observe output bytes including adjacent poison frames, length, errno, input bytes, mask words and locale width. They do not establish complete access traces, absence of undefined behavior for arbitrary input, or strong qualification.',
]


def prepare(environment_package, original, output, *, multibyte_package=None):
    started = time.monotonic()
    if sha256_file(original) != PE:
        raise ValueError('quote engine requires the pinned Hello PE32 executable')
    environment = native_environment(environment_package)
    if environment['runner'] is None or environment['server'] is None:
        raise ValueError('requires the existing PE32/Wine comparison environment')
    output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('hello_routine_image', HERE.parent/'hello-native-quoting/prepare_image.py')
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    library = helper.prepare_image(original, output/'image')
    runtime = {name: path for name, path in environment['runtime_files'].items()
               if name in ('libgcc_s_sjlj-1.dll', 'libmcfgthread-2.dll')}
    if 'libmcfgthread-2.dll' not in runtime:
        raise ValueError('requires retained compiler runtime DLLs')
    runtime.update({'hello.exe': original, 'hello-routines.dll': library})
    objects = HERE.parent/'hello-quoting-state/slots/quote-objects.h'
    cases = [dict(id=f'style-{style}-flags-{flags}-locale-{locale}', arguments=list(map(str, [style, flags, locale])))
             for locale in range(4 if multibyte_package else 3) for style in range(11) for flags in (0, 1, 2, 4, 7)]
    assumptions = list(ASSUMPTIONS)
    if multibyte_package:
        selected, _ = load_comparison_package(multibyte_package)
        if selected['target_id'] != 'gnu-hello' or selected['component_id'] != 'multibyte-conversion':
            raise ValueError('requires the Hello multibyte-conversion package')
        assumptions[4] = 'Locale quotes, byte/wide printability, MB_CUR_MAX and invalid-style termination remain pinned native services. Conversion reset/decode/initial-state execute the selected multibyte-conversion C group, including its explicit lower runtime services.'
        assumptions.append('The additional locale-3 cases supply controlled UTF-8 charset and width services on both sides. Native C and Japanese contexts remain separate; this does not assert native CRT UTF-8 locale support.')
    bindings = bind_dependencies(consumers={'conversion-runtime':multibyte_package}) if multibyte_package else {}
    prepare_comparison_package(interface_package=interface(), target_id='gnu-hello', component_id='quote-buffer',
        source_files={**{name: HERE/name for name in ('quote-buffer.c', 'quote-buffer-objects.h')}, 'quote-objects.h': objects},
        operation_symbols={'buffer': 'quote_buffer'},
        adapter_files={name: HERE/name for name in ('driver.c', 'bridge.c')},
        include_files={**{name: HERE/name for name in ('quote-buffer-runtime.h', 'quote-buffer-objects.h')},
            'quote-objects.h': objects, 'image-preparation.json': output/'image/image-preparation.json',
            'COPYING.hello': HERE/'COPYING.hello',
            **({'multibyte-runtime.h':multibyte_package/'headers/multibyte-runtime.h'} if multibyte_package else {})},
        original_files=['runtime/hello.exe', 'runtime/hello-routines.dll', 'headers/image-preparation.json'],
        oracle_kind='native-original', cases=cases, observation_fields=['mb_cur_max', 'samples'],
        assumptions=assumptions,
        scope='Complete native Hello quote engine, all eleven styles; bounded byte/multibyte cases and pinned live locale services.',
        export_adapters=['adapters/bridge.c'], output=output/'quote-buffer',
        **bindings,
        **{**environment, 'runtime_files': runtime, 'link_files': {}})
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started, original_sha256=PE,
        cases=len(cases), invocations_per_case=112, native_oracle=True, selected_multibyte=bool(multibyte_package),
        new_proof_rules=False, strong_qualification=False, original_startup=False))
    return output/'quote-buffer'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('environment_package', type=Path, nargs='?', help='optional retained environment; otherwise use pinned dev-shell tools')
    for name in ('original', 'output'): parser.add_argument(name, type=Path)
    parser.add_argument('--multibyte-package',type=Path,help='select the complete stateful conversion group')
    args = parser.parse_args()
    print(prepare(args.environment_package.resolve() if args.environment_package else None, args.original.resolve(), args.output.resolve(),
                  multibyte_package=args.multibyte_package.resolve() if args.multibyte_package else None))
