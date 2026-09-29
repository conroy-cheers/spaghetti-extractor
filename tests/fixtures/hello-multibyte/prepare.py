"""Prepare complete stateful conversion from retained native inputs, without a pilot rebuild."""
import argparse
import importlib.util
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from declarations import OPERATIONS, RANGES, interface

HERE = Path(__file__).resolve().parent
PE = '71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c'
ASSUMPTIONS = [
    'The component owns complete mbrtoc32, rpl_mbrtowc, rpl_mbsinit and mbszero bodies plus the conversion cold fragment. The UTF-8 algorithm and continuation repair are authored C, without original algorithm fallback.',
    'The original native image is pinned and section-preserving; the driver supplies CRT initialization. Original Hello startup/TLS, signals, concurrent or reentrant use are outside this scope.',
    'State has four live representation bytes. Explicit state and the two distinct native implicit-state cells preserve their actual contents across calls. Input/output proxies are call-scoped and preserve live aliases; output words are suitably aligned live C objects.',
    'Input spans are readable for the supplied finite sizes and do not wrap addresses. The lower native mbrtowc service initializes its output on successful returns; malformed pointers and other uninitialized native state are not fabricated.',
    'The C and Japanese_Japan.932 contexts use the actual locale/charset/CRT services. Controlled UTF-8 replaces only locale_charset and MB_CUR_MAX on both sides; it is an explicit service context, not evidence that the retained CRT supports UTF-8 LC_CTYPE.',
    'Native charset selection, lower CRT conversion, errno and abort remain synchronous runtime services. Target errno numbers 22 and 42 remain observable; no host errno-number equality is assumed.',
    'Cases observe return/errno, explicit and implicit state, output, input aliases and adjacent state frames through incremental calls, resets and null arguments. They are finite comparisons, not a checked memory summary or strong qualification.',
    'Three malformed-prefix cases observe actual CRT abort in child processes, including output/state aliases. The abort observer snapshots call-time output/state/errno and forwards the real import; a bounded process supervisor captures exit and raw output. Capture failure is not an observed outcome.',
]


def prepare(environment_package, original, output):
    started = time.monotonic()
    if sha256_file(original) != PE: raise ValueError('requires the pinned Hello executable')
    environment = native_environment(environment_package)
    if environment['runner'] is None or environment['server'] is None: raise ValueError('requires a PE32/Wine environment')
    output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('hello_routine_image', HERE.parent/'hello-native-quoting/prepare_image.py')
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    library = helper.prepare_image(original, output/'image', include_multibyte=True)
    runtime = {name:path for name,path in environment['runtime_files'].items() if name in ('libgcc_s_sjlj-1.dll','libmcfgthread-2.dll')}
    if 'libmcfgthread-2.dll' not in runtime: raise ValueError('requires retained compiler runtime DLLs')
    runtime.update({'hello.exe':original,'hello-routines.dll':library})
    cases = [dict(id=f'context-{mode}-operation-{operation}-chunk-{chunk}', arguments=list(map(str,[mode,operation,chunk])))
             for mode in range(3) for operation in range(2) for chunk in (1,2,3,8)]
    cases += [dict(id=f'terminal-output-{mode}',arguments=['terminal',str(mode)]) for mode in range(3)]
    prepare_comparison_package(interface_package=interface(), target_id='gnu-hello', component_id='multibyte-conversion',
        source_files={name:HERE/name for name in ('multibyte.c','multibyte-objects.h')},
        operation_symbols={name:'multibyte_'+name for name in OPERATIONS},
        adapter_files={name:HERE/name for name in ('bridge.c','driver.c')},
        include_files={**{name:HERE/name for name in ('multibyte-objects.h','multibyte-runtime.h','COPYING.hello')},
            'multibyte-image.h':output/'image/native-image.h','image-preparation.json':output/'image/image-preparation.json',
            **native_adapter_headers('pe32-entry-hook.h', 'pe32-import-hook.h', 'pe32-process-observer.h')},
        original_files=['runtime/hello.exe','runtime/hello-routines.dll','headers/image-preparation.json'],
        oracle_kind='native-original', cases=cases, observation_fields=['context','sequences','invalid_state','terminal'],
        assumptions=ASSUMPTIONS,
        scope='Complete stateful Hello conversion group; native C/Japanese locale and explicit controlled UTF-8 context.',
        export_adapters=['adapters/bridge.c'], output=output/'multibyte-conversion',
        **{**environment,'runtime_files':runtime,'link_files':{}})
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,original_sha256=PE,
        ranges=RANGES,cases=len(cases),returning_cases=24,sequences_per_returning_case=288,terminal_cases=3,controlled_utf8=True,
        new_proof_rules=False,strong_qualification=False,original_startup=False))
    return output/'multibyte-conversion'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('environment_package',type=Path,nargs='?',help='optional retained comparison environment; otherwise use pinned dev-shell tools')
    for name in ('original','output'):parser.add_argument(name,type=Path)
    args=parser.parse_args()
    print(prepare(args.environment_package.resolve() if args.environment_package else None,args.original.resolve(),args.output.resolve()))
