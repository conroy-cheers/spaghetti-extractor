"""Reuse three authored units inside actual native Hello callers and services."""
import argparse
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_package import load_comparison_package, prepare_comparison_package
from spaghetti_extractor.util import write_json
from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from prepare_image import prepare_image, ORIGINAL

HERE = Path(__file__).resolve().parent
ASSUMPTIONS = [
    'Pinned Hello PE32 routine image: only DLL flag, process entry, checksum and TLS directory headers change; section bytes are unchanged before normal loader relocations/imports.',
    'The fixture uses the driver CRT and C locale; original process startup, original TLS callbacks, signals, concurrency and arbitrary reentrancy are not executed or claimed.',
    'The PE32 C record layout matches the actual slot/options layout; these native pointer adapters do not establish a portable heap theorem.',
    'Actual x86 quoting callers, quoting engine, lower allocation, errno and cleanup routines execute; selected source bodies replace complete owned main ranges and the quote cold region traps.',
    'Inputs are live strings/explicit byte spans and valid small slot indices; no original invalid-index abort or allocation-exhaustion behavior is exercised here.',
    'CRT import observation covers this image malloc/realloc/free calls, sizes and logical live identities; physical relocation choices, uninitialized bytes and allocations internal to other DLLs are not compared.',
    'Returned text, initialized cache records, current errno, cleanup/reentry and native allocator interactions are finite observations, not strong native admission or whole-program equivalence.',
]


def package_paths(base, component_packages=False):
    if component_packages:
        return {name: base/name for name in ('quote-slots', 'allocation-grow', 'preserve-errno-free')}
    return {'quote-slots': base/'repaired/inputs', 'allocation-grow': base/'growth-repaired/inputs',
            'preserve-errno-free': base/'release-reused/inputs'}


def prepare(base, environment_package, original, output, *, component_packages=False, cleanup_package=None,
            reallocate_package=None, checked_allocation_package=None, terminal_failures=False, quote_engine_package=None,
            program_observer=False):
    if terminal_failures and not checked_allocation_package:
        raise ValueError('terminal failure comparison requires --checked-allocation-package')
    started = time.monotonic()
    packages = package_paths(base, component_packages)
    parent, interface = load_comparison_package(packages['quote-slots'])
    if parent['target_id'] != 'gnu-hello' or parent['component_id'] != 'quote-slots':
        raise ValueError('requires the Hello quote-slots component package')
    environment = native_environment(environment_package)
    if environment['runner'] is None or environment['server'] is None:
        raise ValueError('requires a retained PE32/Wine compiler and runtime environment')
    shared_representation = None
    if cleanup_package:
        cleanup_plan, _ = load_comparison_package(cleanup_package)
        if cleanup_plan['target_id'] != 'gnu-hello' or cleanup_plan['component_id'] != 'quote-cleanup':
            raise ValueError('requires the Hello quote-cleanup component package')
        shared_representation = cleanup_plan.get('representation')
        if shared_representation is None:
            raise ValueError('cleanup requires its reviewed shared-cache representation group')
    if reallocate_package:
        reallocate_plan, _ = load_comparison_package(reallocate_package)
        if reallocate_plan['target_id'] != 'gnu-hello' or reallocate_plan['component_id'] != 'allocation-reallocate':
            raise ValueError('requires the Hello allocation-reallocate component package')
    if checked_allocation_package:
        checked_plan, _ = load_comparison_package(checked_allocation_package)
        if checked_plan['target_id'] != 'gnu-hello' or checked_plan['component_id'] != 'checked-allocation':
            raise ValueError('requires the Hello checked-allocation component package')
    if quote_engine_package:
        engine_plan, _ = load_comparison_package(quote_engine_package)
        if engine_plan['target_id'] != 'gnu-hello' or engine_plan['component_id'] != 'quote-buffer':
            raise ValueError('requires the Hello quote-buffer component package')
    multibyte = next((d for d in engine_plan.get('dependencies',[]) if d['id']=='multibyte-conversion'),None) if quote_engine_package else None
    multibyte_headers = {}
    if program_observer and (not multibyte or not cleanup_package or not reallocate_package or not checked_allocation_package):
        raise ValueError('program observation requires the current complete eight-component selection')
    if multibyte:
        headers = [quote_engine_package/path/'multibyte-runtime.h' for path in multibyte['include_directories']
                   if (quote_engine_package/path/'multibyte-runtime.h').is_file()]
        if len(headers)!=1: raise ValueError('selected multibyte conversion needs its unambiguous exported runtime header')
        multibyte_headers['multibyte-runtime.h'] = headers[0]
    output.mkdir(parents=True, exist_ok=False)
    image = output/'image'; library = prepare_image(original, image, include_cleanup=cleanup_package is not None,
                                                   include_reallocate=reallocate_package is not None,
                                                   include_checked_allocation=checked_allocation_package is not None,
                                                   include_terminal_failures=terminal_failures,
                                                   include_quote_engine=quote_engine_package is not None,
                                                   include_multibyte=bool(multibyte), include_program=program_observer)
    suppliers = {name: packages[name] for name in ('allocation-grow', 'preserve-errno-free')}
    if quote_engine_package:
        suppliers['quote-buffer'] = quote_engine_package
    consumers = {**({'cleanup': cleanup_package} if cleanup_package else {}),
                 **({'native-reallocation': reallocate_package} if reallocate_package else {}),
                 **({'native-checked-allocation': checked_allocation_package} if checked_allocation_package else {})}
    bindings = bind_dependencies(services={'grow_slots': suppliers['allocation-grow'],
                                          'release_buffer': suppliers['preserve-errno-free'],
                                          **({'quote_buffer': quote_engine_package} if quote_engine_package else {})},
                                 consumers=consumers)
    extra_headers = {**({'cleanup-runtime.h': cleanup_package/'headers/cleanup-runtime.h'} if cleanup_package else {}),
                     **({'reallocate-runtime.h': reallocate_package/'headers/reallocate-runtime.h'} if reallocate_package else {}),
                     **({'checked-runtime.h': checked_allocation_package/'headers/checked-runtime.h'} if checked_allocation_package else {}),
                     **({'quote-buffer-runtime.h': quote_engine_package/'headers/quote-buffer-runtime.h'} if quote_engine_package else {}),
                     **multibyte_headers}
    assumptions = list(ASSUMPTIONS[:3] if terminal_failures else ASSUMPTIONS)
    if cleanup_package and not terminal_failures:
        assumptions.append('The complete cleanup loop at 52f2 is also replaced; its cache objects alias the quote component state, and both typed release services call the selected native free entry. Local cleanup uses a controlled release service, while this integration selects its implementation.')
    if reallocate_package and not terminal_failures:
        assumptions.append('The complete rpl_realloc body at 8db8 is replaced beneath actual xrealloc and growth callers. A real xrealloc zero-size probe observes normalization; direct native realloc probes cover controlled raw-allocator failure and high-bit rejection. Only those probe allocator failures are injected, preserving the live old block; normal quoting allocations still use the actual CRT.')
    if checked_allocation_package:
        assumptions.append('Eight checked allocation operations replace their whole bodies and shared check_nonnull tail; the two short aliases are validated entry branches to selected primary entries. Actual lower native routines preserve allocation/errno effects around declared injected raw allocator failures.')
        if not terminal_failures:
            assumptions.append('Every checked allocation entry runs success and controlled failure probes. xalloc_die is intercepted as a declared nonlocal nomem service. This does not exercise actual CRT process termination; normal quoting uses real allocation.')
    if terminal_failures:
        assumptions.extend([
            'Nine child processes exercise actual allocation, resize and array-resize alias callers with raw allocation failure injected. At xalloc_die a synchronous observer records live errno, old contents and allocation events, restores the original entry bytes, then runs native error/exit/abort without a jump handler.',
            'exit_failure is explicitly 1, 37 or 0; error_print_progname is null and the driver CRT supplies argv/program name and C locale. Original Hello startup/TLS and native allocator exhaustion remain untested. Windows error dialogs are disabled; abort itself is not replaced.',
            'A bounded ordinary C supervisor compares exact DWORD exit codes and raw stdout/stderr bytes. Output capacity is 16384 bytes per stream and timeout is 10 seconds. Capture failure or truncation rejects; cross-stream order is not observed. The child job owns descendants; this is not an OS sandbox.',
            'Reserved generated SPX_SERVICE and SPX_SERVICE_SCOPE lines are forwarded to the existing protocol checker, not compared as target diagnostics. Only after the child terminates and its reviewed xalloc_die observation is present does a supervisor C handler receive nomem. This telemetry transport does not replace child termination; malformed or incomplete protocol remains a failure.',
            'The selected network is loaded where supplied, but terminal cases directly execute only the checked allocation family and lower realloc. The separate quoting suite remains required for normal consumer coverage.',
        ])
    if quote_engine_package:
        assumptions.append('The complete quote engine [36ea,4eb3) is selected C and its invalid-style cold region [14640,14645) is trapped. Borrowed argument/output/mask contents cross the native adapter live; locale conversion/classification remain native services. Normal consumer cases verify source dispatch counters and absence of the original engine body.')
    if multibyte:
        assumptions[-1] = assumptions[-1].replace('locale conversion/classification remain native services', 'conversion uses the selected C group; locale/classification and lower CRT decoding remain explicit services')
        if not terminal_failures:
            assumptions[1] = 'The fixture uses driver CRT initialization and explicit locale/service contexts; original process startup, original TLS callbacks, signals, concurrency and arbitrary reentrancy are not executed or claimed.'
            assumptions.append('The quoting sequences run in native C and Japanese_Japan.932 locales and in an explicit controlled UTF-8 charset/width context on both sides. Controlled UTF-8 is not native CRT locale support. All selected conversion bodies are trapped and per-operation entry counts are retained, including zero for unexercised operations.')
    source = packages['quote-slots']/'source'
    destination = output/'quote-slots'
    # Reuse only the compiler runtime needed by this executable. jq and its
    # application dependencies are not part of the Hello native experiment.
    runtime = {name: path for name, path in environment['runtime_files'].items()
               if name in ('libgcc_s_sjlj-1.dll', 'libmcfgthread-2.dll')}
    if 'libmcfgthread-2.dll' not in runtime:
        raise ValueError('retained compiler runtime is absent')
    runtime.update({'hello.exe': original, 'hello-routines.dll': library})
    prepare_comparison_package(interface_package=interface,
        source_files={p.name: p for p in source.iterdir() if p.is_file()},
        operation_symbols=parent['operation_symbols'], target_id='gnu-hello', component_id='quote-slots',
        adapter_files={name: HERE/name for name in ('runtime.c', 'driver.c')},
        include_files={**{name: HERE/name for name in ('native-runtime.h', 'allocator.h', 'checked-family.h', 'terminal.h', 'program-runtime.h')},
            **extra_headers,
            'runtime.h': HERE.parent/'hello-allocation-growth/runtime.h',
            'quote-objects.h': source/'quote-objects.h',
            'native-image.h': image/'native-image.h', 'image-preparation.json': image/'image-preparation.json',
            **native_adapter_headers(),
            **(native_adapter_headers('pe32-process-observer.h') if terminal_failures else {})},
        original_files=['runtime/hello.exe', 'runtime/hello-routines.dll', 'headers/image-preparation.json'],
        oracle_kind='native-original',
        cases=([dict(id=f'terminal-entry-{entry}-status-{status}', arguments=['terminal', str(entry), str(status)])
                for entry in (0, 2, 9) for status in (1, 37, 0)] if terminal_failures else
              [dict(id=name+(f'-context-{mode}' if mode else ''), arguments=args+([str(mode)] if multibyte else []))
               for mode in range(3 if multibyte else 1)
               for name,args in [(f'style-{style}-kind-{kind}',[str(style),str(kind)]) for style in range(10) for kind in range(2)]+
                   [('custom-delimiters',['0','2'])]]),
        observation_fields=['terminal'] if terminal_failures else ['invocations', 'cleanup', 'after_cleanup', 'allocation_events', 'remaining_allocations',
                            *(['reallocation_probe'] if reallocate_package else []),
                            *(['checked_allocation'] if checked_allocation_package else []),
                            *(['multibyte_context'] if multibyte else [])],
        assumptions=assumptions,
        representation=shared_representation,
        scope=('Actual PE32 Hello fatal allocation consumers, diagnostics and process termination; declared raw failures and runtime initialization.' if terminal_failures else
               'Actual PE32 Hello quoting callers and cleanup with '+str(3+bool(cleanup_package)+bool(reallocate_package)+bool(checked_allocation_package)+bool(quote_engine_package)+bool(multibyte))+' authored components; explicit routine initialization, real CRT allocation and declared probes.'),
        **bindings, output=destination,
        **{**environment, 'runtime_files': runtime, 'link_files': {}})
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started, original_sha256=ORIGINAL,
        selected=['quote-slots', *suppliers, *(['quote-cleanup'] if cleanup_package else []),
                  *(['allocation-reallocate'] if reallocate_package else []),
                  *(['checked-allocation'] if checked_allocation_package else []),
                  *(['multibyte-conversion'] if multibyte else [])],
        native_caller_entries=[0x622d, 0x6257, 0x62b6] if terminal_failures else [0x53e5, 0x5416, 0x55e7],
        cases=9 if terminal_failures else 63 if multibyte else 21, terminal_failures=terminal_failures,
        selected_multibyte=bool(multibyte),
        new_authored_bodies=False, new_proof_rules=False,
        fresh_component_packages=component_packages,
        native_whole_program_startup=False, strong_qualification=False))
    print(destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base_workflow', type=Path)
    parser.add_argument('environment_package', type=Path, nargs='?', help='optional retained environment; otherwise use pinned dev-shell tools')
    for name in ('original_pe', 'output'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--component-packages', action='store_true',
                        help='base contains freshly prepared component packages, without earlier check results')
    parser.add_argument('--cleanup-package', type=Path,
                        help='also select the independently prepared cleanup component')
    parser.add_argument('--reallocate-package', type=Path,
                        help='also replace realloc normalization and errno behavior beneath real native callers')
    parser.add_argument('--checked-allocation-package', type=Path,
                        help='also replace the complete allocation family and its shared tail')
    parser.add_argument('--terminal-failures', action='store_true',
                        help='compare actual diagnostic/exit/abort paths in bounded child processes')
    parser.add_argument('--quote-engine-package', type=Path,
                        help='replace the complete quote engine beneath actual quoting callers')
    parser.add_argument('--program-observer', action='store_true',
                        help='include the ordinary C DLL observer for the separate normal-entry program experiment')
    args = parser.parse_args()
    prepare(args.base_workflow.resolve(), args.environment_package.resolve() if args.environment_package else None, args.original_pe.resolve(), args.output.resolve(),
            component_packages=args.component_packages,
            cleanup_package=args.cleanup_package.resolve() if args.cleanup_package else None,
            reallocate_package=args.reallocate_package.resolve() if args.reallocate_package else None,
            checked_allocation_package=args.checked_allocation_package.resolve() if args.checked_allocation_package else None,
            terminal_failures=args.terminal_failures,
            quote_engine_package=args.quote_engine_package.resolve() if args.quote_engine_package else None,
            program_observer=args.program_observer)
