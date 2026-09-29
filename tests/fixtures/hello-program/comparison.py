"""Prepare normal-entry Hello workloads for public component check/replay/reuse."""
import argparse
from pathlib import Path
import tempfile
import time

from spaghetti_extractor.components.comparison_package import load_comparison_package, revise_comparison_package
from spaghetti_extractor.util import sha256_file, write_json

CASES=[('default',[]),('traditional',['-t']),('custom',['-g','A lifted greeting']),
       ('empty',['-g','']),('accent',['-g','caf\u00e9']),('quoted',['-g','a "quoted" \\ greeting']),
       ('long',['-g','q'*1024]),('help',['--help']),('version',['--version']),
       ('unknown',['--not-an-option']),('operand',['extra']),('missing-greeting',['-g'])]
COMPONENTS={'quote-slots','allocation-grow','preserve-errno-free','quote-buffer',
            'quote-cleanup','allocation-reallocate','checked-allocation','multibyte-conversion'}


def prepare(package, observer, output, string_package=None):
    started=time.monotonic();plan,_=load_comparison_package(package)
    if (plan['target_id']!='gnu-hello' or plan['component_id']!='quote-slots'
            or {plan['component_id'],*[r['id'] for r in plan.get('dependencies',[])]}!=COMPONENTS):
        raise ValueError('requires the reviewed eight-component Hello native selection')
    if '#define HELLO_NATIVE_PROGRAM 1' not in (package/'headers/native-image.h').read_text():
        raise ValueError('prepare the native package with --program-observer first')
    if plan['original']['files'].get('runtime/hello.exe')!='71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c':
        raise ValueError('requires the reviewed Hello original')
    if 'HELLO_PUBLIC_COMPARISON' not in observer.read_text():
        raise ValueError('observer must support public program observations')
    if string_package is not None:
        string,_=load_comparison_package(string_package)
        if (string['target_id']!='gnu-hello' or string['component_id']!='string-conversion'
                or string.get('dependencies') or string['tools']!=plan['tools']
                or string['original']['files'].get('runtime/hello.exe')!=plan['original']['files']['runtime/hello.exe']):
            raise ValueError('requires the local string-conversion package with the same original and tools')
        if ('fixture_string_program_initialize' not in (string_package/'adapters/bridge.c').read_text()
                or 'fixture_string_program_initialize' not in observer.read_text()):
            raise ValueError('string bridge and program observer must support the shared program entry')
    driver=dict(kind='pe32-import',image='runtime/hello.exe',
        library='hello-components.dll',symbol='spx_hello_program_anchor',process=dict(exit_codes=[0,1],drive='P'))
    assumptions=[
        'The pinned original PE32 program runs through its actual entry and both original TLS callbacks. One observer import preserves original sections and entry/TLS directories.',
        'Single-threaded synchronous observer; original exit, both TLS process-attach callbacks and the selected state reset must be observed. Signals, arbitrary reentrancy and concurrent execution are outside scope.',
        'All sides use P:\\hello.exe with private runtime files and Wine prefixes. The declared drive preserves the program pathname when the workspace moves. Command arguments are unchanged; unexpected working-directory files are rejected.',
        'Compare exit status, raw stdout/stderr, TLS counts, logical allocation events/lifetimes and implicit conversion states. Selection-specific call counts are retained diagnostics; the observer checks coverage.',
        *plan['assumptions'][2:]]
    if string_package is not None:
        assumptions.append(
            'The program independently enters string-conversion and the quoting network. The string adapter reaches the selected multibyte entry through its existing decode16 service. Observe implicit string state and retain actual selected call counts; program selection alone does not prove service compatibility.')
    with tempfile.TemporaryDirectory(prefix='hello-program-inputs-') as temporary:
        header=Path(temporary)/'native-image.h'
        header.write_text((package/'headers/native-image.h').read_text()+'\n#define HELLO_PUBLIC_COMPARISON 1\n')
        headers={p.relative_to(package/'headers').as_posix():p for p in (package/'headers').rglob('*') if p.is_file()}
        headers.update({'native-image.h':header,'program-runtime.h':observer})
        revise_comparison_package(package=package,output=output,include_files=headers,
            program_driver=driver,cases=[dict(id=name,arguments=args) for name,args in CASES],
            observation_fields=['exit_code','stdout','stderr','state'],assumptions=assumptions,
            scope='Normal Hello startup, TLS and command-line workloads with the selected C; untouched-original control and reported allocation/conversion state.',
            program_entry_packages={'string-conversion':string_package} if string_package is not None else None)
    plan,_=load_comparison_package(output)
    write_json(output/'program-preparation.json',dict(seconds=time.monotonic()-started,
        observer_sha256=sha256_file(observer),producer_sha256=sha256_file(Path(__file__)),
        program_entries=plan['program_driver'].get('entries',['quote-slots']),
        original_startup=True,strong_qualification=False,whole_program_portable=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package',type=Path)
    parser.add_argument('observer',type=Path,help='reviewed program-runtime.h C observer')
    parser.add_argument('output',type=Path)
    parser.add_argument('--string-package',type=Path,help='local string-conversion workspace, selected as another program entry')
    args=parser.parse_args();prepare(args.package.resolve(),args.observer.resolve(),args.output.resolve(),
        args.string_package.resolve() if args.string_package else None)
