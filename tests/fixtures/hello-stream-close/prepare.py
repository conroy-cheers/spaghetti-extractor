"""Prepare a previously unprepared close_stream boundary from the pinned PE."""
import argparse
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import service_catalog
from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_pe32_program import prepare_routine_image
from declarations import definitions, interface

HERE = Path(__file__).resolve().parent
PE = '71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c'
ASSUMPTIONS = [
    'Complete close_stream at RVA 0x6894..0x68f8 of pinned Hello; authored from retained disassembly, including all returning paths. Original startup/TLS are omitted in the routine oracle and covered separately through standalone program comparisons.',
    'A non-null live stream is consumed exactly once regardless of the result. Shared call-scoped proxies preserve its identity and contents; pending/error inspect it before close, and no stream access is valid afterward. Native FILE layout is confined to the oracle and adapters.',
    'pending, error, close, bad_descriptor and clear_errno are synchronous services. Pending is queried before error, then close exactly once. Nonzero error and close values need not equal minus one. The error predicate isolates target EBADF=9 from host error constants; caller errno and close effects remain observable.',
    'Controlled service combinations cover two stream identities and full surrounding frames; real MSVCRT file cases include pending writes, reads, prior errors and externally closed descriptors. Controlled cases are distinct from real file execution.',
    'The generated service bridge checks concrete call/return nesting; ordinary C borrow/take guards check live proxies. This is finite testing, not a checked heap/lifetime summary or universal qualification. Concurrency, reentrancy, invalid pointers and undefined target FILE manipulations are outside scope.',
]


def prepare(original, output):
    started = time.monotonic()
    if sha256_file(original) != PE: raise ValueError('requires pinned Hello bytes')
    environment = native_environment()
    output.mkdir(parents=True, exist_ok=False)
    library=output/'image/hello-routines.dll'
    write_json(output/'image/image-preparation.json',prepare_routine_image(original,library))
    services = definitions()
    cases = [dict(id='controlled-'+str(side), arguments=['controlled',str(side)]) for side in range(2)]
    cases += [dict(id='real-'+name, arguments=['real',name])
              for name in ('write','read','prior-error','closed-empty','closed-pending')]
    prepare_comparison_package(interface_package=interface(services), target_id='gnu-hello',component_id='stream-close',
        source_files={'close.c':HERE/'close.c'}, operation_symbols={'run':'lifted_stream_close'},
        adapter_files={'driver.c':HERE/'driver.c'},
        include_files={'stream-view.h':HERE.parent/'portable-runtime/stream-view.h', 'BOUNDARY.md':HERE/'BOUNDARY.md',
            'image-preparation.json':output/'image/image-preparation.json',
            **native_adapter_headers()},
        original_files=['runtime/hello.exe','runtime/hello-routines.dll','headers/image-preparation.json'],
        oracle_kind='native-original', cases=cases, observation_fields=['sequences'],
        assumptions=ASSUMPTIONS, scope='Complete stream-close decision with consumed live stream, ordered services and errno effects.',
        service_catalog=service_catalog(services).to_payload(),
        service_bridge=dict(native_symbol='fixture_close',
            adapters={name:dict(symbol='traced_'+name,kind='native',outcomes={'return':None}) for name in services},
            transports={'io_stream':dict(native_type='NativeStream',borrow='fixture_borrow',take='fixture_take',pack='fixture_pack')}),
        output=output/'stream-close',
        **{**environment,'runtime_files':{**environment['runtime_files'],'hello.exe':original,'hello-routines.dll':library}})
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(cases),original_sha256=PE,
        new_tool_internals=False,model_seconds=0,solver_seconds=0,strong_qualification=False))
    return output/'stream-close'


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('original',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();print(prepare(a.original.resolve(),a.output.resolve()))
