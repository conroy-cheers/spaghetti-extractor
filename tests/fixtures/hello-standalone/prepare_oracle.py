"""Bind unchanged/observed originals and explicit lower-allocation-fault images."""
import argparse
from pathlib import Path
import shutil
import subprocess
import time

from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_pe32_program import add_experimental_import

HERE=Path(__file__).resolve().parent
PE_SHA='71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c'


def prepare(original,output):
    if sha256_file(original)!=PE_SHA:raise ValueError('requires the pinned Hello executable')
    environment=native_environment()
    output.mkdir(parents=True,exist_ok=False)
    shutil.copyfile(original,output/'plain.exe')
    for name,path in environment['runtime_files'].items():shutil.copyfile(path,output/name)
    for name,path in [('observe.c',HERE/'observe.c'),('launch.c',HERE/'launch.c'),
            ('fault-native.c',HERE/'fault-native.c'),('allocation-fault.h',HERE.parent/'native/allocation-fault.h'),
            *native_adapter_headers().items()]:
        shutil.copyfile(path,output/name)
    library=output/'observe.dll'
    command=[str(environment['compiler']),'-std=c11','-O2','-Wall','-Wextra','-Werror','-shared',str(output/'observe.c'),'-o',str(library)]
    started=time.monotonic();result=subprocess.run(command,capture_output=True,timeout=60)
    (output/'compile.stdout').write_bytes(result.stdout);(output/'compile.stderr').write_bytes(result.stderr)
    if result.returncode:raise ValueError('observer compile failed; inspect compile.stderr')
    launcher=[str(environment['compiler']),'-std=c11','-O2','-Wall','-Wextra','-Werror','-municode',str(output/'launch.c'),'-o',str(output/'launch.exe')]
    result=subprocess.run(launcher,capture_output=True,timeout=60)
    (output/'launcher.stdout').write_bytes(result.stdout);(output/'launcher.stderr').write_bytes(result.stderr)
    if result.returncode:raise ValueError('launcher compile failed; inspect launcher.stderr')
    preparation=add_experimental_import(original,library,'spx_hello_observe',output/'observed.exe')
    fault_library=output/'fault.dll'
    fault_command=[str(environment['compiler']),'-std=c11','-O2','-Wall','-Wextra','-Werror',
        '-shared',str(output/'fault-native.c'),'-o',str(fault_library)]
    result=subprocess.run(fault_command,capture_output=True,timeout=60)
    (output/'fault.stdout').write_bytes(result.stdout);(output/'fault.stderr').write_bytes(result.stderr)
    if result.returncode:raise ValueError('allocation fault compile failed; inspect fault.stderr')
    fault_preparation=[add_experimental_import(original,fault_library,'spx_hello_allocation_fault',output/'fault.exe'),
        add_experimental_import(output/'fault.exe',library,'spx_hello_observe',output/'fault-observed.exe')]
    write_json(output/'oracle.json',dict(original_sha256=PE_SHA,command=command,launcher_command=launcher,seconds=time.monotonic()-started,
        preparation=preparation,runner=str(environment['runner']),server=str(environment['server']),
        fault_command=fault_command,fault_preparation=fault_preparation,
        fault_scope='Single-threaded malloc import calls returning to original _rpl_malloc RVA 0x663b; controlled NULL/ENOMEM, not physical exhaustion',
        files={p.name:sha256_file(p) for p in output.iterdir() if p.is_file()},
        producer_sha256=sha256_file(Path(__file__)),strong_qualification=False))
    print(output)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('original',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.output.resolve())
