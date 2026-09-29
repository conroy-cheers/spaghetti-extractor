"""Relink checked component objects as an experimental normal-process DLL.

This is a documented assembly experiment, not strong admission. It keeps the
existing comparison receipt and uses the same compiler and component objects.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import time

from spaghetti_extractor.components.comparison_build import observed_command
from spaghetti_extractor.components.comparison_package import copy_comparison, load_comparison_package, package_file
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.components.comparison_pe32_program import add_experimental_import


def prepare(comparison, output, *, diagnostic=False):
    started=time.monotonic()
    result=load_comparison_result(comparison)
    plan,_=load_comparison_package(comparison/'inputs')
    if plan['target_id']!='gnu-hello' or plan['component_id']!='quote-slots':
        raise ValueError('requires the connected Hello native comparison')
    if result['status']!='match' and not (diagnostic and result['status']=='mismatch'):
        raise ValueError('requires a matching comparison, or explicit diagnostic use of a retained mismatch')
    if '#define HELLO_NATIVE_PROGRAM 1' not in (comparison/'inputs/headers/native-image.h').read_text():
        raise ValueError('prepare the native package with --program-observer before checking it')
    original=comparison/'inputs/runtime/hello.exe'
    if sha256_file(original)!='71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c':
        raise ValueError('the program adapter requires the reviewed Hello executable')
    output.mkdir(parents=True,exist_ok=False)
    copy_comparison(comparison,output/'comparison')
    retained=output/'comparison';build=retained/'build'
    compilation=json.loads((build/'compilation.json').read_text())
    objects=[package_file(build,row['object']) for row in compilation['units']]
    runtime=output/'runtime';runtime.mkdir()
    library=runtime/'hello-components.dll'
    command=[plan['tools']['compiler']['path'],'-shared',*map(str,objects),
             *[str(package_file(retained/'inputs',p)) for p in plan['link_files']],'-o',str(library)]
    timings=[]
    linked=observed_command(command,cwd=output,env=dict(os.environ),timeout=60,
        output=output/'link',phase='link',timings=timings)
    if linked['returncode'] or linked['timed_out']:
        raise ValueError('component DLL link failed; inspect retained link.stderr')
    for side in ('plain','original','source'):
        directory=runtime/side;directory.mkdir()
        for path in plan['runtime_files']:
            source=package_file(retained/'inputs',path)
            if source.name in ('libgcc_s_sjlj-1.dll','libmcfgthread-2.dll'):
                shutil.copyfile(source,directory/source.name)
        if side=='plain':shutil.copyfile(original,directory/'hello.exe')
        else:
            shutil.copyfile(library,directory/library.name)
            add_experimental_import(original,library,'spx_hello_program_anchor',directory/'hello.exe')
    write_json(output/'program.json',dict(status='diagnostic' if diagnostic else 'prepared',
        authority='experimental-execution-only',strong_qualification=False,whole_program_portable=False,
        comparison_receipt_sha256=result['receipt_sha256'],comparison_status=result['status'],
        source_selection=[plan['component_id'],*[p['id'] for p in plan.get('dependencies',[])]],
        objects={str(p.relative_to(output)):sha256_file(p) for p in objects},
        runtime_files={str(p.relative_to(output)):sha256_file(p) for p in runtime.rglob('*') if p.is_file()},
        seconds=time.monotonic()-started,timings=timings))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('comparison',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--diagnostic',action='store_true',help='execute a known mismatch only for discrepancy diagnosis; never admission')
    args=parser.parse_args()
    prepare(args.comparison.resolve(),args.output.resolve(),diagnostic=args.diagnostic)
