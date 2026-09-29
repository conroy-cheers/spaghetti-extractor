"""Export the real Hello source selection and build it outside the checkout."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from spaghetti_extractor.components.source import load_component_source_package
from spaghetti_extractor.util import sha256_file, write_json


def run(connected, string, output):
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic(); commands = []

    def command(arguments, cwd, environment=None):
        before = time.monotonic()
        result = subprocess.run(list(map(str, arguments)), cwd=cwd, env=environment,
            capture_output=True, text=True, timeout=120)
        index = len(commands)
        (output/f'{index:02d}.stdout').write_text(result.stdout)
        (output/f'{index:02d}.stderr').write_text(result.stderr)
        commands.append(dict(command=list(map(str, arguments)), cwd=str(cwd),
            seconds=time.monotonic()-before, exit_code=result.returncode))
        write_json(output/'commands.json', commands)
        if result.returncode: raise RuntimeError(f'command {index} failed; inspect retained logs')
        return result.stdout

    project = output/'project'
    command([sys.executable, '-m', 'spaghetti_extractor', 'candidate', 'export', 'gnu-hello',
        '--comparison', connected, '--comparison', string, '--output', project], Path.cwd())
    description = json.loads((project/'source-export.json').read_text())
    if len(description['components']) != 9: raise ValueError('requires the reviewed nine-component selection')
    if any(project.rglob('*.exe')) or any(project.rglob('*.dll')): raise ValueError('export contains native runtime files')
    tools = {name:shutil.which(name) for name in ('make','cc','ar','nm','objdump')}
    if not all(tools.values()): raise ValueError('enter the lifting development shell for build tools')
    # Build with conventional tools and no Python/module/Nix build variables.
    # Tool binaries themselves are supplied by this machine's Nix environment.
    environment = {'PATH':os.environ['PATH'], 'LC_ALL':'C'}
    with tempfile.TemporaryDirectory(prefix='hello-source-build-') as temporary:
        external = Path(temporary)/'project'; shutil.copytree(project, external)
        command([tools['make'], '-j2', 'CC='+tools['cc'], 'AR='+tools['ar']], external, environment)
        symbols = command([tools['nm'], '--defined-only', external/'liblifted.a'], external, environment)
        architecture = command([tools['objdump'], '-f', external/'liblifted.a'], external, environment)
        expected = {symbol for unit in description['components'].values() for symbol in unit['operation_symbols'].values()}
        defined = [row.split()[-1] for row in symbols.splitlines() if len(row.split()) == 3 and row.split()[1] == 'T']
        if any(defined.count(symbol) != 1 for symbol in expected): raise ValueError('export lost or duplicated a selected operation')
        if 'elf64-x86-64' not in architecture: raise ValueError('this checkpoint requires the host x86-64 build')
        for name, digest in description['files'].items():
            if sha256_file(external/name) != digest: raise ValueError('build changed exported input '+name)
        for unit in description['components'].values(): load_component_source_package(external/unit['source_package'])
        shutil.copyfile(external/'liblifted.a', output/'liblifted.a')
    write_json(output/'audit.json', dict(status='pass', seconds=time.monotonic()-started,
        source_export_sha256=sha256_file(project/'source-export.json'), archive_sha256=sha256_file(output/'liblifted.a'),
        components=9, operation_definitions=len(expected), outside_checkout=True, build_requires_python=False,
        tools={name:dict(path=path, sha256=sha256_file(Path(path))) for name,path in tools.items()},
        architecture='x86_64', original_runtime_copied=False, application_executed=False,
        whole_program_portable=False, strong_qualification=False, producer_sha256=sha256_file(Path(__file__))))
    print('PASS: nine source packages built outside the checkout; application/runtime integration remains open.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('connected_comparison','string_comparison','output'): parser.add_argument(name, type=Path)
    args = parser.parse_args()
    run(args.connected_comparison.resolve(), args.string_comparison.resolve(), args.output.resolve())
