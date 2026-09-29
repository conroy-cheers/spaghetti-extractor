"""Retain runtime-library notices and use the existing source assembly recipe."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys


def assemble(project, bindings):
    here = Path(__file__).resolve().parent
    for name in ('COPYING.LGPL-2.1', 'DISCLAIMER.PD', 'windows-path-provenance.json'):
        shutil.copyfile(here.parent / 'portable-runtime' / name, project / 'provenance' / name)
    subprocess.run([sys.executable, str(here.parent / 'jq-portable/refresh.py'), str(project),
        '--bindings', str(bindings)], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('--bindings', type=Path, default=Path(__file__).with_name('portable-bindings.json'))
    args = parser.parse_args()
    assemble(args.project.resolve(), args.bindings.resolve())
