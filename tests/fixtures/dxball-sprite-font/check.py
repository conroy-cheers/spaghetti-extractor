"""Retain connected original-versus-lifted font checks through the public CLI."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import write_json


def check(packages, output):
    if not os.environ.get('WAYLAND_DISPLAY'): raise ValueError('run in spaghetti-headless-wayland')
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for unit in ('metrics', 'render'):
        started = time.monotonic()
        args = ['component', 'check', 'dxball', 'font-'+unit, '--comparison-package', str(packages/('font-'+unit)),
                '--output', str(output/unit)]
        ran = subprocess.run([sys.executable, '-m', 'spaghetti_extractor', *args], capture_output=True, text=True, timeout=240)
        (output/(unit+'.stdout')).write_text(ran.stdout); (output/(unit+'.stderr')).write_text(ran.stderr)
        row = dict(unit=unit, arguments=args, exit_code=ran.returncode, seconds=time.monotonic()-started)
        if (output/unit/'comparison-result.json').exists():
            result = load_comparison_result(output/unit)
            phases = {}
            for phase in result['timings']: phases[phase['phase']] = phases.get(phase['phase'], 0) + phase['seconds']
            row.update(status=result['status'], cases=len(result['cases']), phases=phases,
                       work_counts=result['work_counts'], receipt_sha256=result['receipt_sha256'])
        rows.append(row); write_json(output/'results.json', rows); print(row, flush=True)
        if ran.returncode: raise RuntimeError('inspect '+str(output/(unit+'.stdout')))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('packages', type=Path); p.add_argument('output', type=Path)
    a = p.parse_args(); check(a.packages.resolve(), a.output.resolve())
