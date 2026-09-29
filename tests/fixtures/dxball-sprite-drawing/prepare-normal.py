"""Reuse the public normal-game driver with the connected drawing selection."""
import argparse
import importlib.util
from pathlib import Path
import sys

from spaghetti_extractor.components.comparison_package import revise_comparison_package

HERE=Path(__file__).resolve().parent
FONT=HERE.parent/'dxball-sprite-font'
sys.path.insert(0,str(FONT))
spec=importlib.util.spec_from_file_location('font_normal_preparation',FONT/'prepare-normal.py')
normal=importlib.util.module_from_spec(spec);spec.loader.exec_module(normal)


def prepare(package,assets,output):
    normal.prepare(package,assets,output/'driver')
    base=output/'driver/package'
    includes={p.relative_to(base/'headers').as_posix():p for p in (base/'headers').rglob('*') if p.is_file()}
    includes['metrics-normal-runtime.c']=FONT/'normal-runtime.c'
    revise_comparison_package(package=base,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':base/'adapters/bridge.c'},
        include_files=includes,
        scope='Normal DX-Ball startup/input/close with lifted sprite drawing, font rendering/metrics and cleanup using original objects/DirectDraw.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'First 128 outer graphics calls and 32 metric calls are compared. Nested native entry counts are diagnostics because internal C calls need not recreate original machine call structure.',
            'Original entry/TLS, allocator, DirectDraw, assets and other game bodies remain. All six selected components use the existing live object transport.',
            'The external controller uses window readiness and wall-clock input/close timing; this is a bounded integration probe without frame/audio or deterministic playthrough coverage.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','assets','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.assets.resolve(),a.output.resolve())
