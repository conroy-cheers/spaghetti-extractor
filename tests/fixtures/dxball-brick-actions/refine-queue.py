"""Refine queue memory access while retaining the pinned comparison environment."""
import argparse
from pathlib import Path
import runpy
import time
from spaghetti_extractor.components.comparison_package import revise_comparison_package
from spaghetti_extractor.util import write_json

HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))

def refine(package,output,*,keep_consumer=False,normal_consumer=False):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    interface,catalog=AUTHOR['declarations']()
    (output/'bridge.c').write_text(AUTHOR['bridge']())
    (output/'brick-runtime.h').write_text(AUTHOR['runtime_header']())
    if normal_consumer:
        leaf=package/'dependencies/brick-actions'
        sources={p.relative_to(leaf/'source').as_posix():p for p in (leaf/'source').rglob('*') if p.is_file()}
        sources['brick.c']=HERE/'brick.c'
        headers={p.relative_to(leaf/'headers').as_posix():p for p in (leaf/'headers').rglob('*') if p.is_file()}
        headers['brick-runtime.h']=output/'brick-runtime.h'
        # The retained pickup consumer includes this adapter and preserves all
        # existing brick operation arguments. Review this edge explicitly.
        revise_comparison_package(package=package,output=output/'selection',component_id='brick-actions',
            interface=interface,source_files=sources,adapter_files={'bridge.c':output/'bridge.c'},include_files=headers,
            service_catalog=catalog,service_bridge=AUTHOR['bridge_spec'](),
            assumptions=[(HERE/'BOUNDARY.md').read_text()],reviewed_requirements=['pickup-lifecycle/game-consumer'])
        selection=output/'selection'
        headers={p.relative_to(selection/'headers').as_posix():p for p in (selection/'headers').rglob('*') if p.is_file()}
        if 'brick-normal-runtime.c' not in headers:
            raise ValueError('requires the retained normal brick consumer')
        headers.update({'brick-runtime.h':output/'brick-runtime.h','brick-normal-runtime.c':HERE/'normal-runtime.c'})
        revise_comparison_package(package=selection,output=output/'package',include_files=headers)
        write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,retained_normal_consumer=True,
            retained_environment=str(package),tool_internal_changes=False,original_source_consulted=False))
        return
    sources={p.relative_to(package/'source').as_posix():p for p in (package/'source').rglob('*') if p.is_file()}
    sources['brick.c']=HERE/'brick.c'
    headers={p.relative_to(package/'headers').as_posix():p for p in (package/'headers').rglob('*') if p.is_file()}
    headers['brick-runtime.h']=output/'brick-runtime.h'
    options=dict(cases=AUTHOR['cases'](),
        scope='Actual brick operations with a refined queue read boundary, live native-address aliases and a demonstrated inaccessible-memory outcome, without game startup.')
    runtime=HERE/'runtime.c'
    if keep_consumer:
        if 'brick-local-runtime.c' not in headers:
            raise ValueError('requires the retained connected brick consumer')
        headers['brick-local-runtime.c']=runtime
        runtime=package/'adapters/runtime.c'
        options={}
    revise_comparison_package(package=package,output=output/'package',interface=interface,
        source_files=sources,adapter_files={'runtime.c':runtime,'bridge.c':output/'bridge.c'},include_files=headers,
        service_catalog=catalog,service_bridge=AUTHOR['bridge_spec'](),
        assumptions=[(HERE/'BOUNDARY.md').read_text()],**options)
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,retained_consumer=keep_consumer,
        retained_environment=str(package),tool_internal_changes=False,original_source_consulted=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('package',type=Path);p.add_argument('output',type=Path)
    consumer=p.add_mutually_exclusive_group()
    consumer.add_argument('--keep-consumer',action='store_true')
    consumer.add_argument('--normal-consumer',action='store_true')
    a=p.parse_args();refine(a.package.resolve(),a.output.resolve(),keep_consumer=a.keep_consumer,normal_consumer=a.normal_consumer)
