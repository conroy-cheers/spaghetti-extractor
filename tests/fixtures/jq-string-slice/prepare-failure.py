"""Reuse a string-slice workspace in the real interpreter failure consumer."""
import argparse
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_package import comparison_preparation, load_comparison_package, revise_comparison_package
from spaghetti_extractor.util import sha256_file, write_json

HERE=Path(__file__).resolve().parent
ORIGINAL='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'


def prepare(base,backend_headers,output):
    started=time.monotonic()
    plan,_=load_comparison_package(base)
    if (plan['target_id'],plan['component_id'])!=('jq','string-slice') or plan['original']['files'].get('runtime/libjq-1.dll')!=ORIGINAL:
        raise ValueError('requires the retained pinned jq string-slice comparison package')
    if sha256_file(base/'headers/jv.h')!=sha256_file(backend_headers/'jv.h'):
        raise ValueError('backend headers must describe the same pinned jq value ABI')
    adapters={p.relative_to(base/'adapters').as_posix():p for p in (base/'adapters').rglob('*') if p.is_file()}
    headers={p.relative_to(base/'headers').as_posix():p for p in (base/'headers').rglob('*') if p.is_file()}
    headers.update({name:backend_headers/name for name in ('jq.h','jv_dtoa.h')})
    headers.update({'failure-driver.h':HERE.parent/'jq-portable/failure.c',
                    'allocation-observer.h':HERE.parent/'jq-array-storage/allocation-observer.h'})
    adapters['allocation-observer.c']=HERE.parent/'jq-array-storage/allocation-observer.c'
    with comparison_preparation(output) as staged:
        driver=staged/'driver.c'
        driver.write_text('#define SPX_COMPONENT_COMPARISON 1\n#include "failure-driver.h"\n')
        adapters['driver.c']=driver
        revise_comparison_package(package=base,output=staged/'string-slice',adapter_files=adapters,include_files=headers,
            cases=[dict(id=name,arguments=[name]) for name in
                   ('string-copy','string-empty','string-invalid','program-string','program-string-cold')],
            observation_fields=['case','callbacks','context_preserved','entries','output','kept','item_kept',
                                'references','failed_size','failures','lifetime','unmapped_live_sizes'],
            # These are selected comparison cases, not new preconditions on the
            # string-slice component. Preserve the contract required by callers.
            scope='Existing string-slice boundary in local and real warm/cold interpreter allocation-failure contexts. '
                'A registered nomem handler and controlled next-malloc failure observe the selected entry; other jq operations remain native. '
                'The cold dtoa context is identified at heap initialization by allocation generation, with live extent and nine null slots checked after failure; populated contexts are outside this observer. '
                'C observations describe that object separately from exact remaining allocations; physical measurements remain in stderr. No general heap or representation proof.')
        write_json(staged/'preparation.json',dict(seconds=time.monotonic()-started,base=str(base),
            preserved_component_sources=plan['sources'],new_checker_or_proof_rules=False,model_seconds=0,solver_seconds=0))
    print(output/'string-slice')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('base','backend_headers','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.base.resolve(),a.backend_headers.resolve(),a.output.resolve())
