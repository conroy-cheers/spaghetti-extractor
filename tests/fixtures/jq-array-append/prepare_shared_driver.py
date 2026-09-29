"""Attach the shared input driver to an existing append comparison, preserving C."""
import argparse
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_environment import native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import comparison_preparation,load_comparison_package,revise_comparison_package
from spaghetti_extractor.util import write_json

HERE=Path(__file__).resolve().parent
ORIGINAL='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'


def prepare(base,support,output):
    started=time.monotonic();plan,_=load_comparison_package(base);shared,_=load_comparison_package(support)
    if plan['component_id']!='array-append' or any(p['target_id']!='jq' or
            p['original']['files'].get('runtime/libjq-1.dll')!=ORIGINAL for p in (plan,shared)):
        raise ValueError('requires append and observer inputs from the pinned jq runtime')
    with comparison_preparation(output) as staged:
        entry=staged/'native-entry.h';entry.write_text(native_entry_header(original=base/'runtime/libjq-1.dll',
            expected_sha256=ORIGINAL,module='libjq-1.dll',entry_rva=0x287bd,end_rva=0x288b3))
        headers={path.relative_to(base/'headers').as_posix():path for path in (base/'headers').rglob('*') if path.is_file()}
        headers.update(native_adapter_headers())
        headers.update({'jq.h':support/'headers/jq.h','allocation-observer.h':support/'headers/allocation-observer.h',
            'binary-driver.h':HERE.parent/'jq-value-transport/binary-driver.h','native-entry.h':entry})
        adapters={Path(name).name:base/name for name in plan['adapters']}
        adapters.update({'driver.c':HERE/'shared-driver.c','allocation-observer.c':support/'adapters/allocation-observer.c'})
        revise_comparison_package(package=base,output=staged/'array-append',adapter_files=adapters,include_files=headers,
            cases=[dict(id='unique',arguments=['[1,2]','3','unique']),
                   dict(id='address',arguments=['[1,2]','3','unique-address']),
                   dict(id='retained',arguments=['[1,2]','{"nested":[7,8]}','retained']),
                   dict(id='aliased',arguments=['[1,2]','null','aliased'])],
            observation_fields=['input_words','samples','allocation_lifetime'],
            scope='Existing jq append C and admission boundary with explicit unique/retained/shared-input callers; '
                  'raw-jv result-address relationships are observations, not lifetime proofs.')
        write_json(staged/'preparation.json',dict(seconds=time.monotonic()-started,input_domain_preserved=True,
            source_and_interface_preserved=True,new_tool_internals=False,model_seconds=0,solver_seconds=0))
    print(output/'array-append')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('base','support','output'):parser.add_argument(name,type=Path)
    args=parser.parse_args();prepare(args.base.resolve(),args.support.resolve(),args.output.resolve())
