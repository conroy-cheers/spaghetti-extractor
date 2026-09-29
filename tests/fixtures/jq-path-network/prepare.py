"""Materialize the larger jq experiment through existing interface/source APIs.

Usage: PYTHONPATH=src python tests/fixtures/jq-path-network/prepare.py BASE OUTPUT
BASE is a retained jq comparison package (tools, exact original, link inputs).
No target compilation, Wine execution, new artifact formats or proof authority.
"""

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time

from spaghetti_extractor.boundary import BoundaryLifecycleV1
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.comparison_environment import native_adapter_headers
from spaghetti_extractor.components.service_authoring import component_interface, service_catalog
from services import library, types, TRANSPORTS, V
from spaghetti_extractor.components.comparison_package import (
    prepare_comparison_package,
    load_comparison_package,
)
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.comparison_composition import requirement

HERE = Path(__file__).resolve().parent
UNITS = {
    "value-get": (
        "get.c",
        [
            "copy",
            "kind",
            "valid",
            "release",
            "length",
            "array_get",
            "object_get",
            "null_value",
            "number",
            "slice_bounds",
            "array_slice",
            "string_slice",
            "indexes",
            "index_error",
        ],
    ),
    "value-set": (
        "set.c",
        [
            "abandon",
            "copy",
            "kind",
            "valid",
            "release",
            "length",
            "array_get",
            "array_set",
            "object_set",
            "null_value",
            "number",
            "slice_bounds",
            "array_slice",
            "array",
            "object",
            "error",
            "update_error",
        ],
    ),
    "path-get": (
        "getpath.c",
        ["copy", "kind", "valid", "release", "length", "array_get", "array_slice", "get", "error"],
    ),
    "path-set": (
        "setpath.c",
        [
            "copy",
            "kind",
            "valid",
            "release",
            "length",
            "array_get",
            "get",
            "set",
            "error",
            "array_slice",
            "null_value",
        ],
    ),
}
ASSUMPTIONS = [
    "single-threaded owned jq values; borrowing services are copy, kind, valid and number",
    "native libjq allocation, reference counting, leaf operations and retained slice normalization are trusted fixture services",
    "sampled logical contents, errors and retained aliases; no complete heap lifetime or allocation-failure assurance",
]


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def resource_checks(intent, *, nonlocal_allocation=False):
    signature=intent.schema.signature_index['operation.run']
    bindings=[]
    for root,values,transition in [('parameter',signature.parameters,'consume'),('result',signature.results,'produce')]:
        for value in values:
            bindings.append(dict(id=root+'.'+value.identity,
                path=dict(root=root,value_id=value.identity,fields=[]),transition=transition,
                resource_kind='jq-reference',provider_domain='libjq',service_id='value-transport',
                interaction_contract_id=intent.component_id+'.reference-transfer',condition=None))
    lifecycle=BoundaryLifecycleV1.create(schema=intent.schema,signature_id=signature.identity,bindings=bindings)
    rule=dict(operation_id='run',lifecycle=lifecycle.to_payload(),max_untransferred=0,max_retained=0)
    if nonlocal_allocation:
        # These bounds describe the selected fault contexts, not an arbitrary
        # recursive jq heap. Native aliases and residual allocations are compared
        # independently; permitting interrupted tokens does not free their objects.
        rule['nonlocal_allowances']={'nomem':dict(max_untransferred=4 if intent.component_id=='path-set' else 2,
                                                max_retained=0)}
    return dict(capacity=4096,frame_capacity=256,instrumented_sides=['source'],
        unobserved=['native original and leaf-service allocation internals',
                    'native object lifetime generations; addresses are alias hints',
                    'unselected code and accesses outside value transport'],
        contracts=[rule])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--resource-checks", action="store_true", help="instrument selected lifecycle contracts")
    parser.add_argument("--array-storage-packages", type=Path,
                        help="select the authored array storage packages beneath the path consumers")
    parser.add_argument("--string-slice-package", type=Path,
                        help="select authored string slicing beneath value/path and interpreter consumers")
    args = parser.parse_args()
    if args.string_slice_package and not args.resource_checks:
        raise ValueError('string slicing requires the shared observed value transport; pass --resource-checks')
    base = args.base.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    plan, intent = load_comparison_package(base)
    if (
        plan["target_id"] != "jq"
        or plan["original"]["files"].get("runtime/libjq-1.dll")
        != "50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d"
    ):
        raise ValueError("requires the pinned jq original used by this experiment")
    tools = {name: Path(value["path"]) for name, value in plan["tools"].items()}
    runtime = {Path(p).name: base / p for p in plan["runtime_files"]}
    link = {Path(p).name: base / p for p in plan["link_files"]}
    cases = json.loads((HERE / "cases.json").read_text())
    string_package=args.string_slice_package.resolve() if args.string_slice_package else None
    string_fixture=HERE.parent/'jq-string-slice'
    if string_package:
        string_plan,_=load_comparison_package(string_package)
        if (string_plan['component_id']!='string-slice' or string_plan['target_id']!='jq' or
            string_plan['original']['files'].get('runtime/libjq-1.dll')!=plan['original']['files']['runtime/libjq-1.dll']):
            raise ValueError('string slice package binds another component or original')
        cases['value-get'] += [dict(id='string-slice-'+name,arguments=[text,bounds,'null','retained'])
            for name,text,bounds in [('multibyte','"a\\u20ac\\ud83d\\ude00z"','{"start":1,"end":3}'),
                                    ('embedded-nul','"a\\u0000b"','{"start":1,"end":2}'),
                                    ('negative','"a\\u20ac\\ud83d\\ude00z"','{"start":-2,"end":99}')]]
        cases['program'].append(dict(id='program-string-slices',arguments=[
            '.text as $s | [$s[1:3], $s[-2:], $s[0:0], $s, getpath(["text", {"start":1,"end":3}])]',
            '{"text":"a\\u20ac\\ud83d\\ude00z"}','null','program']))
        if args.array_storage_packages:
            cases['program'].append(dict(id='program-nomem-string',arguments=[
                '.text[1:3]','{"text":"a\\u20ac\\ud83d\\ude00z"}','null','program-nomem-string']))
    if args.array_storage_packages:
        failures={
            'value-get': [('nomem-index-error','[10,11]','true','[55]')],
            'value-set': [('nomem-shared-update','[10,11]','0','[55]'),
                          ('nomem-array-create','null','0','[55]')],
            'path-get': [('nomem-path-read','[[10,11],[20]]','[0,1]','[55]')],
            'path-set': [('nomem-path-detach','[[10,11],[20]]','[0,1]','[55]'),
                         ('nomem-empty-rest','[[10,11],[20]]','[0]','[55]')],
        }
        for unit,rows_ in failures.items():
            cases[unit]+=[dict(id=name,arguments=[root,key,item,'nomem']) for name,root,key,item in rows_]
        cases['path-set'].append(dict(id='nomem-path-number',arguments=['[[10,11],[20]]','[0,1]','[55]','nomem-cold']))
        cases['program'].append(dict(id='program-nomem-path',
            arguments=['setpath([0,1]; .[1])','[[10,11],[20]]','null','program-nomem']))
    packages = {}
    composed = {}
    bridges = {}
    rows = []
    definitions,adapters=library(intent.to_payload(),nonlocal_allocation=bool(args.array_storage_packages or string_package))
    array_packages={}
    array_headers=None
    array_fixture=HERE.parent/'jq-array-storage'
    array_services={'copy':'copy','release':'release','length':'length','array':'create',
                    'array_get':'get','array_set':'set','array_slice':'slice'}
    assumptions=ASSUMPTIONS
    if args.array_storage_packages:
        array_root=args.array_storage_packages.resolve()
        array_packages={key:array_root/('storage-'+key) for key in ['slice','length']}
        array_headers=array_packages['slice']/'headers'
        for package in array_packages.values():
            array_plan,_=load_comparison_package(package)
            if array_plan['target_id']!='jq' or array_plan['original']['files'].get('runtime/libjq-1.dll')!=plan['original']['files']['runtime/libjq-1.dll']:
                raise ValueError('array storage package binds another original')
        adapters={key:dict(value, symbol='path_storage_'+key) if key in array_services else value for key,value in adapters.items()}
        assumptions=[ASSUMPTIONS[0],
            'Selected ordinary-C array creation/copy/release/length/get/set/slice; native guarded allocator, foreign destructors and other jq services remain.',
            'Native-compatible descriptors preserve existing heap aliases; native foreign destructors and unselected native readers still access that layout.',
            ASSUMPTIONS[2],
            'Test-only single-threaded CRT import observation tracks allocations from the observed consumer through cleanup; diagnostic serialization allocations are excluded from lifetime counts.',
            'Selected malloc failures deliver the actual native nomem callback and longjmp; nomem cases warm native numeric conversion before observation, nomem-cold does not.',
            'Named nomem resource allowances bound stranded transport tokens only for the selected fault contexts; native references, aliases and residual allocations are independently compared.']
    if string_package:
        assumptions=[*assumptions,
            'Selected authored string-slice owns byte/codepoint traversal and release/construction order; the complete native slice body is intercepted. Native constructors, borrowed contents and lower services remain explicit.']
    for unit, (source, names) in UNITS.items():
        setup = out / (unit + "-setup")
        setup.mkdir()
        selected_services={name:definitions[name] for name in names}
        params=[('root',V),('key',V)]+([('item',V)] if unit.endswith('set') else [])
        i = component_interface(component_id=unit,types=types(intent.to_payload()),
            parameters=params,result=V,services=selected_services)
        write(setup / "interface.json", i.to_payload())
        build_component_source_package(
            lift_unit_id=unit,
            files={source: HERE / source,**({'numeric-index.h':HERE/'numeric-index.h'} if unit.startswith('value-') else {})},
            shared_inputs={},
            operation_symbols={"run": "lifted_" + unit.replace("-", "_")},
            out_dir=setup / "source",
        )
        bridges[unit] = setup / "bridge.c"
        resources=resource_checks(i,nonlocal_allocation=bool(array_packages or string_package)) if args.resource_checks else None
        bridges[unit].write_text('#include "portable-component-implementation.h"\n#include "native-api.h"\n#include "value-transport.h"\n#include "native-services.h"\n'+
            ('#include "array-path-bridge.h"\n' if array_packages else '')+'#include "comparison-service-bridge.h"\n')
        service_bridge=dict(adapters={name:adapters[name] for name in names},
            transports={name:asdict(t) for name,t in TRANSPORTS.items()},native_symbol='fixture_'+unit.replace('-','_'))
        packages[unit] = out / unit
        for integrated in [False, True] if unit.startswith("path-") else [False]:
            suffix = "-network" if integrated else ""
            destination = out / (unit + suffix)
            selected = (
                ["value-get"]
                if unit == "path-get"
                else ["value-set", "path-get"]
                if unit == "path-set"
                else []
            )
            selected = selected if integrated else []
            config = setup / ("config" + suffix + ".h")
            cname = unit.replace("-", "_")
            original = {
                "value-get": "jv_get",
                "value-set": "jv_set",
                "path-get": "jv_getpath",
                "path-set": "jv_setpath",
            }[unit]
            config.write_text(
                "#define PATH_IS_SET "
                + str(int(unit.endswith("set")))
                + "\n#define PATH_ENTRY fixture_"
                + cname
                + "\n#define PATH_ORIGINAL "
                + original
                + "\n#define PATH_NETWORK "
                + str(int(integrated))
                + "\n#define PATH_ALLOCATION_OBSERVER "
                + str(int(bool(array_packages)))
                + "\n"
            )
            selected_packages={dep:composed.get(dep,packages[dep]) for dep in selected}
            requirements=[]
            if string_package and unit=='value-get':
                requirements.append(requirement(identity='string-slice',supplier='string-slice',root=string_package,
                    unit=string_plan,kind='service',service='string_slice'))
            if integrated:
                for name,supplier in [('get','value-get')]+([('set','value-set'),('readback','path-get')] if unit=='path-set' else []):
                    package=selected_packages.get(supplier,packages[supplier])
                    supplier_plan,_=load_comparison_package(package)
                    requirements.append(requirement(identity=name,supplier=supplier,root=package,unit=supplier_plan,
                        kind='consumer' if name=='readback' else 'service',service=None if name=='readback' else name))
            recursion=[]
            if unit=='path-set':
                requirements.append(dict(id='recursive-update',supplier=unit,contract_sha256='self',kind='internal',service=None))
                recursion=[dict(id='jq-path-set-recursion',members=[unit],mode='synchronous-comparison',progress='unproved')]
            if array_packages:
                for key in names:
                    if key not in array_services:continue
                    supplier='storage-'+array_services[key]
                    package=args.array_storage_packages.resolve()/supplier
                    requirements.append(requirement(identity='array-storage-'+key,supplier=supplier,root=package,
                        unit=load_comparison_package(package)[0],kind='service',service=key))
                # The shared layout is selected coherently even for a caller
                # that uses only part of the storage family's service surface.
                for key,package in array_packages.items():
                    requirements.append(requirement(identity='array-family-'+key,supplier='storage-'+key,root=package,
                        unit=load_comparison_package(package)[0]))
            prepare_comparison_package(
                interface_package=setup / "interface.json",
                source_package=setup / "source",
                target_id="jq",
                component_id=unit,
                adapter_files={
                    **({'allocation-observer.c':array_fixture/'allocation-observer.c'} if array_packages else {}),
                    "driver.c": HERE / "driver.c",
                    "bridge.c": bridges[unit],
                    "dispatch.c": HERE / "native-dispatch.c",
                    "errors.c": HERE / "native-errors.c",
                    "slice.c": HERE / "native-slice.c",
                    "value-runtime.c": HERE.parent
                    / "jq-value-transport/value-runtime.c",
                },
                include_files={
                    **({'string-native.h':string_fixture/'string-native.h',
                        'string-view.h':string_fixture/'string-view.h'} if string_package else {}),
                    **({'array-path-bridge.h':array_fixture/'path-bridge.h','array-native.h':array_headers/'native.h',
                        'runtime.h':array_headers/'runtime.h','value-layout.h':array_headers/'value-layout.h',
                        **({'native-storage.h':array_headers/'native-storage.h'} if (array_headers/'native-storage.h').is_file() else {}),
                        'allocation-observer.h':array_fixture/'allocation-observer.h',
                        **native_adapter_headers('pe32-import-hook.h')} if array_packages else {}),
                    "config.h": config,
                    "native-api.h": HERE / "native-api.h",
                    "native-services.h": HERE / "native-services.h",
                    "path-contract.h": HERE / "path-contract.h",
                    "jv.h": base / "headers/jv.h",
                    "jq.h": HERE / "jq.h",
                    "interpreter.h": HERE / "interpreter.h",
                    "allocation-failure.h": HERE / "allocation-failure.h",
                    "interpreter-failure.h": HERE / "interpreter-failure.h",
                    **native_adapter_headers('pe32-entry-hook.h'),
                    "value-transport.h": HERE.parent
                    / "jq-value-transport/value-transport.h",
                    "value-runtime-impl.h": HERE.parent
                    / ("jq-value-transport/observed-runtime.h" if args.resource_checks else "jq-value-transport/raw-runtime.h"),
                },
                link_files=link,
                runtime_files=runtime,
                original_files=["runtime/libjq-1.dll"],
                oracle_kind="native-original",
                cases=cases[unit]
                + (cases["program"] if integrated and unit == "path-set" else []),
                observation_fields=[
                    "outcome",
                    "result",
                    "root_after",
                    "key_after",
                    "item_after",
                    "readback",
                ] + (['allocation_lifetime','allocation_failure','references','alias_matrix'] if array_packages else []),
                assumptions=assumptions,
                scope="jq "
                + unit
                + suffix
                + "; bounded path/value corpus against actual patched PE32 libjq",
                compiler=tools["compiler"],
                runner=tools["runner"],
                server=tools["server"],
                output=destination,
                resource_checks=resources,
                service_catalog=service_catalog(selected_services).to_payload(),
                service_bridge=service_bridge,
                requirements=requirements,
                recursion_groups=recursion,
                export_adapters=["adapters/bridge.c"],
                representation=({'group':{'id':'jq-path-values','label':'Shared jq path/value references','members':sorted(UNITS)},
                    'revision':'observed-reference-tokens-v1','inputs':{'transport':'headers/value-transport.h','implementation':'headers/value-runtime-impl.h'}} if resources else None),
                dependencies=[
                    {
                        "id": dep,
                        "package": selected_packages[dep],
                    }
                    for dep in selected
                ]+[{'id':'storage-'+key,'package':package} for key,package in array_packages.items()]+
                    ([{'id':'string-slice','package':string_package}] if string_package and unit=='value-get' else []),
            )
            if integrated: composed[unit]=destination
            rows.append(
                {
                    "package": str(destination),
                    "unit": unit,
                    "selected": selected,
                    "case_count": len(cases[unit])
                    + (
                        len(cases["program"])
                        if integrated and unit == "path-set"
                        else 0
                    ),
                }
            )
    write(
        out / "preparation.json",
        {
            "seconds": time.monotonic() - started,
            "base": str(base),
            "packages": rows,
            "fixture_sha256": {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(HERE.iterdir())
                if p.is_file()
            },
            "oracle": plan["original"],
            "assumptions": assumptions,
        },
    )
    policy = {
        "format": "spaghetti-extractor-experimental-component-policy-v1",
        "target_id": "jq",
        "configuration_id": "jq-path-network",
        "scope": "component-network",
        "required_components": list(UNITS),
        "accepted_assumptions": {u: assumptions for u in UNITS},
        "allow_original_runtime_dependencies": True,
        "allowed_formal_statuses": [
            "not-requested",
            "unavailable",
            "timeout",
            "proved",
        ],
    }
    policy['accepted_service_catalogs']={unit:json.loads((out/unit/'comparison-plan.json').read_text())['service_catalog']['catalog_sha256'] for unit in UNITS}
    if args.resource_checks:
        policy['accepted_resource_checks']={unit:canonical_sha256_v3(json.loads((out/unit/'comparison-plan.json').read_text())['resource_checks']) for unit in UNITS}
        policy['accepted_representations']={unit:{'group':{'id':'jq-path-values','label':'Shared jq path/value references','members':sorted(UNITS)},
            'revision':'observed-reference-tokens-v1'} for unit in UNITS}
    write(out / "experimental-policy.json", policy)
    print(out)


if __name__ == "__main__":
    main()
