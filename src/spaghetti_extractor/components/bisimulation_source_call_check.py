"""Public preparation of compiler-bound service-call regions, without proof authority."""

import json
from pathlib import Path
import subprocess
import time

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file, write_json
from .bisimulation_compilation import workspace_compile_command
from .bisimulation_region_context import check_inert_region_markers
from .bisimulation_source_call_region import project_source_call_region
from .bisimulation_source_edit_check import checked_edit_boundary, _marked_source
from .bisimulation_source_inventory import compile_source_inventory
from .component_c_v5 import render_component_c_headers_v5
from .source import component_operation_symbols
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5


POLICY = 'compiled-source-service-call-region-v1'
GRAPH_POLICY = 'compiled-source-region-graph-v1'


def _boundary(value, source, graph):
    if graph:
        from .bisimulation_source_region_graph import checked_graph_boundary
        return checked_graph_boundary(value, source)
    return checked_edit_boundary(value, source, minimum_exits=1)


def _projection(inventory, function, markers, boundary, graph):
    if graph:
        from .bisimulation_source_region_graph import project_source_region_graph
        return project_source_region_graph(**inventory, function=function, cuts=markers, entries=boundary['regions'])
    return project_source_call_region(**inventory, function=function, entry=markers['entry'],
        exits={k: v for k, v in markers.items() if k != 'entry'})


def prepare_source_call_regions(*, package, source, bundle, boundaries, workspace,
                                goto_cc, goto_instrument, timeout_seconds=30, timings=None, graph=False):
    """Retain full-source and marked inventories; inspect every selected instruction.

    This is a source binding for downstream local proofs, not a functional
    theorem. Failed preparation remains incomplete and never authorizes a cut.
    """
    workspace = Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    result = {'policy': GRAPH_POLICY if graph else POLICY, 'status': 'prepared', 'authorizing': False,
              'activation_authorized': False, 'functional_correctness_checked': False,
              'source_package': source, 'interface_intent': bundle.intent.to_payload(),
              'boundaries': boundaries, 'regions': [], 'checks': [], 'models': {},
              'tools': {name: {'path': str(path), 'sha256': sha256_file(Path(path))}
                        for name, path in [('goto_cc', goto_cc), ('goto_instrument', goto_instrument)]}}
    symbols = component_operation_symbols(source)
    headers = render_component_c_headers_v5(bundle, symbols)

    def run(command, root, name, phase='compiler'):
        tick = time.monotonic()
        try:
            process = subprocess.run(workspace_compile_command(command, root), capture_output=True,
                                     text=True, timeout=timeout_seconds)
        finally:
            if timings is not None:
                timings.append({'phase': phase, 'step': 'source-call-region:' + root.name + ':' + name,
                                'seconds': time.monotonic() - tick})
        (root / (name + '.stdout')).write_text(process.stdout)
        (root / (name + '.stderr')).write_text(process.stderr)
        if process.returncode:
            raise ValueError(name + ': ' + process.stderr[-2000:])
        return process.stdout

    for index, boundary in enumerate(boundaries):
        row = {'index': index, 'boundary': boundary, 'status': 'incomplete'}
        try:
            boundary = _boundary(boundary, source, graph)
            function = symbols[boundary['operation_id']]
            text = (package / 'sources' / boundary['source']).read_text()
            _, markers = _marked_source(text, boundary)
            inventories = {}
            for side in ('ordinary', 'marked'):
                root = workspace / f'{index:04d}-{side}'
                inventories[side], command = compile_source_inventory(package=package, source=source,
                    headers=headers, root=root, function=function, goto_cc=goto_cc,
                    goto_instrument=goto_instrument, run=run,
                    transform=(lambda path, value: _marked_source(value, boundary)[0]
                               if path == boundary['source'] else value) if side == 'marked' else None)
                result['models'][root.name] = {'command': command, 'goto_sha256': sha256_file(root / 'model.goto')}
            tick = time.monotonic()
            ordinary, marked = inventories['ordinary'], inventories['marked']
            erasure = check_inert_region_markers(original_functions=ordinary['functions'],
                original_symbols=ordinary['symbols'], marked_functions=marked['functions'],
                marked_symbols=marked['symbols'], function=function, markers=list(markers.values()))
            projection = _projection(marked, function, markers, boundary, graph)
            row.update(status='prepared', marker_erasure=erasure, projection=projection)
            if timings is not None:
                timings.append({'phase': 'model', 'step': 'source-call-region:projection', 'seconds': time.monotonic()-tick})
        except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired) as error:
            result['status'] = 'incomplete'
            row['detail'] = str(error)
            result['checks'].append({'status': 'incomplete', 'code': 'source_region_graph_unsupported' if graph else 'source_call_region_unsupported',
                                     'detail': str(error), 'region_index': index})
        result['regions'].append(row)
    result['artifacts'] = [{'path': str(path.relative_to(workspace)), 'sha256': sha256_file(path)}
                           for path in sorted(workspace.rglob('*')) if path.is_file()]
    result['receipt_sha256'] = canonical_sha256_v3(result)
    write_json(workspace / ('source-region-graphs.json' if graph else 'source-call-regions.json'), result)
    return result


def checked_source_call_regions(result, *, artifacts, graph=False):
    """Reconstruct prepared projections from bound compiler inventories, without a solver.

    This reader validates source binding only. Consumers must still check the
    supplier, incoming domain and projected behavior before using a local proof.
    """
    def require(condition, detail):
        if not condition:
            raise ValueError('source call binding: ' + detail)

    require(result.get('policy') == (GRAPH_POLICY if graph else POLICY) and result.get('status') == 'prepared'
            and result.get('authorizing') is False and result.get('activation_authorized') is False
            and result.get('functional_correctness_checked') is False
            and result.get('receipt_sha256') == canonical_sha256_v3({k: v for k, v in result.items() if k != 'receipt_sha256'}),
            'incomplete, stale or authorizing preparation')
    artifacts = Path(artifacts).resolve()
    paths = set()
    for row in result['artifacts']:
        path = artifacts / row['path']
        require(path.resolve().is_relative_to(artifacts) and row['path'] not in paths
                and sha256_file(path) == row['sha256'], 'stale or escaping compiler input/output')
        paths.add(row['path'])
    for tool in result['tools'].values():
        require(sha256_file(Path(tool['path'])) == tool['sha256'], 'compiler tool changed')
    require(len(result['regions']) == len(result['boundaries']) and result['regions'], 'missing region inventory')
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(result['interface_intent']))
    require(bundle.intent.component_id == result['source_package']['lift_unit_id'], 'component identity differs')
    headers = render_component_c_headers_v5(bundle, component_operation_symbols(result['source_package']))
    projections = []
    for index, (row, configured) in enumerate(zip(result['regions'], result['boundaries'], strict=True)):
        require(row['index'] == index and row['boundary'] == configured and row['status'] == 'prepared',
                'region identity differs')
        boundary = _boundary(configured, result['source_package'], graph)
        function = component_operation_symbols(result['source_package'])[boundary['operation_id']]
        inventories = {}
        for side in ('ordinary', 'marked'):
            root = artifacts / f'{index:04d}-{side}'
            require(str((root/'model.goto').relative_to(artifacts)) in paths
                    and sha256_file(root/'model.goto') == result['models'][root.name]['goto_sha256'], 'missing compiled model')
            for name, content in headers.items():
                file = root / 'include' / name
                require(str(file.relative_to(artifacts)) in paths and file.read_text() == content,
                        'generated interface header differs')
            inventory = {}
            for key, field in [('functions', 'functions'), ('symbols', 'symbolTable')]:
                file = root / (key+'.stdout')
                require(str(file.relative_to(artifacts)) in paths, 'missing compiler inventory')
                records = [v[field] for v in json.loads(file.read_text()) if field in v]
                require(len(records) == 1, 'ambiguous compiler inventory')
                inventory[key] = {v['name']: v for v in records[0]} if key == 'functions' else records[0]
            inventories[side] = inventory
        ordinary_root = artifacts / f'{index:04d}-ordinary'
        marked_root = artifacts / f'{index:04d}-marked'
        for source in [*result['source_package']['files'], *result['source_package']['shared_inputs']]:
            file = ordinary_root / 'inputs' / source['path']
            require(str(file.relative_to(artifacts)) in paths and sha256_file(file) == source['sha256'], 'authored source differs')
            expected = file.read_text()
            if source['path'] == boundary['source']:
                expected, markers = _marked_source(expected, boundary)
            require((marked_root/'inputs'/source['path']).read_text() == expected, 'marked source differs')
        ordinary, marked = inventories['ordinary'], inventories['marked']
        erasure = check_inert_region_markers(original_functions=ordinary['functions'], original_symbols=ordinary['symbols'],
            marked_functions=marked['functions'], marked_symbols=marked['symbols'], function=function, markers=list(markers.values()))
        projection = _projection(marked, function, markers, boundary, graph)
        require(erasure == row['marker_erasure'] and projection == row['projection'], 'compiled projection differs')
        projections.append(projection)
    return projections


def prepare_source_region_graphs(**kwargs):
    return prepare_source_call_regions(**kwargs, graph=True)


def checked_source_region_graphs(result, *, artifacts):
    return checked_source_call_regions(result, artifacts=artifacts, graph=True)
