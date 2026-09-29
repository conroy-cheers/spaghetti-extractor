"""Readable navigation for the source recipe's actual selected C bindings."""
from pathlib import Path


def guide_files(components):
    return {'README.md', 'COMPONENTS.md', *('bindings/'+name+'.md' for name in components)}


def write_binding_guides(output,export,choices,bindings,support_files):
    units=export['components']
    index=['# Selected portable jq components','',
        'Open a binding guide to work on one component in this source program. '
        'Its boundary guide retains inputs, shared objects, assumptions and comparison examples.','',
        '| Component | Generated C entry | Local guides |','|---|---|---|']
    for identity,unit in sorted(units.items()):
        binding=bindings[identity];spec=choices.get(identity,{})
        if 'assembly' in spec:
            assembly=spec['assembly']
            names=', '.join('`'+name+'`' for name in assembly['entries'])
            index.append(f'| {identity} | {names} | [Bindings](bindings/{identity}.md) · [Boundary](lifted/components/{identity}/README.md) |')
            lines=[f'# {identity}: portable program bindings','',
                f'[Boundary and C](../lifted/components/{identity}/README.md)','',
                'Operator-owned C entries: '+names+'.','',assembly['lifetime'],'',
                '| Native entry | Component operations |','|---|---|']
            lines += [f'| `{name}` | '+', '.join('`'+op+'`' for op in operations)+' |'
                      for name,operations in assembly['entries'].items()]
            lines += ['', 'C support:']+['- ['+name+']('+identity+'/'+name+')' for name in [*assembly['sources'],*assembly['headers']]]
            lines += ['', 'Replaced definitions:']+['- `'+row['symbol']+'` in `'+row['file']+'`.' for row in assembly['replacements']]
            lines += ['', 'These portable bindings are independent of the native comparison harness. '
                      'Use candidate apply with the target refresh recipe and affected build/workload checks to apply C or binding changes together. '
                      'The recipe retains the explicit adapter files and replacement group.','']
            (output/'bindings'/f'{identity}.md').write_text('\n'.join(lines))
            continue
        index.append(f'| {identity} | `{binding["native_symbol"]}` | '
            f'[Bindings](bindings/{identity}.md) · [Boundary](lifted/components/{identity}/README.md) |')
        lines=[f'# {identity}: portable program bindings','',
            f'[Component boundary and C](../lifted/components/{identity}/README.md) · '
            '[All selected components](../COMPONENTS.md)','',
            f'Generated entry: `{binding["native_symbol"]}` in [{identity}.c]({identity}.c).',
            'Authored operation symbols: '+', '.join(f'`{name}` → `{symbol}`' for name,symbol in sorted(unit['operation_symbols'].items()))+'.','']
        if spec.get('backend_file'):
            symbol=spec.get('backend_symbol',binding['native_symbol'])
            lines.extend([f'Superseded backend body: `{symbol}` in '
                f'[{spec["backend_file"]}](../backends/jq/{spec["backend_file"]}). '
                'An explicit C wrapper may preserve a different public ABI.',''])
        requirements={row['service']:row['supplier'] for row in unit.get('requirements',[]) if row['kind']=='service'}
        lines.extend(['## Services','', '| Service | Selected C adapter | Declared supplier |','|---|---|---|'])
        for name,adapter in sorted(binding['adapters'].items()):
            supplier=requirements.get(name)
            link=f'[{supplier}]({supplier}.md)' if supplier in units else f'`{supplier}`' if supplier else 'No component declared'
            lines.append(f'| `{name}` | `{adapter["symbol"]}` | {link} |')
        if not binding['adapters']:lines.append('| — | No services selected | — |')
        lines.extend(['','The generated entry above contains these calls. Review their implementations through the C support files below. '
                      'An undeclared supplier may still call selected components through its C adapter.','',
                      '## C support and shared state',''])
        for name in sorted(set(support_files[identity])):
            lines.append(f'- Binding support: [{name}]({name}).')
        for filename,headers in sorted(spec.get('backend_headers',{}).items()):
            for name in sorted(headers):
                relative=Path(filename).with_name(name).as_posix()
                lines.append(f'- Backend adapter: [{name}](../backends/jq/{relative}), included after the private definitions in '
                    f'[{filename}](../backends/jq/{filename}).')
        consumers=[name for name,other in sorted(units.items()) if any(row['supplier']==identity for row in other.get('requirements',[]))]
        if consumers:
            lines.extend(['','Declared consumers: '+', '.join(f'[{name}]({name}.md)' for name in consumers)+'.'])
        lines.extend(['','## Edit and update','',
            'Edit ordinary component C through its boundary guide and comparison workspace. '
            'Apply the matching result with `candidate apply`, using the source recipe’s `refresh.py {project}` as the assembly command '
            'and the affected build/workloads as check commands. Use that same action for service or backend changes with reviewed binding inputs. '
            'Backend-header edits affect their containing translation unit; they do not require editing neighboring component bodies.','',
            'This generated guide describes the portable program selection. The boundary guide’s comparison bindings describe a separate execution environment. '
            'Keep operator notes in a separate file; refresh preserves conflicting edits for explicit review.',''])
        (output/'bindings'/f'{identity}.md').write_text('\n'.join(lines))
    index.extend(['','These are selected C bindings and declared dependencies, not inferred runtime coverage or new assurance. '
        'Use the linked boundary guides for assumptions and recorded comparisons, and run affected program workloads after changing executable inputs.',''])
    (output/'COMPONENTS.md').write_text('\n'.join(index))
