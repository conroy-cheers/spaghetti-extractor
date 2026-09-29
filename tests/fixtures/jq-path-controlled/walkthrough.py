"""Public local/integration checks for a freshly authored controlled boundary.

Run inside spaghetti-headless-wayland. This records the ordinary operator
commands and checks their expected outcomes; it is not a target-specific checker.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_run import load_comparison_result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['controlled','paths','output']:parser.add_argument(name,type=Path)
    args=parser.parse_args()
    controlled=args.controlled.resolve();paths=args.paths.resolve();out=args.output.resolve()
    if not os.environ.get('WAYLAND_DISPLAY'):raise RuntimeError('requires a headless Wayland desktop')
    out.mkdir(parents=True,exist_ok=False)
    commands=[];results={}
    def run(arguments,expected=0):
        command=[sys.executable,'-m','spaghetti_extractor',*map(str,arguments)]
        started=time.monotonic();result=subprocess.run(command,capture_output=True,text=True)
        number=len(commands)
        (out/f'{number:02d}.stdout').write_text(result.stdout)
        (out/f'{number:02d}.stderr').write_text(result.stderr)
        commands.append(dict(command=command,exit_code=result.returncode,seconds=time.monotonic()-started))
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if result.returncode!=expected:
            raise RuntimeError(f'command {number}: expected {expected}, got {result.returncode}; inspect {out}')
    def check(label,package,unit='path-get',*,previous=None,dependency=None,case=None,expected=0):
        arguments=['component','check','jq',unit,'--comparison-package',package,'--output',out/label]
        if previous:arguments+=['--reuse-comparison',out/previous]
        if dependency:arguments+=['--dependency-package','value-get='+str(dependency)]
        if case:arguments+=['--case',case]
        run(arguments,expected)
        result=load_comparison_result(out/label);results[label]=result
        return result

    for unit,package,draft in [('path-get',controlled/'caller','caller-draft'),
                              ('value-get',paths/'value-get','supplier-draft')]:
        run(['component','start','jq',unit,'--comparison-package',package,'--output',out/draft])
        assert (out/draft/'compile_commands.json').is_file()
    caller=out/'caller-draft';supplier=out/'supplier-draft'
    check('service-baseline',controlled/'service')
    local=check('caller-baseline',caller)
    check('supplier-baseline',supplier,'value-get')
    check('integration-baseline',paths/'path-get-network',dependency=supplier)
    local_plan=json.loads((out/'caller-baseline/inputs/comparison-plan.json').read_text())
    assert 'value-get' not in [row['id'] for row in local_plan.get('dependencies',[])]
    assert not any(name.endswith('/get.c') and 'storage-get/' not in name for name in local['input_sha256s'])
    for row in local['cases']:
        assert row['status']=='match'
        for side in ['original','source']:assert row['observations'][side]['body_absence']==2734

    source=supplier/'source/get.c';original=source.read_text()
    old='  if (!s->valid(e, result)) {\n    s->release(e, result);\n    result = s->null_value(e);\n  }\n  return result;'
    assert original.count(old)==1
    helper=('static spx_jv_value_v2 value_or_null(const spx_value_get_services_v5 *s,\n'
            '                                      void *e, spx_jv_value_v2 result) {\n'
            '  if (s->valid(e, result)) return result;\n'
            '  s->release(e, result);\n'
            '  return s->null_value(e);\n}\n\n')
    declaration='spx_jv_value_v2 lifted_value_get('
    assert original.count(declaration)==1
    compatible=original.replace(declaration,helper+declaration).replace(old,'  return value_or_null(s, e, result);')
    source.write_text(compatible)
    check('supplier-compatible',supplier,'value-get',previous='supplier-baseline')
    check('caller-reused',caller,previous='caller-baseline')
    integration=check('integration-compatible',paths/'path-get-network',previous='integration-baseline',dependency=supplier)
    assert integration['reuse']['status']=='invalidated'
    assert any('value-get/source/get.c' in name for name in integration['reuse']['changed_inputs'])

    # The local contract permits correct get responses even when a proposed real
    # implementation is wrong. It cannot substitute for checking that supplier.
    assert compatible.count('if (index < 0)')==1
    source.write_text(compatible.replace('if (index < 0)','if (index < -1)'))
    try:
        check('supplier-wrong',supplier,'value-get',previous='supplier-compatible',case='negative',expected=2)
        check('caller-with-wrong-neighbor',caller,previous='caller-reused')
        wrong=check('integration-wrong',paths/'path-get-network',previous='integration-compatible',
            dependency=supplier,case='negative',expected=2)
        assert wrong['cases'][0]['status']=='mismatch'
    finally:
        source.write_text(compatible)
    check('retained-replay',out/'integration-wrong/inputs',case='negative',expected=2)
    check('supplier-repaired',supplier,'value-get',previous='supplier-compatible')
    check('integration-repaired',paths/'path-get-network',previous='integration-compatible',dependency=supplier)
    for name in ['caller-reused','caller-with-wrong-neighbor','supplier-repaired','integration-repaired']:
        assert results[name]['reuse']['status']=='reused'
        assert not any(results[name]['work_counts'].values())
    assert all(result['formal_check']['status']=='not-requested' for result in results.values())
    summary=dict(status='pass',authorizing=False,
        scope='Finite controlled get with real shared-array services; original image remains exactly bound',
        conditional_local_evidence=True,whole_program_complete=False,
        native_get_body_bytes_erased_per_side=2734,selected_get_body_absent=True,
        source_growth_bytes=len(compatible.encode())-len(original.encode()),
        results={name:dict(status=result['status'],receipt_sha256=result['receipt_sha256'],
            work_counts=result['work_counts'],reuse=result['reuse'],timings=result['timings']) for name,result in results.items()})
    (out/'audit.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(dict(status='pass',comparisons=len(results),commands=len(commands),authorizing=False)))


if __name__=='__main__':main()
