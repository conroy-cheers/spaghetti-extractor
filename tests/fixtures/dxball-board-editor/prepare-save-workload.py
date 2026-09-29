"""Exercise the real editor's save behavior before extending native selection."""
import argparse
from pathlib import Path
import subprocess
import sys

from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package

HERE=Path(__file__).resolve().parent


def prepare(game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    environment=native_environment()
    subprocess.run([str(environment['compiler']),'-std=c11','-Wall','-Wextra','-Werror','-municode',
        str(HERE/'probe-editor.c'),'-o',str(output/'probe-editor.exe'),'-luser32'],check=True)
    runner=output/'editor-runner'
    runner.write_text('#!'+sys.executable+'\n'+f'''import os,sys,subprocess
wine={str(environment['runner'])!r}
args=sys.argv[1:]
if os.environ.get('SPX_COMPARISON_SIDE') not in ('plain','original','source'):
    os.execv(wine,[wine,*args])
if args[0].startswith('/'):
    args[0]='Z:'+args[0].replace('/',chr(92))
with open('tmp/controller.log','wb') as log:
    ran=subprocess.run([wine,'probe-editor.exe',*args],stdout=log,timeout=42)
sys.exit(ran.returncode)
''')
    runner.chmod(0o755)
    revise_comparison_package(package=game,output=output/'package',runner=runner,
        program_driver={**plan['program_driver'],'process':{
            **plan['program_driver']['process'],'mutable_files':['Default.bds']}},
        runtime_files={**{p.name:p for p in (game/'runtime').iterdir() if p.is_file()},'probe-editor.exe':output/'probe-editor.exe'},
        cases=[dict(id='editor-clear-save-close',arguments=[])],
        scope='Real normal-entry editor clear/save behavior through the existing selected board and graphics network.',
        assumptions=[*plan['assumptions'],
            'The counted workload enters the editor with Ctrl+F1, clears the current board with Backspace, saves with S and closes. Read-only memory checks confirm cleared current and saved bytes. No application code/data or files are changed by the controller. The application itself must change Default.bds. The new editor C is not selected in this integration prerequisite probe.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.game.resolve(),a.output.resolve())
