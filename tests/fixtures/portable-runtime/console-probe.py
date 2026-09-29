"""Exercise the same CRT consumer through native and portable console services."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from spaghetti_extractor.components.comparison_runtime import wine_sessions
from spaghetti_extractor.util import write_json
from tests.fixtures.native.terminal import terminal_process


def exercise(root, reader):
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('headless Wayland is required')
    runner=shutil.which('wine');server=shutil.which('wineserver')
    prefix=root/'wine';prefix.mkdir()
    fontconfig=root/'fontconfig.xml'
    fontconfig.write_text('<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd"><fontconfig></fontconfig>\n')
    env={**os.environ,'WINEPREFIX':str(prefix),'WINEDEBUG':'-all','LC_ALL':'C.UTF-8',
         'FONTCONFIG_FILE':str(fontconfig)}
    inputs=['caf\u00e9 \u20ac \u201cquotes\u201d','abcdef\r\tQ','ab\tcd\rZ\nnext\bQ',
            'x'*100+'\bQ','\bQ','line\n'*140]
    inputs+=['w'*n for n in (79,80,99,100,101,199,200,201)]
    inputs+=['w'*n+'\tZ' for n in (95,96,97,99,100)]
    inputs+=['x'*100+control+'Q' for control in ('\r','\n','\t','\b','\a','\b\b','\r\b')]
    inputs+=['\n\bQ','\n\b\bQ']
    rows=[]
    with wine_sessions(server=server,environments={'native':env},cwd=root,logs=root,
            timeout=30,timings=[],persistent=True,dispose_prefixes=True,runner=runner):
        for streams in ('both','stdout','stderr'):
            pairs=[[text,'second \u00e9\tend'] for text in inputs]+[['first',text] for text in inputs]
            for index,arguments in enumerate(pairs):
                name=f'{streams}-{index}';report=root/(name+'.json')
                original=subprocess.run([runner,'console-launch.exe','original.exe',*arguments],cwd=root,
                    env={**env,'SPX_CONSOLE_REPORT':'Z:'+str(report).replace('/','\\'),
                         'SPX_CONSOLE_STREAMS':streams},capture_output=True,timeout=40)
                if original.returncode:raise ValueError((name,'original failed',original.stderr))
                observed=json.loads(report.read_text())
                native=dict(exit_code=observed['exit_code'],cursor=observed['cursor'],lines=observed['lines'],
                    stdout=list(original.stdout),stderr=list(original.stderr))
                portable=terminal_process([str(root/'portable'),*arguments],environment=env,cwd=root,streams=streams)
                rendered=subprocess.run([str(reader),'120','100'],input=portable['terminal'],capture_output=True,timeout=10)
                if rendered.returncode:raise ValueError((name,'screen observer failed',rendered.stderr))
                result=dict(json.loads(rendered.stdout),exit_code=portable['exit_code'],
                    stdout=list(portable['stdout']),stderr=list(portable['stderr']))
                rows.append(dict(id=name,match=native==result))
                if native!=result:
                    write_json(root/'mismatch.json',dict(id=name,original=native,portable=result))
                    raise ValueError(name+' differs; inspect mismatch.json')
    write_json(root/'console-probe.json',dict(status='match',cases=rows))


if __name__=='__main__':exercise(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
