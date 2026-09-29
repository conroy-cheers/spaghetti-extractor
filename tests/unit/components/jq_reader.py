"""Run independent jq readers without putting their source in argv.

The complete contextual reader exceeds some hosts' per-argument size limit.
Keep the exact filter bytes and normal subprocess semantics; only transport the
filter through jq's file option instead of one large command-line argument.
"""

import subprocess
import tempfile
from pathlib import Path


def run(command, **kwargs):
    index = 2 if len(command) > 1 and command[1] in {"-e", "-c", "-n"} else 1
    if (len(command) <= index or not isinstance(command[index], str)
            or len(command[index]) < 4096):
        return subprocess.run(command, **kwargs)
    with tempfile.TemporaryDirectory(prefix="spx-jq-reader-") as temporary:
        program = Path(temporary) / "reader.jq"
        program.write_text(command[index], encoding="utf-8")
        return subprocess.run([*command[:index], "-f", str(program), *command[index+1:]], **kwargs)
