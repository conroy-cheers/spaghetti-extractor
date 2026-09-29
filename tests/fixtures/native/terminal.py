"""Run a real process on a fresh POSIX PTY and retain its actual output bytes."""
import errno
import os
import pty
import select
import subprocess
import tempfile
import termios
import time
import tty


def terminal_process(command, *, executable=None, environment=None, cwd=None,
                     streams='both', columns=100, rows=120, timeout=30):
    if streams not in ('both', 'stdout', 'stderr') or not 1 <= columns <= 512 or not 1 <= rows <= 1024:
        raise ValueError('unsupported terminal observation profile')
    master, slave = pty.openpty()
    process = None
    try:
        tty.setraw(slave)
        termios.tcsetwinsize(slave, (rows, columns))
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(command, executable=executable, cwd=cwd, env=environment,
                stdin=subprocess.DEVNULL,
                stdout=slave if streams in ('both', 'stdout') else stdout,
                stderr=slave if streams in ('both', 'stderr') else stderr)
            os.close(slave); slave = None
            data = bytearray(); deadline = time.monotonic() + timeout
            while True:
                if not select.select([master], [], [], max(0, deadline-time.monotonic()))[0]:
                    raise TimeoutError('terminal process did not close its output within the deadline')
                try:
                    part = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not part:
                    break
                data.extend(part)
            code = process.wait(timeout=max(0.001, deadline-time.monotonic()))
            stdout.seek(0); stderr.seek(0)
            return dict(exit_code=code, terminal=bytes(data), stdout=stdout.read(), stderr=stderr.read())
    finally:
        os.close(master)
        if slave is not None:
            os.close(slave)
        if process is not None and process.poll() is None:
            process.kill(); process.wait()
