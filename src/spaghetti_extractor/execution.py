"""Bounded process cleanup shared by concrete execution paths.

Process groups do not contain detached runtime services. Their owning runtime
session must stop those separately. Never wait for inherited output pipes to
reach EOF as part of process cleanup.
"""
from __future__ import annotations

import os
import signal
import subprocess

CLEANUP_GRACE_SECONDS = 2.0


def signal_process_group(process: subprocess.Popen, sig: signal.Signals) -> None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            process.terminate() if sig == signal.SIGTERM else process.kill()
        except ProcessLookupError:
            pass


def stop_process(process: subprocess.Popen, *, grace: float = CLEANUP_GRACE_SECONDS) -> bool:
    """Escalate within two finite grace periods; report an unreaped root.

    Signal the group even if its leader has exited: children may remain. Detached
    children require the runtime session's separate lifecycle handling.
    """
    signal_process_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    finally:
        signal_process_group(process, signal.SIGKILL)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        return False
    return True


def communicate_until_exit(process: subprocess.Popen, data: bytes, *,
                           stdout, stderr, timeout: float) -> None:
    """Keep pipe semantics while capturing through root exit, never child EOF.

    Detached services can keep write handles open after the root exits. Drain
    currently available output for at most 50 ms, then close our pipe ends.
    Output produced later is outside this root-process observation interval.
    """
    import selectors
    import time

    deadline = time.monotonic() + timeout
    pending = memoryview(data)
    with selectors.DefaultSelector() as selector:
        for stream, sink in ((process.stdout, stdout), (process.stderr, stderr)):
            if stream is not None:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, sink)
        if process.stdin is not None:
            if pending:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()

        def pump(wait):
            nonlocal pending
            events = selector.select(wait)
            for key, event in events:
                stream = key.fileobj
                try:
                    if event & selectors.EVENT_READ:
                        chunk = os.read(stream.fileno(), 65536)
                        if chunk:
                            key.data.write(chunk)
                        else:
                            selector.unregister(stream)
                            stream.close()
                    else:
                        sent = os.write(stream.fileno(), pending[:65536])
                        pending = pending[sent:]
                        if not pending:
                            selector.unregister(stream)
                            stream.close()
                except BrokenPipeError:
                    selector.unregister(stream)
                    stream.close()
                except BlockingIOError:
                    pass
            return bool(events)

        try:
            while process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(process.args, timeout)
                pump(min(0.02, remaining))
            drain_deadline = time.monotonic() + 0.05
            while time.monotonic() < drain_deadline and pump(0):
                pass
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
