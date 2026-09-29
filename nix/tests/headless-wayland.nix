{ pkgs }:

let
  runner = import ../headless-wayland.nix { inherit pkgs; };
in
pkgs.runCommand "spaghetti-extractor-headless-wayland-check" {
  nativeBuildInputs = [ runner pkgs.bash (pkgs.python3.withPackages (ps: [ ps.pillow ])) pkgs.pulseaudio pkgs.stdenv.cc pkgs.libX11 ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  # The same XWarpPointer path used by Wine SetCursorPos crashed Xwayland when
  # headless Weston had no pointer seat. Reproduce without an application/prefix.
  cat > pointer.c <<'C'
  #include <X11/Xlib.h>
  int main(void) {
    Display *d = XOpenDisplay(0);
    if (!d) return 1;
    Window root = DefaultRootWindow(d), returned_root, child;
    int rx, ry, wx, wy; unsigned mask;
    XWarpPointer(d, None, root, 0, 0, 0, 0, 320, 240);
    XSync(d, False);
    int ok = XQueryPointer(d, root, &returned_root, &child, &rx, &ry, &wx, &wy, &mask);
    XCloseDisplay(d);
    return !ok || rx != 320 || ry != 240;
  }
C
  cc -std=c11 -Wall -Wextra -Werror pointer.c -lX11 -o pointer-check
  spaghetti-headless-wayland ./pointer-check
  # Observe actual composed Xwayland pixels independently of GDI or any target.
  cat > colour.c <<'C'
  #include <X11/Xlib.h>
  #include <stdio.h>
  #include <unistd.h>
  int main(void) {
    Display *d = XOpenDisplay(0);
    if (!d) return 1;
    Window w = XCreateSimpleWindow(d, DefaultRootWindow(d), 0, 0, 160, 100, 0, 0, 0x3456ab);
    XSelectInput(d, w, ExposureMask);
    XMapRaised(d, w);
    XEvent event; XNextEvent(d, &event);
    XSync(d, False);
    FILE *ready = fopen("colour-ready", "w");
    if (!ready || fclose(ready)) return 2;
    for (;;) pause();
  }
C
  cc -std=c11 -Wall -Wextra -Werror colour.c -lX11 -o colour-window
  cat > capture-check.py <<'PYTEST'
from pathlib import Path
import os
import subprocess
import time
from PIL import Image

p = subprocess.Popen(['./colour-window'])
try:
    deadline = time.monotonic()+10
    while not Path('colour-ready').exists():
        assert p.poll() is None and time.monotonic()<deadline, 'colour window did not start'
        time.sleep(.02)
    # XSync orders X requests; Xwayland presentation remains asynchronous.
    for attempt in range(10):
        path = Path(f'desktop-{attempt}.png')
        subprocess.run([os.environ['SPAGHETTI_DESKTOP_CAPTURE'], str(path)], check=True, timeout=8)
        with Image.open(path) as image:
            colours = image.convert('RGB').getcolors(image.width*image.height)
        if any(count > 1000 and colour == (0x34, 0x56, 0xab) for count, colour in colours):
            break
        time.sleep(.05)
    else:
        raise AssertionError('compositor capture omitted the rendered window')
finally:
    p.terminate()
    p.wait(timeout=5)
PYTEST
  spaghetti-headless-wayland --capture python3 capture-check.py
  # Exercise actual Wayland startup and process transport without a Wine prefix.
  # The native ingress/candidate gates separately execute real PE32 programs.
  export DISPLAY=:9999
  export WAYLAND_DISPLAY=not-a-real-display
  export PULSE_SERVER=unix:/not-a-real-audio-server
  export PULSE_SINK=not-a-real-sink
  export PULSE_SOURCE=not-a-real-source
  set +e
  printf 'operator input\n' | spaghetti-headless-wayland bash -c '
    test "$WAYLAND_DISPLAY" = spaghetti-wayland || exit 81
    test "$DISPLAY" != :9999 || exit 82
    test -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" || exit 83
    test "$PULSE_SERVER" = "unix:$XDG_RUNTIME_DIR/pulse/native" || exit 84
    test "$(pactl get-default-sink)" = spaghetti_test || exit 85
    test "$(pactl get-default-source)" = spaghetti_test.monitor || exit 86
    test -z "''${SPAGHETTI_DESKTOP_CAPTURE:-}" || exit 87
    read -r line
    printf "%s\n" "$line"
    printf "application diagnostic\n" >&2
    printf "%s\n" "$XDG_RUNTIME_DIR" > runtime-path
    exit 7
  ' > observed.stdout 2> observed.stderr
  status=$?
  set -e
  if [ "$status" != 7 ]; then
    cat observed.stdout observed.stderr >&2
    echo "expected application exit 7, observed $status" >&2
    exit 1
  fi
  printf 'operator input\n' > expected.stdout
  printf 'application diagnostic\n' > expected.stderr
  cmp expected.stdout observed.stdout
  cmp expected.stderr observed.stderr
  test ! -e "$(cat runtime-path)"
  # Cancellation keeps the desktop available during a finite grace period,
  # escalates a TERM-ignoring application and returns its partial logs.
  python3 - <<'PYTEST'
import os
from pathlib import Path
import signal
import subprocess
import time

script = """
import os,signal,time
from pathlib import Path
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path('cancel-runtime').write_text(os.environ['XDG_RUNTIME_DIR'])
print('partial application output', flush=True)
Path('cancel-pid').write_text(str(os.getpid()))
while True: time.sleep(1)
"""
env = {**os.environ, 'SPAGHETTI_WAYLAND_CLEANUP_SECONDS': '1'}
p = subprocess.Popen(['spaghetti-headless-wayland', 'python3', '-c', script],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
try:
    deadline = time.monotonic()+20
    while not Path('cancel-pid').exists():
        if p.poll() is not None or time.monotonic()>deadline:
            raise AssertionError('command did not start')
        time.sleep(.02)
    started = time.monotonic()
    p.terminate()
    stdout, stderr = p.communicate(timeout=12)
    assert p.returncode == 143, (p.returncode, stderr)
    assert b'partial application output' in stdout, (stdout, stderr)
    assert not Path(Path('cancel-runtime').read_text()).exists()
    pid = int(Path('cancel-pid').read_text())
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise AssertionError('cancelled application remains alive')
    Path('cancel-seconds').write_text(str(time.monotonic()-started))
    # A launcher dies promptly while its child unwinds a runtime session.
    worker = """
import signal,time
from pathlib import Path
def stop(signum, frame):
    time.sleep(1.5)
    Path('child-cleanup-complete').write_text('done')
    raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
Path('child-ready').write_text('ready')
while True: time.sleep(1)
"""
    launcher = "import subprocess,sys; subprocess.run([sys.executable,'-c',sys.argv[1]])"
    p = subprocess.Popen(['spaghetti-headless-wayland','python3','-c',launcher,worker],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={**os.environ,'SPAGHETTI_WAYLAND_CLEANUP_SECONDS':'3'})
    deadline=time.monotonic()+20
    while not Path('child-ready').exists():
        assert p.poll() is None and time.monotonic()<deadline, 'child did not start'
        time.sleep(.02)
    p.terminate()
    stdout,stderr=p.communicate(timeout=15)
    assert p.returncode==143,(p.returncode,stderr)
    assert Path('child-cleanup-complete').read_text()=='done'

finally:
    if p.poll() is None:
        p.kill()
        p.communicate(timeout=2)
PYTEST
  # The documented persistent shell needs a real terminal, live output and job
  # control. Exercise one operator session rather than another program matrix.
  python3 - <<'PYTEST'
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import termios
import time

master, slave = pty.openpty()
termios.tcsetwinsize(slave, (24, 80))
settings = termios.tcgetattr(slave)
p = subprocess.Popen(
    ['spaghetti-headless-wayland', '--interactive', 'bash', '--noprofile', '--norc', '-i'],
    stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
    env={**os.environ, 'SPAGHETTI_WAYLAND_CLEANUP_SECONDS': '1'})
observed = bytearray()
pending = bytearray()

def receive(marker):
    deadline = time.monotonic() + 20
    while marker not in pending:
        assert time.monotonic() < deadline, (marker, bytes(observed))
        if select.select([master], [], [], .1)[0]:
            data = os.read(master, 65536)
            observed.extend(data)
            pending.extend(data)
        elif p.poll() is not None:
            raise AssertionError((p.returncode, bytes(observed)))
    end = pending.index(marker) + len(marker)
    del pending[:end]

try:
    Path('foreground.py').write_text("""
import os,signal,time
from pathlib import Path
def interrupt(signum, frame):
    raise SystemExit(130)
signal.signal(signal.SIGINT, interrupt)
Path('foreground-ready').write_text(str(os.getpid()))
time.sleep(30)
""")
    receive(b'$ ')
    os.write(master, b'PS1="spx-""ready> "\n')
    receive(b'spx-ready> ')
    # Split markers so echoed input cannot be mistaken for command output.
    os.write(master, b'test -t 0 && test -t 1 && test -t 2 && printf "terminal-%s\\n" ready; stty size; printf "%s" "$XDG_RUNTIME_DIR" > interactive-runtime\n')
    receive(b'terminal-ready\r\n')
    receive(b'24 80\r\n')
    receive(b'spx-ready> ')
    termios.tcsetwinsize(slave, (37, 101))
    os.kill(p.pid, signal.SIGWINCH)
    runtime = Path(Path('interactive-runtime').read_text())
    with Path((runtime/'terminal-device').read_text()).open('rb') as terminal:
        deadline = time.monotonic() + 5
        while termios.tcgetwinsize(terminal.fileno()) != (37, 101):
            assert time.monotonic() < deadline, 'terminal resize was not forwarded'
            time.sleep(.02)
    os.write(master, b'stty size\n')
    receive(b'37 101\r\n')
    receive(b'spx-ready> ')
    os.write(master, b'python3 foreground.py\n')
    # Echoed input is not evidence that a foreground job has started. Wait for
    # the child before interrupting; otherwise Ctrl-C can race shell job setup.
    deadline = time.monotonic()+10
    while not Path('foreground-ready').exists():
        assert p.poll() is None and time.monotonic()<deadline, 'foreground job did not start'
        time.sleep(.02)
    os.write(master, b'\x03')
    receive(b'spx-ready> ')
    os.write(master, b'printf "still-%s\\n" usable\n')
    receive(b'still-usable\r\n')
    receive(b'spx-ready> ')
    os.write(master, b'exit 7\n')
    assert p.wait(timeout=15) == 7, bytes(observed)
    assert termios.tcgetattr(slave) == settings, 'operator terminal settings changed'
    assert not Path(Path('interactive-runtime').read_text()).exists()
    Path('interactive.stdout').write_bytes(observed)
finally:
    if p.poll() is None:
        p.terminate()
        p.wait(timeout=15)
    os.close(master)
    os.close(slave)
PYTEST
  mkdir -p "$out"
  cp observed.stdout observed.stderr cancel-seconds interactive.stdout "$out/"
  echo pass > "$out/status"
''
