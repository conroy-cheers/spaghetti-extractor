{ pkgs }:

let
  capture = pkgs.writeShellApplication {
    name = "spaghetti-desktop-capture";
    runtimeInputs = [ pkgs.weston pkgs.coreutils ];
    text = ''
      if [ "$#" -ne 1 ]; then
        echo "usage: spaghetti-desktop-capture OUTPUT.png" >&2
        exit 2
      fi
      if [ -e "$1" ]; then
        echo "desktop capture output already exists: $1" >&2
        exit 2
      fi
      capture_dir=$(mktemp -d "$XDG_RUNTIME_DIR/capture.XXXXXX")
      trap 'rm -rf "$capture_dir"' EXIT
      # Weston names its output by date. Give this invocation a private directory
      # so repeated captures within one second cannot overwrite each other.
      XDG_PICTURES_DIR="$capture_dir" timeout 5 weston-screenshooter \
        --source-type=framebuffer --buffer-type=shm
      captures=("$capture_dir"/*.png)
      if [ "''${#captures[@]}" -ne 1 ] || [ ! -s "''${captures[0]}" ]; then
        echo "compositor did not produce one complete desktop capture" >&2
        exit 1
      fi
      mv -- "''${captures[0]}" "$1"
    '';
  };
  audioClientConfig = pkgs.writeText "spaghetti-pulse-client.conf" ''
    autospawn = no
    enable-shm = no
  '';
  # script supplies a controlling terminal and job control; inherit the size of
  # the operator's terminal before replacing this launcher with their command.
  terminal = pkgs.writeScript "spaghetti-wayland-terminal" ''
    #!${pkgs.python3}/bin/python3
    import os
    from pathlib import Path
    import sys
    import termios

    root = Path(sys.argv[1])
    termios.tcsetwinsize(0, tuple(map(int, (root/"terminal-size").read_text().split())))
    (root/"terminal-device").write_text(os.ttyname(0))
    (root/"command-pid").write_text(str(os.getpid()))
    try:
        os.execvp(sys.argv[2], sys.argv[2:])
    except OSError as error:
        print(error, file=sys.stderr)
        sys.exit(127)
  '';
  # Keep compositor diagnostics out of the application's observed streams and
  # retain its exit status: a compositor exiting normally is not test success.
  child = pkgs.writeScript "spaghetti-wayland-child" ''
    #!${pkgs.python3}/bin/python3
    import os
    from pathlib import Path
    import subprocess
    import sys

    root = Path(sys.argv[1])
    interactive = (root/"interactive").exists()
    command = sys.argv[2:]
    if interactive:
        command = ["${pkgs.util-linux}/bin/script", "--quiet", "--return",
            "--flush", "--echo=always", "/dev/null", "--", "${terminal}",
            str(root), *command]
    # The command owns a process group independent of Weston. The outer wrapper
    # forwards cancellation while keeping the desktop alive for runtime cleanup.
    with (root/"stdin").open("rb") as stdin, (root/"stdout").open("wb") as stdout, (root/"stderr").open("wb") as stderr:
        try:
            process = subprocess.Popen(command, stdin=stdin, stdout=stdout,
                stderr=stderr, start_new_session=True)
            if not interactive:
                (root/"command-pid").write_text(str(process.pid))
            code = process.wait()
            code = code if code >= 0 else 128 - code
        except OSError as error:
            stderr.write((str(error) + "\n").encode())
            code = 127
        (root/"status").write_text(str(code))
    sys.exit(code)
  '';
in
pkgs.writeShellApplication {
  name = "spaghetti-headless-wayland";
  runtimeInputs = [ pkgs.weston pkgs.coreutils pkgs.pulseaudio capture ];
  text = ''
    interactive=false
    capture_args=()
    unset SPAGHETTI_DESKTOP_CAPTURE
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --interactive) interactive=true; shift ;;
        --capture)
          capture_args=(--debug)
          export SPAGHETTI_DESKTOP_CAPTURE=${capture}/bin/spaghetti-desktop-capture
          shift ;;
        --) shift; break ;;
        *) break ;;
      esac
    done
    if "$interactive"; then
      if [ ! -t 0 ] || [ ! -t 1 ]; then
        echo "--interactive requires a terminal on stdin and stdout" >&2
        exit 2
      fi
    fi
    if [ "$#" -eq 0 ]; then
      echo "usage: spaghetti-headless-wayland [--interactive] [--capture] COMMAND [ARGUMENT ...]" >&2
      exit 2
    fi
    # UNIX socket paths are limited to 108 bytes. Nix build directories and
    # retained evidence paths can be longer, so use a private short runtime dir.
    work=$(mktemp -d /tmp/spx-wayland.XXXXXX)
    compositor=
    audio=
    input_process=
    output_process=
    terminal_settings=
    # This allowance includes Python runtime server/prefix cleanup. Tests may
    # choose a shorter deadline for a command that deliberately ignores TERM.
    cleanup_seconds=''${SPAGHETTI_WAYLAND_CLEANUP_SECONDS:-60}
    if ! [[ "$cleanup_seconds" =~ ^[0-9]+$ ]] || [ "$cleanup_seconds" -lt 1 ] || [ "$cleanup_seconds" -gt 60 ]; then
      echo "Wayland cleanup allowance must be 1..60 seconds" >&2
      rm -rf "$work"
      exit 2
    fi
    # Bound every wait, including a child that ignores graceful termination.
    # shellcheck disable=SC2329
    stop_process() {
      local pid=$1
      kill "$pid" 2>/dev/null || true
      timeout 2 tail --pid="$pid" -f /dev/null 2>/dev/null || true
      if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
        timeout 2 tail --pid="$pid" -f /dev/null 2>/dev/null || true
      fi
      if kill -0 "$pid" 2>/dev/null; then
        echo "headless Wayland helper did not terminate: $pid" >&2
        return 1
      else
        wait "$pid" 2>/dev/null || true
      fi
    }
    # Invoked on normal return as well as cancellation or startup failure.
    # shellcheck disable=SC2329
    cleanup() {
      local status=$1
      trap ':' TERM INT
      trap "" WINCH
      if [ -f "$work/command-pid" ]; then
        local command_pid
        command_pid=$(cat "$work/command-pid")
        if "$interactive"; then
          # An interactive shell gives foreground jobs their own process groups.
          # Keep its whole terminal session alive during the cleanup allowance.
          ${pkgs.procps}/bin/pkill -TERM -s "$command_pid" 2>/dev/null || true
          # shellcheck disable=SC2016
          timeout "$cleanup_seconds" ${pkgs.bash}/bin/bash -c '
            while ${pkgs.procps}/bin/pgrep -s "$1" >/dev/null; do sleep 0.1; done
          ' bash "$command_pid" || true
          ${pkgs.procps}/bin/pkill -KILL -s "$command_pid" 2>/dev/null || true
        else
          kill -TERM -- "-$command_pid" 2>/dev/null || true
          # A launcher may exit before a child has stopped its detached Wine
          # server. Wait for the whole application group, not just its leader.
          if kill -0 -- "-$command_pid" 2>/dev/null; then
            # shellcheck disable=SC2016
            timeout "$cleanup_seconds" ${pkgs.bash}/bin/bash -c '
              while kill -0 -- "-$1" 2>/dev/null; do sleep 0.1; done
            ' bash "$command_pid" || true
          fi
          kill -KILL -- "-$command_pid" 2>/dev/null || true
        fi
        timeout 2 tail --pid="$command_pid" -f /dev/null 2>/dev/null || true
        if kill -0 "$command_pid" 2>/dev/null; then
          echo "headless Wayland application cleanup failed" >&2
          if [ "$status" -eq 0 ]; then status=1; fi
        fi
      fi
      if [ -n "$compositor" ]; then
        stop_process "$compositor" || { if [ "$status" -eq 0 ]; then status=1; fi; }
      fi
      if [ -n "$audio" ]; then
        stop_process "$audio" || { if [ "$status" -eq 0 ]; then status=1; fi; }
      fi
      if [ -n "$input_process" ]; then
        stop_process "$input_process" || { if [ "$status" -eq 0 ]; then status=1; fi; }
      fi
      if [ -n "$output_process" ]; then
        # Drain the terminal stream after its writer closes, without replaying it.
        timeout 2 tail --pid="$output_process" -f /dev/null 2>/dev/null || true
        stop_process "$output_process" || { if [ "$status" -eq 0 ]; then status=1; fi; }
      fi
      if [ -n "$terminal_settings" ]; then stty "$terminal_settings" || true; fi
      # Preserve partial application logs on cancellation too.
      if [ -f "$work/stdout" ]; then head -c "$(stat -c %s "$work/stdout")" "$work/stdout"; fi
      if [ -f "$work/stderr" ]; then head -c "$(stat -c %s "$work/stderr")" "$work/stderr" >&2; fi
      rm -rf "$work"
      exit "$status"
    }
    trap 'cleanup "$?"' EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    # shellcheck disable=SC2329
    resize_terminal() {
      local rows columns
      read -r rows columns < <(stty size) || return 0
      printf '%s %s\n' "$rows" "$columns" > "$work/terminal-size"
      if [ -f "$work/terminal-device" ]; then
        stty -F "$(cat "$work/terminal-device")" rows "$rows" cols "$columns" 2>/dev/null || true
      fi
    }
    if "$interactive"; then
      terminal_settings=$(stty -g)
      touch "$work/interactive"
      resize_terminal
      trap resize_terminal WINCH
      mkfifo "$work/stdout"
      cat "$work/stdout" &
      output_process=$!
      # Ctrl-C belongs to the foreground terminal job, not the desktop wrapper.
      stty raw -echo
    fi
    export XDG_RUNTIME_DIR="$work"
    export FONTCONFIG_FILE=${pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; }}
    unset DISPLAY WAYLAND_DISPLAY
    # Supply a real software audio endpoint even in a sandbox with no sound
    # hardware or host Pulse/PipeWire service. Every candidate uses this same
    # private server; no application-specific DirectSound replacement is needed.
    mkdir -p "$work/pulse" "$work/pulse-state"
    : > "$work/pulse/daemon.conf"
    export PULSE_SERVER="unix:$work/pulse/native"
    export PULSE_SINK=spaghetti_test
    export PULSE_SOURCE=spaghetti_test.monitor
    export PULSE_COOKIE="$work/pulse/cookie"
    export PULSE_CLIENTCONFIG=${audioClientConfig}
    env -u PULSE_DLPATH PULSE_CONFIG_PATH="$work/pulse" \
      PULSE_RUNTIME_PATH="$work/pulse" PULSE_STATE_PATH="$work/pulse-state" \
      pulseaudio --daemonize=no --fail=yes --use-pid-file=no \
      --exit-idle-time=-1 --disable-shm=yes --realtime=no --high-priority=no \
      --log-target=stderr -n \
      --load="module-null-sink sink_name=spaghetti_test rate=48000 channels=2" \
      --load="module-native-protocol-unix socket=$work/pulse/native auth-anonymous=1 auth-cookie-enabled=0" \
      >"$work/audio.log" 2>&1 &
    audio=$!
    audio_ready=false
    for ((attempt=0; attempt<100; attempt++)); do
      if ! kill -0 "$audio" 2>/dev/null; then break; fi
      if timeout 1 pactl info >"$work/audio-info" 2>"$work/audio-client.log"; then
        audio_ready=true
        break
      fi
      sleep 0.1
    done
    if ! "$audio_ready"; then
      cat "$work/audio.log" "$work/audio-client.log" >&2
      echo "headless audio startup failed or timed out" >&2
      exit 1
    fi
    # Minimal Nix sandboxes do not have the conventional Xwayland socket dir.
    if [ ! -d /tmp/.X11-unix ]; then
      mkdir -m 1777 /tmp/.X11-unix || test -d /tmp/.X11-unix
    fi
    # Weston closes the launched client's stdin. A FIFO preserves streaming
    # input without buffering an interactive terminal to EOF before launch.
    mkfifo "$work/stdin"
    cat <&0 >"$work/stdin" &
    input_process=$!
    # Wine creates transient Xwayland surfaces during prefix startup. Weston
    # 15's kiosk shell crashed in active-surface selection for that workflow;
    # use the regular desktop shell for a multi-window headless desktop.
    # Xwayland needs a pointer seat even without physical input devices. Without
    # it, cursor warps from ordinary Win32 SetCursorPos crash the X server.
    # Capture/debug access is opt-in and confined to this private desktop.
    weston --backend=headless --fake-seat --renderer=pixman --xwayland "''${capture_args[@]}" \
      --shell=desktop-shell.so --socket=spaghetti-wayland --no-config \
      --log="$work/weston.log" -- ${child} "$work" "$@" \
      <&0 >"$work/compositor.stdout" 2>"$work/compositor.stderr" &
    compositor=$!
    # Startup must produce a command identity (or a terminal launch result).
    # Once started, the application/runner controls its execution deadline.
    for ((attempt=0; attempt<300; attempt++)); do
      if [ -f "$work/command-pid" ] || [ -f "$work/status" ] || ! kill -0 "$compositor" 2>/dev/null; then break; fi
      sleep 0.1
    done
    if [ ! -f "$work/command-pid" ] && [ ! -f "$work/status" ]; then
      cat "$work/weston.log" "$work/compositor.stderr" >&2
      echo "headless Wayland application startup failed or timed out" >&2
      exit 1
    fi
    # A terminal resize interrupts wait; keep waiting for actual desktop exit.
    while kill -0 "$compositor" 2>/dev/null; do wait "$compositor" || true; done
    compositor=
    if [ ! -f "$work/status" ]; then
      cat "$work/weston.log" "$work/compositor.stderr" >&2
      echo "headless Wayland command did not complete" >&2
      exit 1
    fi
    exit "$(cat "$work/status")"
  '';
}
