{
  pkgs,
  namePrefix,
  candidateBinary,
  runtimeAssets,
  executableName ? "candidate.exe",
  timeoutSeconds ? 45,
  screenshotAfterSeconds ? 10,
  inputAfterSeconds ? 5,
  inputKeys ? [ ],
  wineDebug ? "-all",
}:

let
  wine = pkgs.wineWow64Packages.stableFull;
in
assert builtins.isString namePrefix && namePrefix != "";
assert builtins.match "[A-Za-z0-9._-]+\\.exe" executableName != null;
assert builtins.isInt timeoutSeconds && timeoutSeconds > 0;
assert builtins.isInt screenshotAfterSeconds && screenshotAfterSeconds > 0;
assert screenshotAfterSeconds < timeoutSeconds;
assert builtins.isInt inputAfterSeconds && inputAfterSeconds > 0;
assert inputKeys == [ ] || inputAfterSeconds < screenshotAfterSeconds;
assert builtins.all builtins.isString inputKeys;
let
  inputScript = pkgs.lib.optionalString (inputKeys != [ ]) ''
    sleep ${toString inputAfterSeconds}
    ${pkgs.lib.concatMapStringsSep "\n" (key:
      "xdotool key --clearmodifiers ${pkgs.lib.escapeShellArg key}"
    ) inputKeys}
    sleep ${toString (screenshotAfterSeconds - inputAfterSeconds)}
  '';
  screenshotWait = if inputKeys == [ ] then screenshotAfterSeconds else 0;
in
pkgs.runCommand "${namePrefix}-headless-diagnostic-run-v1" {
  nativeBuildInputs = [
    wine
    pkgs.coreutils
    pkgs.imagemagick
    pkgs.jq
    pkgs.xvfb-run
    pkgs.xwd
    pkgs.xdotool
  ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export HOME="$TMPDIR/home"
  export WINEPREFIX="$TMPDIR/wine"
  export WINEDEBUG=${pkgs.lib.escapeShellArg wineDebug}
  export WINEDLLOVERRIDES="mscoree,mshtml="
  work="$TMPDIR/candidate"
  mkdir -p "$HOME" "$work" "$out"
  cp -a ${runtimeAssets}/. "$work/"
  chmod -R u+w "$work"
  cp ${candidateBinary} "$work/${executableName}"

  xvfb-run -a -s '-screen 0 640x480x24' \
    wineboot -u >"$TMPDIR/wineboot.stdout" 2>"$TMPDIR/wineboot.stderr"
  set +e
  xvfb-run -a -s '-screen 0 640x480x24' \
    sh -c '
      cd "$1"
      timeout "$2"s wine "./$3" &
      candidate_pid=$!
      ${inputScript}
      sleep "$4"
      if kill -0 "$candidate_pid" 2>/dev/null; then
        xwd -root -silent -out "$5" || true
      fi
      wait "$candidate_pid"
    ' sh "$work" ${toString timeoutSeconds} \
      ${pkgs.lib.escapeShellArg executableName} \
      ${toString screenshotWait} "$TMPDIR/candidate-screen.xwd" \
    >"$TMPDIR/candidate.stdout" 2>"$TMPDIR/candidate.stderr"
  candidate_status=$?
  set -e

  cp "$TMPDIR/candidate.stdout" "$out/"
  cp "$TMPDIR/candidate.stderr" "$out/"
  cp "$TMPDIR/wineboot.stdout" "$out/"
  cp "$TMPDIR/wineboot.stderr" "$out/"
  if test "$candidate_status" -eq 124; then
    run_status=candidate-running-at-timeout
  elif test "$candidate_status" -eq 0; then
    run_status=candidate-exited-successfully
  else
    run_status=candidate-exited-with-error
  fi
  if test -s "$work/spaghetti-extractor-diagnostic.bin"; then
    cp "$work/spaghetti-extractor-diagnostic.bin" "$out/"
    diagnostic_sha256="$(
      sha256sum "$out/spaghetti-extractor-diagnostic.bin" | cut -d ' ' -f 1
    )"
    diagnostic_json="$(${pkgs.jq}/bin/jq -n \
      --arg path spaghetti-extractor-diagnostic.bin \
      --arg sha256 "$diagnostic_sha256" \
      '{path: $path, sha256: $sha256}')"
  else
    diagnostic_json=null
  fi
  if test -s "$TMPDIR/candidate-screen.xwd"; then
    magick "$TMPDIR/candidate-screen.xwd" -strip \
      -define png:exclude-chunk=time,date \
      "$out/candidate-screen.png"
    screenshot_sha256="$(
      sha256sum "$out/candidate-screen.png" | cut -d ' ' -f 1
    )"
    screenshot_json="$(${pkgs.jq}/bin/jq -n \
      --arg path candidate-screen.png \
      --arg sha256 "$screenshot_sha256" \
      --argjson after_seconds ${toString screenshotAfterSeconds} \
      --argjson scripted_key_count ${toString (builtins.length inputKeys)} \
      '{
        path: $path,
        sha256: $sha256,
        after_seconds: $after_seconds,
        scripted_key_count: $scripted_key_count
      }')"
  else
    screenshot_json=null
  fi
  ${pkgs.jq}/bin/jq -n \
    --arg format stage-b-headless-diagnostic-run-v1 \
    --arg status "$run_status" \
    --argjson candidate_status "$candidate_status" \
    --argjson diagnostic "$diagnostic_json" \
    --argjson screenshot "$screenshot_json" \
    --argjson original_runtime_observations false \
    '{
      format: $format,
      status: $status,
      candidate_status: $candidate_status,
      diagnostic: $diagnostic,
      screenshot: $screenshot,
      oracle: {
        original_runtime_observations: $original_runtime_observations,
        candidate_only: true
      }
    }' >"$out/diagnostic-run.json"
  touch -d @1 "$out/"*
''
