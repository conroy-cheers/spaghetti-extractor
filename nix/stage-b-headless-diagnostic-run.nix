{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  candidateBinary,
  nativeEnginePlan,
  nativeRuntimePackage,
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
  diagnosticPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.stage_b_native_diagnostic" ];
    name = "${namePrefix}-native-diagnostic-python-closure";
  };
  python = "${pythonEnv}/bin/python3";
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
    pythonEnv
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
  export PYTHONPATH=${diagnosticPythonSource}/src
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
    ${python} - \
      "$out/spaghetti-extractor-diagnostic.bin" \
      ${nativeEnginePlan} \
      ${nativeRuntimePackage}/native-runtime-package.json \
      "$out/diagnostic-decoded.json" <<'PY'
  import json
  import pathlib
  import sys

  from spaghetti_extractor.stage_b_native_diagnostic import (
      decode_stage_b_native_diagnostic_file,
  )

  diagnostic, engine, runtime, output = map(pathlib.Path, sys.argv[1:])
  payload = decode_stage_b_native_diagnostic_file(
      diagnostic,
      native_engine_plan=engine,
      native_runtime_package=runtime,
  )
  output.write_text(
      json.dumps(payload, indent=2, sort_keys=True) + "\n",
      encoding="ascii",
  )
  PY
    diagnostic_sha256="$(
      sha256sum "$out/spaghetti-extractor-diagnostic.bin" | cut -d ' ' -f 1
    )"
    decoded_sha256="$(
      sha256sum "$out/diagnostic-decoded.json" | cut -d ' ' -f 1
    )"
    diagnostic_json="$(${pkgs.jq}/bin/jq -n \
      --arg path spaghetti-extractor-diagnostic.bin \
      --arg sha256 "$diagnostic_sha256" \
      --arg decoded_path diagnostic-decoded.json \
      --arg decoded_sha256 "$decoded_sha256" \
      --slurpfile decoded "$out/diagnostic-decoded.json" \
      '{
        path: $path,
        sha256: $sha256,
        decoded: {path: $decoded_path, sha256: $decoded_sha256},
        failure: $decoded[0].failure,
        counts: $decoded[0].counts,
        static_context: $decoded[0].static_context
      }')"
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
      },
      authority: "diagnostic-only; no behavioral acceptance authority"
    }' >"$out/diagnostic-run.json"
  touch -d @1 "$out/"*
''
