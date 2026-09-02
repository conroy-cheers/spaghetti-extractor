# spaghetti-extractor-python-role: developer
{ pkgs
, pythonEnv
, source
, name ? "spaghetti-extractor-roundtrip"
, seed ? 0
, count ? 6
}:

let
  python = "${pythonEnv}/bin/python3";
  generatorPythonSource = import ./python-module-closure.nix {
    phaseRole = "developer";
    inherit pkgs;
    modules = [ "spaghetti_extractor.roundtrip_fuzz.generator" ];
    name = "${name}-generator-python-closure";
  };
  runnerPythonSource = import ./python-module-closure.nix {
    phaseRole = "developer";
    inherit pkgs;
    modules = [ "spaghetti_extractor.roundtrip_fuzz.runner" ];
    name = "${name}-runner-python-closure";
  };
  common = {
    nativeBuildInputs = [
      pythonEnv
      pkgs.pkgsCross.mingw32.stdenv.cc
      pkgs.pkgsCross.mingw32.buildPackages.binutils
    ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  };
  corpus = pkgs.runCommand "${name}-corpus" common ''
    export PYTHONPATH=${generatorPythonSource.pythonPath}
    ${python} - "$out" ${toString seed} ${toString count} <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.roundtrip_fuzz.generator import generate_spike_corpus

    generate_spike_corpus(
        out=pathlib.Path(sys.argv[1]), seed=int(sys.argv[2]), count=int(sys.argv[3])
    )
    PY
  '';
  qualification = pkgs.runCommand "${name}-qualification" (common // {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
  }) ''
    export PYTHONPATH=${runnerPythonSource.pythonPath}
    mkdir -p "$out"
    ${python} - ${corpus}/corpus.json "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.roundtrip_fuzz.runner import run_roundtrip_corpus

    run_roundtrip_corpus(corpus=pathlib.Path(sys.argv[1]), out=pathlib.Path(sys.argv[2]))
    PY
    jq -e '
      .format == "spaghetti-extractor-roundtrip-run-result-v2"
      and .status == "qualified"
      and .counts.cases == ${toString count}
      and .counts.expectations_matched == ${toString count}
    ' "$out/result.json" >/dev/null
    mkdir -p "$TMPDIR/replay"
    ${python} - ${corpus}/corpus.json "$TMPDIR/replay" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.roundtrip_fuzz.runner import run_roundtrip_corpus

    run_roundtrip_corpus(corpus=pathlib.Path(sys.argv[1]), out=pathlib.Path(sys.argv[2]))
    PY
    diff -ru "$out" "$TMPDIR/replay"
  '';
in
{
  inherit corpus qualification;
  aggregate = qualification;
}
