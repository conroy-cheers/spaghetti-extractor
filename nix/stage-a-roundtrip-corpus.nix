{ pkgs
, pythonEnv
, source
, name ? "spaghetti-extractor-roundtrip"
, seed ? 0
, count ? 6
}:

let
  python = "${pythonEnv}/bin/python3";
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
    export PYTHONPATH=${source}/src
    ${python} -m spaghetti_extractor.cli roundtrip-generate \
      --out "$out" --seed ${toString seed} --count ${toString count}
  '';
  qualification = pkgs.runCommand "${name}-qualification" (common // {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
  }) ''
    export PYTHONPATH=${source}/src
    mkdir -p "$out"
    ${python} -m spaghetti_extractor.cli roundtrip-run \
      --corpus ${corpus}/corpus.json --out "$out"
    jq -e '
      .format == "stage-a-roundtrip-run-result-v2"
      and .status == "qualified"
      and .counts.cases == ${toString count}
      and .counts.expectations_matched == ${toString count}
    ' "$out/result.json" >/dev/null
  '';
in
{
  inherit corpus qualification;
  aggregate = qualification;
}
