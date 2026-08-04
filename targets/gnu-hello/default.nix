{ pkgs, pythonEnv, pythonSource }:

let
  mingw = pkgs.pkgsCross.mingw32;
  source = pkgs.lib.fileset.toSource {
    root = ./source/idiomatic;
    fileset = ./source/idiomatic;
  };
in
{
  intent = import ../../nix/stage-b-target-intent.nix {
    inherit pkgs pythonEnv pythonSource;
    target = ./.;
  };

  idiomaticCandidate = mingw.stdenv.mkDerivation {
    pname = "spaghetti-extractor-gnu-hello-idiomatic";
    version = "2.12.3";
    src = source;
    dontConfigure = true;
    strictDeps = true;
    __contentAddressed = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra hello.c -o hello.exe
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin" "$out/share/spaghetti-extractor/gnu-hello"
      cp hello.exe "$out/bin/hello.exe"
      cp hello.c hello.h "$out/share/spaghetti-extractor/gnu-hello/"
    '';
  };
}
