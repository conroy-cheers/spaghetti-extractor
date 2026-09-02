{
  pkgs,
  pythonPackages ? pkgs.python3Packages,
}:

let
  nativeSource = pkgs.lib.fileset.toSource {
    root = ../native;
    fileset = pkgs.lib.fileset.unions [
      ../native/Cargo.toml
      ../native/Cargo.lock
      ../native/pyproject.toml
      ../native/src/lib.rs
      ../native/src/abi_solver.rs
      ../native/src/artifact_json.rs
      ../native/src/library_index.rs
    ];
  };
in
pythonPackages.buildPythonPackage {
  pname = "spaghetti-extractor-native";
  version = "0.1.0";
  pyproject = true;
  src = nativeSource;

  cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
    src = nativeSource;
    hash = "sha256-8E341iDvt56FJkPd++kDB1gudXwBzesWWvMwP5zBTbY=";
  };

  build-system = [
    pkgs.rustPlatform.cargoSetupHook
    pkgs.rustPlatform.maturinBuildHook
  ];

  pythonImportsCheck = [ "spaghetti_extractor_native" ];
  doCheck = false;
}
