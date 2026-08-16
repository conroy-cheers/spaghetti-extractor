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
      ../native/src
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
    hash = "sha256-Wzqhu6aLDeArZ97RQ+m4i2zgwfyCuXU61XTU/LFHN4o=";
  };

  build-system = [
    pkgs.rustPlatform.cargoSetupHook
    pkgs.rustPlatform.maturinBuildHook
  ];

  pythonImportsCheck = [ "spaghetti_extractor_native" ];
  doCheck = false;
}
