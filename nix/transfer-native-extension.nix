{
  pkgs,
  pythonPackages ? pkgs.python3Packages,
}:

let
  nativeSource = pkgs.lib.fileset.toSource {
    root = ../native;
    fileset = pkgs.lib.fileset.unions [
      ../native/transfer/Cargo.toml
      ../native/transfer/Cargo.lock
      ../native/transfer/pyproject.toml
      ../native/transfer/src/lib.rs
      ../native/src/reference_kernel.rs
      ../native/src/reference_plan.rs
    ];
  };
in
pythonPackages.buildPythonPackage {
  pname = "spaghetti-extractor-transfer-native";
  version = "0.1.0";
  pyproject = true;
  src = nativeSource;
  sourceRoot = "source/transfer";

  cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
    src = nativeSource;
    sourceRoot = "source/transfer";
    hash = "sha256-0l0kjCDfSKMoPsxSzhLpuXTNH3j1djdUCql07mofaeo=";
  };

  build-system = [
    pkgs.rustPlatform.cargoSetupHook
    pkgs.rustPlatform.maturinBuildHook
  ];

  pythonImportsCheck = [ "spaghetti_extractor_transfer_native" ];
  doCheck = false;
}
