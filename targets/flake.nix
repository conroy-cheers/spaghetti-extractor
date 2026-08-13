{
  description = "Spaghetti Extractor validation target corpus";

  inputs = {
    # Keep the in-tree corpus on the same pinned package set as the toolkit.
    nixpkgs.url = "github:NixOS/nixpkgs/89570f24e97e614aa34aa9ab1c927b6578a43775";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs@{ flake-parts, ... }:
    let
      targetPaths = import ./registry.nix;
      targetIds = builtins.attrNames targetPaths;
      directoryEntries = builtins.readDir ./.;
      discoveredTargetIds = builtins.filter
        (name:
          directoryEntries.${name} == "directory"
          && builtins.pathExists (./. + "/${name}/target.json"))
        (builtins.attrNames directoryEntries);
      targetMetadata = builtins.mapAttrs
        (_: path: builtins.fromJSON (builtins.readFile (path + "/target.json")))
        targetPaths;
    in
    assert discoveredTargetIds == targetIds;
    assert builtins.all (id: targetMetadata.${id}.id == id) targetIds;
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];

      flake = {
        lib = {
          inherit targetIds targetMetadata;
        };
      };

      perSystem = { pkgs, system, ... }:
        let
          sdk = import ../nix/target-sdk-v1.nix { inherit pkgs; };
          bundles = sdk.target.registry (builtins.mapAttrs
            (_: path: import path { inherit pkgs sdk; })
            targetPaths);
          artifacts = builtins.mapAttrs (_: target: target.artifacts) bundles;
          targetChecks = builtins.mapAttrs (_: target: target.defaultCheck) bundles;
          checkAttrs = pkgs.lib.mapAttrs'
            (id: target: pkgs.lib.nameValuePair "target-${id}" target.defaultCheck)
            bundles;
          corpusBoundary = pkgs.runCommand
            "spaghetti-extractor-target-corpus-boundary"
            { nativeBuildInputs = [ pkgs.ripgrep ]; }
            ''
              set -euo pipefail
              if rg -n '\.\./\.\./nix/' ${./.} --glob '*.nix' \
                  --glob '!flake.nix'; then
                echo "target modules must consume the public SDK" >&2
                exit 1
              fi
              if ! rg -q 'import ../nix/target-sdk-v1[.]nix' ${./flake.nix}; then
                echo "consumer flake must use the public target SDK entrypoint" >&2
                exit 1
              fi
              touch "$out"
            '';
          acceptedIds = pkgs.lib.concatStringsSep "|" targetIds;
          consumerSource = pkgs.lib.fileset.toSource {
            root = ../.;
            fileset = pkgs.lib.fileset.unions [
              ../pyproject.toml
              ../src
              ../nix
              ../profiles
              ../tools
              ../targets
            ];
          };
          testRunner = pkgs.writeShellApplication {
            name = "spaghetti-extractor-target-test";
            runtimeInputs = [ ];
            text = ''
              set -euo pipefail
              if [ "$#" -ne 1 ]; then
                echo "usage: spaghetti-extractor-target-test <target-id>" >&2
                echo "available targets: ${pkgs.lib.concatStringsSep ", " targetIds}" >&2
                exit 2
              fi
              target="$1"
              case "$target" in
                ${acceptedIds}) ;;
                *)
                  echo "unknown validation target: $target" >&2
                  echo "available targets: ${pkgs.lib.concatStringsSep ", " targetIds}" >&2
                  exit 2
                  ;;
              esac

              toolkit_repository="$PWD"
              if [ ! -d "$toolkit_repository/src/spaghetti_extractor" ] \
                  && [ -d "$toolkit_repository/../src/spaghetti_extractor" ]; then
                toolkit_repository="$(cd "$toolkit_repository/.." && pwd)"
              fi
              if [ ! -d "$toolkit_repository/src/spaghetti_extractor" ]; then
                toolkit_repository=${consumerSource}
              fi
              ${sdk.validation.testRunner}/bin/spaghetti-extractor-test \
                smoke --repository "$toolkit_repository"

              builder_flags=()
              if [ -f ${consumerSource}/nix/stage-a-builders ]; then
                builder_flags=(
                  --builders @${consumerSource}/nix/stage-a-builders
                  --option builders-use-substitutes true
                )
              fi
              nix --extra-experimental-features "nix-command flakes ca-derivations" \
                build --no-link \
                "path:${consumerSource}?dir=targets#legacyPackages.${system}.targetChecks.$target" \
                "''${builder_flags[@]}"
            '';
          };
        in
        {
          legacyPackages = {
            targets = artifacts;
            inherit targetChecks;
          };
          checks = checkAttrs // { corpus-boundary = corpusBoundary; };
          packages.target-test-runner = testRunner;
          apps.test = {
            type = "app";
            program = "${testRunner}/bin/spaghetti-extractor-target-test";
            meta.description = "Run generic smoke validation followed by one target bundle check";
          };
        };
    };
}
