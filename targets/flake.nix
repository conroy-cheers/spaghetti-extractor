{
  description = "Spaghetti Extractor validation target corpus";

  inputs = {
    # Keep the in-tree corpus on the same pinned package set as the toolkit.
    nixpkgs.url = "github:NixOS/nixpkgs/89570f24e97e614aa34aa9ab1c927b6578a43775";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    let
      targetPaths = import ./registry.nix;
      targetIds = builtins.attrNames targetPaths;
      directoryEntries = builtins.readDir ./.;
      discoveredTargetIds = builtins.filter (
        name: directoryEntries.${name} == "directory" && builtins.pathExists (./. + "/${name}/target.json")
      ) (builtins.attrNames directoryEntries);
      targetMetadata = builtins.mapAttrs (
        _: path: builtins.fromJSON (builtins.readFile (path + "/target.json"))
      ) targetPaths;
    in
    assert discoveredTargetIds == targetIds;
    assert builtins.all (id: targetMetadata.${id}.id == id) targetIds;
    assert builtins.all (
      id:
      targetMetadata.${id}.format == "spaghetti-extractor-target-bundle-v3"
      && (
        targetMetadata.${id}.workflow.default_configuration == null
        || builtins.isString targetMetadata.${id}.workflow.default_configuration
      )
    ) targetIds;
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];

      flake = {
        lib = {
          inherit targetIds targetMetadata;
        };
      };

      perSystem =
        { pkgs, system, ... }:
        let
          sdk = import ../nix/target-sdk.nix { inherit pkgs; };
          bundles = sdk.target.registry (
            builtins.mapAttrs (_: path: import path { inherit pkgs sdk; }) targetPaths
          );
          artifacts = builtins.mapAttrs (_: target: target.artifacts) bundles;
          targetChecks = builtins.mapAttrs (_: target: target.defaultCheck) bundles;
          targetAcceptanceChecks = builtins.mapAttrs (_: target: target.acceptanceCheck) bundles;
          operatorTargets = builtins.mapAttrs (_: target: target.operator) bundles;
          operatorIndex = builtins.mapAttrs (_: target: target.operatorIndex) bundles;
          checkAttrs = pkgs.lib.mapAttrs' (
            id: target: pkgs.lib.nameValuePair "target-${id}" target.defaultCheck
          ) bundles;
          helloSemanticLinkPerformance = import ../nix/linked-semantic-module-performance.nix {
            inherit pkgs;
            pythonEnv = sdk.validation.pythonEnv;
            semanticObject = "${bundles.gnu-hello.artifacts.candidate.semantic-object}/semantic-object.json";
            behavioralRoots = "${bundles.gnu-hello.artifacts.analysis.static-export}/behavioral-roots.json";
            original = "${bundles.gnu-hello.artifacts.input.original}/bin/hello.exe";
            canonical = "${bundles.gnu-hello.artifacts.candidate.linked-semantic-module}/linked-semantic-module.json";
            namePrefix = "spaghetti-extractor-gnu-hello";
          };
          corpusBoundary =
            pkgs.runCommand "spaghetti-extractor-target-corpus-boundary"
              { nativeBuildInputs = [ pkgs.ripgrep ]; }
              ''
                set -euo pipefail
                if rg -n '\.\./\.\./nix/' ${./.} --glob '*.nix' \
                    --glob '!flake.nix'; then
                  echo "target modules must consume the public SDK" >&2
                  exit 1
                fi
                if ! rg -q 'import ../nix/target-sdk[.]nix' ${./flake.nix}; then
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
              ../native
              ../src
              ../nix
              ../profiles
              ../tools
              ../targets
            ];
          };
          testRunner = pkgs.writeShellApplication {
            name = "spaghetti-extractor-target-test";
            runtimeInputs = [
              pkgs.nix
              sdk.package
            ];
            text = ''
              set -euo pipefail
              mode=regression
              if [ "''${1-}" = "--acceptance" ]; then
                mode=acceptance
                shift
              fi
              if [ "$#" -ne 1 ]; then
                echo "usage: spaghetti-extractor-target-test [--acceptance] <target-id>" >&2
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

              check_flags=()
              if [ "$mode" = acceptance ]; then
                check_flags=(--acceptance)
              fi
              spaghetti-extractor project check \
                "''${check_flags[@]}" \
                --target-flake "path:${consumerSource}?dir=targets" \
                "$target"
            '';
          };
        in
        {
          legacyPackages = {
            targets = artifacts;
            inherit
              operatorIndex
              operatorTargets
              targetChecks
              targetAcceptanceChecks
              ;
          };
          checks = checkAttrs // {
            corpus-boundary = corpusBoundary;
            target-gnu-hello-semantic-link-performance = helloSemanticLinkPerformance.derivation;
          };
          packages = {
            target-test-runner = testRunner;
          };
          apps.test = {
            type = "app";
            program = "${testRunner}/bin/spaghetti-extractor-target-test";
            meta.description = "Run one target regression gate, or its strict acceptance gate";
          };
        };
    };
}
