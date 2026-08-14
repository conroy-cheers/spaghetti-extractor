# spaghetti-extractor-python-role: proposal
{
  pkgs,
  pythonEnv,
  componentProposals,
  intent,
  namePrefix,
}:

let
  selectionSource = import ./python-module-closure.nix {
    phaseRole = "proposal";
    inherit pkgs;
    modules = [ "spaghetti_extractor.components.proposal_selection" ];
    name = "${namePrefix}-component-proposal-selection-python-closure";
  };
  preparation = pkgs.runCommand
    "${namePrefix}-component-proposal-selection-v1"
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export LC_ALL=C.UTF-8
      export SOURCE_DATE_EPOCH=1
      export PYTHONPATH=${selectionSource}/src
      mkdir -p "$out"
      ${pythonEnv}/bin/python3 - \
        ${componentProposals} \
        ${intent} \
        "$out/selected-proposals.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.components.proposal_selection import (
          write_component_proposal_selection_v1,
      )

      write_component_proposal_selection_v1(
          proposals=pathlib.Path(sys.argv[1]),
          intent=pathlib.Path(sys.argv[2]),
          out=pathlib.Path(sys.argv[3]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-proposal-selection-v1" and
        .status == "checked" and
        (.executes_original_binary | not) and
        (.authority.can_authorize_replacement | not) and
        (.selections | length) > 0 and
        (.selection_sha256 | type == "string")
      ' "$out/selected-proposals.json" >/dev/null
    '';
  # Controlled IFD: downstream component phases receive a store path whose
  # identity depends only on the selected resolution fields and authored
  # selectors. The complete proposal package remains a dependency of
  # preparation, never of resolution or any component contract.
  selectedProposals = builtins.toFile
    "${namePrefix}-selected-component-proposals-v1.json"
    (builtins.readFile "${preparation}/selected-proposals.json");
  payload = builtins.fromJSON (builtins.readFile selectedProposals);
in
assert payload.format == "spaghetti-extractor-component-proposal-selection-v1";
assert payload.status == "checked";
assert payload.executes_original_binary == false;
assert payload.authority.can_authorize_replacement == false;
{
  inherit preparation selectedProposals;
}
