# spaghetti-extractor-python-role: developer
{
  pkgs,
  pythonEnv,
  kernelCache,
  semanticKernel,
  isaFormInventory,
  bochsRunner,
  sharedISACampaign ? null,
  namePrefix ? "spaghetti-extractor",
}:

let
  isaCampaign =
    if sharedISACampaign != null then
      sharedISACampaign
    else
      import ./qualified-platform-isa-campaign.nix {
        inherit
          pkgs
          pythonEnv
          kernelCache
          semanticKernel
          isaFormInventory
          bochsRunner
          namePrefix
          ;
      };
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-qualified-platform-v1-release";
    kind = "qualified-platform";
    artifactName = "qualified-platform.json";
    expectedFormat = "spaghetti-extractor-qualified-platform-v1";
    allowedStatuses = [ "complete" ];
    pythonModules = [
      "spaghetti_extractor.qualified_platform.release"
      "spaghetti_extractor.qualified_platform.replay"
    ];
    phaseRole = "developer";
    inputs = {
      semantic_kernel = semanticKernel;
      isa_form_inventory = isaFormInventory;
      isa_form_replay = isaCampaign.replay;
      isa_form_qualification_certificate =
        isaCampaign.qualificationCertificate;
    };
    program = ''
      from spaghetti_extractor.qualified_platform.release import (
          write_qualified_platform_v1,
      )
      write_qualified_platform_v1(
          semantic_kernel=inputs["semantic_kernel"],
          isa_form_inventory=inputs["isa_form_inventory"],
          isa_form_replay=inputs["isa_form_replay"],
          isa_form_qualification_certificate=(
              inputs["isa_form_qualification_certificate"]
          ),
          out=output,
          link_member=True,
      )
    '';
  };
in
{
  inherit isaCampaign;
  inherit (phase) derivation manifest artifact phasePythonSource;
  qualifiedPlatform = phase.artifact;
}
