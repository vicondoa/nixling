{ lib, pkgs, system, nixpkgs, inputs, d2bModule, d2bLib, flakeRoot, modules }:

import ../helpers/surface.nix {
  inherit lib pkgs system nixpkgs inputs d2bModule d2bLib flakeRoot modules;
  name = "provider-catalog";
  caseFiles = [{
    path = ../cases/provider-elf-shim.nix;
    names = [ "provider-elf-shim/positive-constructor" ];
  } {
    path = ../cases/provider-catalog.nix;
    names = [
      "provider-catalog/closed-27-row-matrix"
      "provider-catalog/extra-provider-id-fails-closed"
      "provider-catalog/non-matrix-artifact-stays-artifact-only"
      "provider-catalog/signed-placement-and-runtime-contract-is-retained"
      "provider-catalog/signed-placement-contract-fails-closed-on-target-drift"
      "provider-catalog/null-catalog-has-no-signed-contract"
    ];
  } {
    path = ../cases/provider-runtime-contracts.nix;
  }];
}
