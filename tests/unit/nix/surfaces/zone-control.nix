{ lib, pkgs, system, nixpkgs, inputs, d2bModule, d2bLib, flakeRoot, modules }:

import ../helpers/surface.nix {
  inherit lib pkgs system nixpkgs inputs d2bModule d2bLib flakeRoot modules;
  name = "zone-control";
  caseFiles = [
    ../cases/bundle-artifacts-compiler.nix
    ../cases/zone-control.nix
    ../cases/zone-link.nix
  ];
}
