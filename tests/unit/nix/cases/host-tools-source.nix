# Nix source contract for profile-capable host tools.
#
# The isolated fixture source is the same source root consumed by the Nix
# host-tool builders. Keep the provider schemas in that closure because the
# Rust provider crates embed them with include_str!.
{ lib, flakeRoot, d2bLib, ... }:

let
  schemaPaths = [
    "docs/reference/schemas/v3/providers/transport-azure-relay.transport-settings.json"
    "docs/reference/schemas/v3/providers/transport-vsock.transport-binding.json"
  ];
  filteredSource = d2bLib.cleanRustPackagesSource flakeRoot;
  fixtureSource =
    builtins.readFile (flakeRoot + "/bazel/checks/fixtures/BUILD.bazel");
  hostToolsSource =
    builtins.readFile (flakeRoot + "/nixos-modules/rust-host-tools.nix");
  vmEvaluatorSource =
    builtins.readFile (flakeRoot + "/nixos-modules/vm-evaluator.nix");
  flakeSource = builtins.readFile (flakeRoot + "/flake.nix");
  makeSource = builtins.readFile (flakeRoot + "/Makefile");
  bazelHostToolsSource =
    builtins.readFile (flakeRoot + "/nix/test-support/bazel-host-tools.nix");
  hostIntegrationLibSource =
    builtins.readFile (flakeRoot + "/tests/host-integration/lib.nix");
  acceptanceControllerBlock =
    let
      functionBlock =
        builtins.elemAt
          (lib.splitString
            "  mkAcceptanceProviderArtifact = pkgs:"
            hostIntegrationLibSource)
          1;
    in
    lib.replaceStrings [ "\n" "\r" ] [ " " "" ]
      (builtins.head (lib.splitString "      signer =" functionBlock));
  orderedUnique = source: needles:
    let
      result = lib.foldl'
        (state: needle:
          let
            pieces = lib.splitString needle state.rest;
            foundExactlyOnce = builtins.length pieces == 2;
          in
          {
            ok = state.ok && foundExactlyOnce;
            rest =
              if foundExactlyOnce then builtins.elemAt pieces 1 else "";
          })
        {
          ok = true;
          rest = source;
        }
        needles;
    in
    result.ok;
  hostSourceLines = lib.splitString "\n" hostToolsSource;
  hostSourceBuilderLines =
    lib.filter (line: lib.hasInfix "src = hostSource;" line) hostSourceLines;
in
{
  "host-tools-source/fixture-declares-provider-schemas" = {
    expr = lib.hasInfix ''"//:d2b_resource_schemas_v3"'' fixtureSource;
    expected = true;
  };

  "host-tools-source/filtered-source-has-provider-schemas" = {
    expr = lib.all
      (path: builtins.pathExists (filteredSource + "/${path}"))
      schemaPaths;
    expected = true;
  };

  "host-tools-source/profile-builders-use-schema-capable-source" = {
    expr = lib.hasInfix "cp -r " hostToolsSource
      && lib.hasInfix ''packagesSrc}/. "$out/"'' hostToolsSource
      && builtins.length hostSourceBuilderLines == 2;
    expected = true;
  };

  "host-tools-source/guest-evaluator-uses-host-tool-overrides" = {
    expr =
      lib.all (needle: lib.hasInfix needle vmEvaluatorSource) [
        "d2bHostTools = guestHostTools"
        "d2bHostToolOverrides = d2bHostToolOverrides"
      ]
      && lib.all (needle: lib.hasInfix needle flakeSource) [
        "d2bHostToolOverrides ? null"
        "inherit d2bHostToolOverrides"
        "evalGuest = args: self.lib.evalGuest (args //"
      ];
    expected = true;
  };

  "host-tools-source/acceptance-controller-uses-bazel-bundle" = {
    expr =
      lib.all (needle: lib.hasInfix needle bazelHostToolsSource) [
        ''"d2b-provider-test-controller"''
        "inventoryShell"
      ]
      && lib.all (needle: lib.hasInfix needle makeSource) [
        "//packages/d2b-provider-test-controller:d2b-provider-test-controller"
        "stage_tool packages/d2b-provider-test-controller/d2b-provider-test-controller d2b-provider-test-controller"
        ''D2B_HOST_TOOL_BUNDLE="$$stage"''
      ]
      && orderedUnique acceptanceControllerBlock [
        "controller = if hostToolBundle == null then"
        "self.packages."
        "d2b-provider-test-controller}/bin/d2b-provider-test-controller"
        "else"
        "hostToolBundle}/bin/d2b-provider-test-controller"
      ]
      && !(orderedUnique acceptanceControllerBlock [
        "controller = if hostToolBundle != null then"
        "hostToolBundle}"
        "else"
        "self.packages."
      ]);
    expected = true;
  };
}
