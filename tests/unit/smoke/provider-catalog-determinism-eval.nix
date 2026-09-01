# Build-level determinism proof for the Provider package catalog emitter.
#
# The drift gate compares a generator's committed output against a fresh run,
# which catches a generator that CHANGED. It cannot catch a generator that
# emits different bytes on two runs of the same input, because it only ever
# runs the generator once. That is the gap this file closes for the catalog
# emitter, and it is the shape later determinism obligations should follow.
#
# How this proves determinism rather than merely re-running one generator:
#
#   * Two INDEPENDENT evaluations. Each catalog is compiled by its own
#     `nixosSystem` evaluation, constructed from a separately built module
#     list. They are distinct thunks, so Nix cannot satisfy the second by
#     returning the memoised value of the first; the compilation genuinely
#     happens twice.
#
#   * DIFFERENT input construction reaching the SAME declared value. The first
#     evaluation authors its artifacts as an attribute-set literal in one
#     order; the second builds the same attribute set with `listToAttrs` over a
#     reversed list, and splits its declarations across two modules so the
#     option system merges them rather than reading them whole. A generator
#     that let authoring order, merge order, or attribute insertion order reach
#     its output produces different bytes here and fails.
#
#   * BYTE comparison, not structural comparison. The two catalogs are
#     serialised and compared as strings, so a difference in ordering or in
#     rendering is caught even where the two values would compare equal
#     structurally.
#
#   * A NEGATIVE control. A third evaluation authors a deliberately different
#     artifact set, and the check requires its bytes to DIFFER. Without that,
#     a comparison that had degenerated into comparing a constant against
#     itself would still pass, and the check would prove nothing.
#
# The result is a JSON evidence document; the flake check writes it to `$out`
# and throws at evaluation time on any mismatch, so `nix flake check
# --no-build` fails rather than producing an unbuilt derivation.
{ system ? builtins.currentSystem
, pkgs ? import <nixpkgs> { inherit system; }
, flake ? builtins.getFlake ("git+file://" + toString ./../../..)
}:

let
  inherit (pkgs) lib;
  nixosSystem = flake.inputs.nixpkgs.lib.nixosSystem;

  shape = import ../../../nixos-modules/generated/provider-catalog-shape.nix;

  base = { ... }: {
    boot.loader.grub.enable = false;
    boot.loader.systemd-boot.enable = false;
    boot.initrd.includeDefaultModules = false;
    fileSystems."/" = { device = "tmpfs"; fsType = "tmpfs"; };
    environment.etc."machine-id".text = "00000000000000000000000000000000";
    system.stateVersion = "25.11";
    users.users.alice = { isNormalUser = true; uid = 1000; };
    d2b.site = {
      waylandUser = "alice";
      launcherUsers = [ "alice" ];
    };
  };

  entryFor = name:
    let
      digestFields = lib.listToAttrs (map
        (field: lib.nameValuePair field
          ("sha256:" + builtins.hashString "sha256" "${name}/${field}"))
        shape.digestFields);
      plainFields = lib.listToAttrs (map
        (field: lib.nameValuePair field "${name}/${field}")
        (lib.filter (field: !(lib.elem field shape.digestFields)) shape.fields));
    in
    digestFields // plainFields;

  artifactFor = name: {
    package = pkgs.writeText "artifact-${name}" name;
    type = "provider";
    catalog = (entryFor name) // {
      publisher = "d2b-official";
      signature = {
        signatureId = "${name}-signature";
        publisherRoot = "d2b-official";
      };
      rootEpoch = 1;
      revocationStatus = "clear";
      denyStatus = "clear";
    };
  };

  names = [ "provider-audio" "provider-storage" "provider-wayland" ];
  providerMatrix = shape.providerMatrix;
  providerMatrixIds = map (row: row.provider) providerMatrix;

  digestProvider = pkgs.runCommand "artifact-provider-digest" { } ''
    mkdir -p "$out/bin" "$out/share/d2b/provider"
    printf 'provider\n' > "$out/bin/provider"
    chmod +x "$out/bin/provider"
    printf '{"name":"provider-digest"}\n' \
      > "$out/share/d2b/provider/manifest.json"
  '';
  digestSystem = pkgs.runCommand "artifact-system-digest" { } ''
    mkdir -p "$out/bin" "$out/etc"
    printf 'boot\n' > "$out/bin/boot"
    printf 'NAME=d2b-test\n' > "$out/etc/os-release"
  '';

  evaluate = modules: (nixosSystem {
    inherit system;
    modules = [ flake.nixosModules.default base ] ++ modules;
  }).config.d2b._providerCatalog.json;

  digestCatalog = (nixosSystem {
    inherit system;
    modules = [
      flake.nixosModules.default
      base
      {
        d2b.artifacts = {
          provider-digest = {
            package = digestProvider;
            type = "provider";
            catalog = entryFor "provider-digest";
          };
          system-digest = {
            package = digestSystem;
            type = "nixos-system";
            catalog = null;
          };
        };
      }
    ];
  }).config.d2b._artifactCatalogV3.catalogData;

  # Evaluation A: one module, attribute-set literal, one authoring order.
  catalogA = evaluate [
    ({ ... }: {
      d2b.artifacts = {
        provider-wayland = artifactFor "provider-wayland";
        provider-audio = artifactFor "provider-audio";
        provider-storage = artifactFor "provider-storage";
      };
    })
  ];

  # Evaluation B: the same declared value, reached differently. Built with
  # listToAttrs over the reversed name list, and split across two modules so
  # the option system merges the declarations.
  catalogB = evaluate [
    ({ ... }: {
      d2b.artifacts = lib.listToAttrs (map
        (name: lib.nameValuePair name (artifactFor name))
        (lib.reverseList (lib.take 2 names)));
    })
    ({ ... }: {
      d2b.artifacts = lib.listToAttrs (map
        (name: lib.nameValuePair name (artifactFor name))
        (lib.drop 2 names));
    })
  ];

  # The negative control: a genuinely different input must produce different
  # bytes, or the comparison above is vacuous.
  catalogDifferent = evaluate [
    ({ ... }: {
      d2b.artifacts = lib.listToAttrs (map
        (name: lib.nameValuePair name (artifactFor name))
        (names ++ [ "provider-network" ]));
    })
  ];

  identical = catalogA == catalogB;
  controlDiffers = catalogA != catalogDifferent;
  nonEmpty = catalogA != "" && lib.hasInfix "provider-wayland" catalogA;
  matrixClosed =
    builtins.length providerMatrix == 27
    && providerMatrixIds == shape.providerIds
    && builtins.length (lib.unique providerMatrixIds) == 27
    && shape.fixedBootstrapProviderIds == [ "system-core" "system-minijail" ];

  failures =
    (lib.optional (!identical)
      "two independent evaluations of the same declared catalog produced different bytes")
    ++ (lib.optional (!controlDiffers)
      "the negative control produced identical bytes; the comparison is vacuous")
    ++ (lib.optional (!nonEmpty)
      "the compiled catalog is empty; the comparison would be trivially true")
    ++ (lib.optional (!matrixClosed)
      "the closed Provider matrix is missing, reordered, or duplicated");
in
if failures != [ ] then
  throw ''
    provider-catalog-determinism FAILED for ${system}:
      ${lib.concatStringsSep "\n  " failures}
  ''
else
  builtins.toJSON {
    inherit system;
    evaluations = 3;
    deterministic = true;
    negativeControlDiffers = true;
    catalogBytes = builtins.stringLength catalogA;
    artifactIds = names;
    providerMatrixRows = builtins.length providerMatrix;
    providerMatrixIds = providerMatrixIds;
    fixedBootstrapProviderIds = shape.fixedBootstrapProviderIds;
    digestContract = {
      entries = digestCatalog.entries;
      providerPath = toString digestProvider;
      systemPath = toString digestSystem;
      systemExpected =
        "sha256:2073c4caf2fffb61dd80ff06ff1e6f45927e492c7b57b29fbc85624b3b09fac2";
    };
  }
