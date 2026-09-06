# The offline artifact catalog.
#
# `ADR-046-provider-model-and-packaging`, "Package catalog": Nix authoring
# declares each Provider derivation separately under `d2b.artifacts.<id>`, and
# a Provider ResourceSpec then selects one by `artifactId`. Nix compiles those
# declarations into an offline, sorted, exact-digest catalog.
#
# Three absences are the design and not omissions:
#
#   * There is no runtime marketplace and no download. Every artifact is a
#     store path this evaluation already has.
#   * There is no PATH scan and no directory discovery. An artifact exists in
#     the catalog only because it was authored.
#   * There is no `latest` and no version-range solving. Selection is by exact
#     digest, and an `artifactId` that names nothing is an error rather than a
#     resolution problem.
#
# `artifactId` is a plain bounded ID, not a ResourceRef, and Artifact is not a
# ResourceType. Provider packages and generic NixOS systems are distinct closed
# artifact kinds. The catalog may retain a store path for activation; the public
# projection strips it, because a resource spec, status, or audit record never
# exposes one.

{ config, lib, pkgs, ... }:

let
  types = lib.types;
  cfg = config.d2b;

  # The generated frozen entry shape. Generated rather than written here so
  # this module and any later consumer cannot drift apart silently.
  shape = import ./generated/provider-catalog-shape.nix;

  # `artifactId` grammar: a plain bounded ID. Lowercase alphanumerics and
  # hyphens, starting with a letter, so it can never be confused with a
  # ResourceRef and never needs quoting.
  artifactIdPattern = "[a-z][a-z0-9-]*";
  maxArtifactIdLength = 64;

  # A digest is recorded as an algorithm-qualified lowercase hex string. The
  # shape is pinned here rather than left free-form because exact-digest
  # selection compares these values literally.
  digestPattern = "sha256:[0-9a-f]{64}";
  signedContractFields = shape.placementContractFields
    ++ shape.runtimeContractFields;
  trustContractFields = shape.trustFields or [
    "trustEpoch"
    "revocationRef"
    "publisherRoot"
    "signatureId"
    "conformanceAttestationDigest"
  ];
  catalogFields = shape.fields ++ signedContractFields ++ trustContractFields;
  publicCatalogFields = shape.fields ++ signedContractFields;
  providerIds = shape.providerIds or [ ];
  fixedBootstrapProviderIds = shape.fixedBootstrapProviderIds or [ ];

  artifactModule = types.submodule ({ name, config, ... }: {
    options = {
      package = lib.mkOption {
        type = types.package;
        description = ''
          The derivation providing this artifact. Declared by the consumer's
          own Nix authoring, typically from a flake input.
        '';
      };

      type = lib.mkOption {
        type = types.enum [
          "provider"
          "nixos-system"
          "nixos-module-set"
          "config-bundle"
        ];
        default = "provider";
        description = ''
          The artifact kind. Provider packages and generic NixOS systems are
          separate closed kinds; the option is an enum so a new kind remains
          an explicit decision rather than a free string.
        '';
      };

      catalog = lib.mkOption {
        type = types.nullOr (types.attrsOf types.anything);
        default = null;
        description = ''
          The catalog entry for this artifact: the frozen field set from the
          specification's "Package catalog" section. Every field in
          `fields` must be present, and every digest field must carry an
          `sha256:<64 hex>` value, because selection is by exact digest.
        '';
      };

      artifactId = lib.mkOption {
        type = types.str;
        default = name;
        readOnly = true;
        description = "The authored identifier, which is the attribute name.";
      };
    };
  });

  artifacts = cfg.artifacts;
  artifactIds = lib.sort (a: b: a < b) (lib.attrNames artifacts);

  # The catalog: sorted by artifactId, so the emitted order is a function of
  # the identifiers alone and not of the order the consumer happened to declare
  # them in. This is what makes two independent evaluations of the same
  # declarations produce the same bytes.
  entries = map
    (id:
      let artifact = artifacts.${id};
      in {
        inherit id;
        inherit (artifact) type;
        storePath = "${artifact.package}";
        entry =
          if artifact.catalog == null
          then { }
          else lib.filterAttrs (fieldName: _: lib.elem fieldName catalogFields) artifact.catalog;
      })
    artifactIds;

  # The public projection. `storePath` is private catalog data retained for
  # activation and is stripped here, because a resource spec, status, or audit
  # record never exposes a store path or the private trust envelope.
  publicEntries = map
    (e: {
      inherit (e) id type;
      entry = lib.filterAttrs
        (fieldName: _: lib.elem fieldName publicCatalogFields)
        e.entry;
    })
    entries;

  # The provider catalog is a separate public document.  It carries only the
  # frozen package metadata; private store locations remain in the artifact
  # catalog used by activation.
  providerEntries = lib.filter (entry: entry.type == "provider") publicEntries;
  providerCatalogEntries = lib.sort
    (left: right:
      let
        leftName = left.entry.providerName or left.id;
        rightName = right.entry.providerName or right.id;
      in leftName < rightName)
    providerEntries;
  providerCatalogData = {
    schemaVersion = "v1";
    entries = map
      (entry: {
        providerName = entry.entry.providerName or entry.id;
        artifactId = entry.id;
      } // entry.entry)
      providerCatalogEntries;
  };
  providerCatalogJson = builtins.toJSON providerCatalogData;
  providerCatalogPath = pkgs.writeText "d2b-provider-catalog.json" providerCatalogJson;

  catalogJson = builtins.toJSON {
    excludedMechanisms = shape.excludedMechanisms;
    entries = publicEntries;
  };

  missingFields = id:
    if artifacts.${id}.catalog == null
    then [ ]
    else lib.filter (field: !(artifacts.${id}.catalog ? ${field})) shape.fields;

  unknownFields = id:
    if artifacts.${id}.catalog == null
    then [ ]
    else lib.filter (field: !(lib.elem field catalogFields))
      (lib.attrNames artifacts.${id}.catalog);

  badDigests = id:
    if artifacts.${id}.catalog == null
    then [ ]
    else lib.filter
      (field:
        let value = artifacts.${id}.catalog.${field} or null;
        in value == null || builtins.match digestPattern (toString value) == null)
      shape.digestFields;

  targetKinds = [ "zone" "host" "guest" ];
  effectClasses = [
    "runtime"
    "transport"
    "substrate"
    "process"
    "volume"
    "storage"
    "network"
    "device"
    "display"
    "audio"
    "credential"
    "observability"
  ];
  placementScopes = [
    "zone-singleton"
    "fixed-execution-target"
    "per-resource-target"
  ];
  placementAnchors = [ "zone" "execution-ref" ];
  targetCapabilityKeys = [
    "artifactDigest"
    "requiredEffectClasses"
    "targetKind"
  ];
  validContractDigest = value:
    builtins.isString value && builtins.match digestPattern value != null;

  attrOr = attrs: name: fallback:
    if builtins.isAttrs attrs && builtins.hasAttr name attrs
    then attrs.${name}
    else fallback;

  firstAttr = attrs: names: fallback:
    if names == [ ]
    then fallback
    else
      let name = builtins.head names;
      in if builtins.isAttrs attrs && builtins.hasAttr name attrs
      then attrs.${name}
      else firstAttr attrs (lib.tail names) fallback;

  trustFieldsPresent = catalog:
    lib.any (field: builtins.hasAttr field catalog)
      ([ "signature" "rootEpoch" "revocationStatus" "denyStatus" ]
        ++ trustContractFields);

  trustAssertions = id:
    let
      catalog =
        if builtins.isAttrs artifacts.${id}.catalog
        then artifacts.${id}.catalog
        else { };
      signatureValue = catalog.signature or null;
      signature =
        if builtins.isAttrs signatureValue
        then signatureValue
        else { };
      nestedSignatureId = firstAttr signature [ "signatureId" "id" ] null;
      catalogSignatureId = attrOr catalog "signatureId" null;
      signatureId = firstAttr catalog [ "signatureId" ] nestedSignatureId;
      publisher = attrOr catalog "publisher" null;
      nestedPublisherRoot =
        firstAttr signature [ "publisherRoot" "root" ] null;
      catalogPublisherRoot = attrOr catalog "publisherRoot" null;
      publisherRoot = firstAttr catalog [ "publisherRoot" ]
        (firstAttr signature [ "publisherRoot" "root" ] publisher);
      rootEpoch = firstAttr catalog [ "trustEpoch" "rootEpoch" ] null;
      legacyRootEpoch = attrOr catalog "rootEpoch" null;
      revocationRef = attrOr catalog "revocationRef" null;
      revocationStatus = attrOr catalog "revocationStatus" null;
      denyStatus = attrOr catalog "denyStatus" null;
      present = artifacts.${id}.type == "provider"
        && trustFieldsPresent catalog;
    in
    lib.optionals present [
      {
        assertion = builtins.isString publisher
          && builtins.match artifactIdPattern publisher != null;
        message = ''
          d2b.artifacts."${id}".catalog.publisher must be a bounded publisher ID
          when trust metadata is published.
        '';
      }
      {
        assertion = builtins.isString signatureId
          && builtins.stringLength signatureId > 0
          && builtins.stringLength signatureId <= 128;
        message = ''
          d2b.artifacts."${id}".catalog signatureId must be non-empty and
          bounded under its publisher root.
        '';
      }
      {
        assertion = catalogSignatureId == null
          || nestedSignatureId == null
          || catalogSignatureId == nestedSignatureId;
        message = ''
          d2b.artifacts."${id}".catalog publisher root/signature ID aliases
          disagree; signature identity must be exact.
        '';
      }
      {
        assertion = builtins.isString publisherRoot
          && builtins.stringLength publisherRoot > 0
          && publisherRoot == publisher;
        message = ''
          d2b.artifacts."${id}".catalog publisher root must match publisher;
          a different root is not an admissible signature identity.
        '';
      }
      {
        assertion = catalogPublisherRoot == null
          || nestedPublisherRoot == null
          || catalogPublisherRoot == nestedPublisherRoot;
        message = ''
          d2b.artifacts."${id}".catalog publisher root aliases disagree;
          signature identity must be exact.
        '';
      }
      {
        assertion = builtins.isInt rootEpoch && rootEpoch >= 1
          && (legacyRootEpoch == null || rootEpoch == legacyRootEpoch);
        message = ''
          d2b.artifacts."${id}".catalog trust epoch must be a positive integer
          and trustEpoch/rootEpoch aliases must agree.
        '';
      }
      {
        assertion = revocationRef == null
          || (builtins.isString revocationRef
            && builtins.stringLength revocationRef > 0
            && builtins.stringLength revocationRef <= 256);
        message = ''
          d2b.artifacts."${id}".catalog revocationRef must be null or a
          bounded non-empty token.
        '';
      }
      {
        assertion = revocationStatus == "clear";
        message = ''
          d2b.artifacts."${id}".catalog revocation status must be clear;
          revoked or unknown artifacts fail closed.
        '';
      }
      {
        assertion = denyStatus == "clear";
        message = ''
          d2b.artifacts."${id}".catalog deny status must be clear; emergency
          denied artifacts fail closed.
        '';
      }
      {
        assertion = !(builtins.hasAttr "conformanceAttestationDigest" catalog)
          || validContractDigest catalog.conformanceAttestationDigest;
        message = ''
          d2b.artifacts."${id}".catalog conformanceAttestationDigest must be
          a lowercase sha256 digest.
        '';
      }
    ];

  providerMatrixAssertions =
    let
      declared = cfg.providerCatalog or { };
      rows = lib.mapAttrsToList
        (name: entry: {
          inherit name entry;
          path = "d2b.providerCatalog.${name}";
        })
        declared;
      unknown = lib.filter
        (row: !(builtins.elem (row.entry.artifactId or null) providerIds))
        rows;
    in
    lib.optionals (rows != [ ]) [
      {
        assertion = unknown == [ ];
        message = ''
          d2b.providerCatalog contains an identity outside the closed 27-row
          Provider matrix: ${lib.concatStringsSep ", " (map
            (row: row.name) unknown)}.
        '';
      }
    ];

  signedContractAssertions = id:
    let
      catalog =
        if builtins.isAttrs artifacts.${id}.catalog
        then artifacts.${id}.catalog
        else { };
      placementPresent = lib.any
        (field: builtins.hasAttr field catalog)
        shape.placementContractFields;
      runtimePresent = lib.any
        (field: builtins.hasAttr field catalog)
        shape.runtimeContractFields;
      scope = catalog.instanceScope or null;
      supported =
        if builtins.isList (catalog.supportedTargetKinds or null)
        then catalog.supportedTargetKinds
        else [ ];
      capabilities =
        if builtins.isList (catalog.targetCapabilities or null)
        then catalog.targetCapabilities
        else [ ];
      capabilityTargets = map
        (capability:
          if builtins.isAttrs capability
          then capability.targetKind or null
          else null)
        capabilities;
      capabilityValid = capability:
        let
          effects =
            if builtins.isAttrs capability
              && builtins.isList (capability.requiredEffectClasses or null)
            then capability.requiredEffectClasses
            else [ ];
        in
        builtins.isAttrs capability
        && lib.sort lib.lessThan (lib.attrNames capability) == targetCapabilityKeys
        && builtins.elem (capability.targetKind or null) targetKinds
        && validContractDigest (capability.artifactDigest or null)
        && builtins.isList (capability.requiredEffectClasses or null)
        && lib.length (lib.unique effects) == lib.length effects
        && lib.all (class: builtins.elem class effectClasses) effects;
      scopeShape =
        if scope == "zone-singleton"
        then supported == [ "zone" ] && capabilities != [ ]
        else if scope == "fixed-execution-target"
        then lib.length supported == 1 && !(builtins.elem "zone" supported)
        else if scope == "per-resource-target"
        then supported != [ ] && !(builtins.elem "zone" supported)
        else false;
    in
    (lib.optionals placementPresent [
      {
        assertion = lib.all
          (field: builtins.hasAttr field catalog)
          shape.placementContractFields;
        message = ''
          d2b.artifacts."${id}".catalog must carry the complete signed
          controller placement contract (${lib.concatStringsSep ", " shape.placementContractFields}).
        '';
      }
      {
        assertion = builtins.elem scope placementScopes;
        message = ''
          d2b.artifacts."${id}".catalog.instanceScope must be one of
          ${lib.concatStringsSep ", " placementScopes}.
        '';
      }
      {
        assertion = builtins.isList supported
          && supported != [ ]
          && builtins.all builtins.isString supported
          && lib.length (lib.unique supported) == lib.length supported
          && lib.sort lib.lessThan supported == supported
          && lib.all (target: builtins.elem target targetKinds) supported;
        message = ''
          d2b.artifacts."${id}".catalog.supportedTargetKinds must be a
          sorted, unique, non-empty subset of zone, host, and guest.
        '';
      }
      {
        assertion = builtins.isList capabilities
          && capabilities != [ ]
          && lib.length capabilities <= 3
          && builtins.all builtins.isAttrs capabilities
          && builtins.all builtins.isString capabilityTargets
          && lib.length (lib.unique capabilityTargets) == lib.length capabilityTargets
          && lib.sort lib.lessThan capabilityTargets == supported
          && lib.all capabilityValid capabilities;
        message = ''
          d2b.artifacts."${id}".catalog.targetCapabilities must provide one
          complete signed capability for every supported target kind.
        '';
      }
      {
        assertion = builtins.elem (catalog.placementAnchor or null) placementAnchors;
        message = ''
          d2b.artifacts."${id}".catalog.placementAnchor must be zone or execution-ref.
        '';
      }
      {
        assertion = scopeShape;
        message = ''
          d2b.artifacts."${id}".catalog signed placement scope is incompatible
          with its supported target kinds.
        '';
      }
    ])
    ++ (lib.optionals runtimePresent [
      {
        assertion = lib.all
          (field: builtins.hasAttr field catalog)
          shape.runtimeContractFields;
        message = ''
          d2b.artifacts."${id}".catalog must carry both signed shared runtime
          artifact digests (${lib.concatStringsSep ", " shape.runtimeContractFields}).
        '';
      }
      {
        assertion = validContractDigest (catalog.d2bdDigest or null)
          && validContractDigest (catalog.brokerDigest or null);
        message = ''
          d2b.artifacts."${id}".catalog.d2bdDigest and brokerDigest must be
          lowercase sha256 digests.
        '';
      }
    ]);

  maxOutputNameLength = 16;
  maxOutputNamesInMessage = 4;

  shortenOutputName = output:
    if builtins.stringLength output <= maxOutputNameLength
    then output
    else builtins.substring 0 (maxOutputNameLength - 3) output + "...";

  outputNamesSummary = outputs:
    let
      rendered = map (name: "\"${name}\"") (map shortenOutputName outputs);
      complete = lib.concatStringsSep ", " rendered;
      shown = lib.take maxOutputNamesInMessage (map shortenOutputName outputs);
      omitted = builtins.length outputs - builtins.length shown;
      abbreviated =
        lib.concatStringsSep ", " (map (name: "\"${name}\"") shown)
        + (if omitted > 0
          then ", ... (${toString omitted} more; ${toString (builtins.length outputs)} total)"
          else "");
    in
    if builtins.stringLength complete <= 96 then complete else abbreviated;

  providerOutputSelection = id:
    let
      artifact = artifacts.${id};
    in
    if artifact.type != "provider" then
      {
        assertion = true;
        message = "";
      }
    else
      let
        package = artifact.package;
        declaredOutputs = package.outputs or [ "out" ];
        shapeRecognised =
          builtins.isList declaredOutputs
          && declaredOutputs != [ ]
          && builtins.all builtins.isString declaredOutputs;
        outputSelectionRecognised =
          if !shapeRecognised then false
          else if builtins.length declaredOutputs == 1 then true
          else if (package.outputSpecified or false) == true then true
          else (package.outputName or null) != builtins.head declaredOutputs;
        outputSummary =
          if !shapeRecognised then ""
          else outputNamesSummary declaredOutputs;
      in
      {
        assertion = outputSelectionRecognised;
        message =
          if !shapeRecognised then
            "d2b.artifacts.\"${id}\".package: provider-artifact-output-shape-unknown: outputs must be a non-empty list of strings; supply a derivation or store path, not a hand-built attrset."
          else if outputSelectionRecognised then ""
          else
            "d2b.artifacts.\"${id}\".package: provider-artifact-output-ambiguous: declared outputs [ ${outputSummary} ] have no selection evidence; stdenv.mkDerivation: select any output (for example package = pkgs.<name>.out; sets outputSpecified). builtins.derivation: select a non-first output (outputName); its first output requires repackaging with stdenv.mkDerivation.";
      };

in
{
  options.d2b.artifacts = lib.mkOption {
    type = types.attrsOf artifactModule;
    default = { };
    description = ''
      Artifact declarations. Each entry names a derivation, its closed kind,
      and its catalog metadata. Provider ResourceSpecs select `provider`
      entries with `artifactId`; Guest system fields select `nixos-system`
      entries. There is no runtime discovery of any kind: an artifact that is
      not declared here does not exist.
    '';
    example = lib.literalExpression ''
      {
        provider-wayland = {
          package = inputs.wayland-provider.packages.''${system}.default;
          type = "provider";
        };
      }
    '';
  };

  options.d2b._providerCatalog = lib.mkOption {
    type = types.attrsOf types.anything;
    internal = true;
    visible = false;
    default = {
      inherit entries publicEntries providerCatalogEntries providerCatalogData
        providerCatalogJson providerCatalogPath providerIds
        fixedBootstrapProviderIds;
      json = catalogJson;
      ids = artifactIds;
      shape = shape;
    };
    description = "Internal compiled artifact catalog.";
  };

  config = {
    d2b._providerCatalog = {
      inherit entries publicEntries providerCatalogEntries providerCatalogData
        providerCatalogJson providerCatalogPath providerIds
        fixedBootstrapProviderIds;
      json = catalogJson;
      ids = artifactIds;
      shape = shape;
    };

    d2b._bundle.extraArtifacts.providerCatalog = {
      data = providerCatalogData;
      jsonText = providerCatalogJson;
      path = providerCatalogPath;
      installFileName = "provider-catalog.json";
      classification = "contractPrivateNonSecret";
      sensitivity = "nonSecret";
    };
  };

  config.assertions =
    # The identifier grammar.
    (map
      (id: {
        assertion = builtins.match artifactIdPattern id != null
          && builtins.stringLength id <= maxArtifactIdLength;
        message = ''
          d2b.artifacts."${id}": artifactId must match ${artifactIdPattern}
          and be at most ${toString maxArtifactIdLength} characters. It is a
          plain bounded ID, not a ResourceRef.
        '';
      })
      artifactIds)

    # Every frozen field present.
    ++ (map
      (id: {
        assertion = missingFields id == [ ];
        message = ''
          d2b.artifacts."${id}".catalog is missing required catalog
          field(s): ${lib.concatStringsSep ", " (missingFields id)}.
          The catalog entry shape is frozen by the Package catalog section of
          ADR-046-provider-model-and-packaging.
        '';
      })
      artifactIds)

    # No field outside the generated catalog or signed runtime contract sets.
    ++ (map
      (id: {
        assertion = unknownFields id == [ ];
        message = ''
          d2b.artifacts."${id}".catalog declares unknown catalog
          field(s): ${lib.concatStringsSep ", " (unknownFields id)}.
          The catalog entry shape is frozen; add a field to the generator, not
          to a consumer declaration.
        '';
      })
      artifactIds)

    # Exact digests, because selection compares them literally.
    ++ (map
      (id: {
        assertion = badDigests id == [ ];
        message = ''
          d2b.artifacts."${id}".catalog has malformed or absent
          digest(s): ${lib.concatStringsSep ", " (badDigests id)}.
          Each must be sha256:<64 lowercase hex>. Selection is by exact digest;
          there is no version-range solving and no latest.
        '';
      })
      artifactIds)

    # Provider packages must name one determinate output before any later
    # required-output validation can diagnose the artifact layout.
    ++ (map providerOutputSelection artifactIds)

    # Placement and shared-runtime fields are optional until a Provider
    # package publishes its signed manifest, but once any is present the
    # complete closed contract is validated.
    ++ (lib.concatMap signedContractAssertions artifactIds)
    ++ (lib.concatMap trustAssertions artifactIds)
    ++ providerMatrixAssertions;
}
