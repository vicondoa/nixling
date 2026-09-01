# The offline Provider package catalog: authoring, selection shape, and the
# eval-time rules that make selection exact.
#
# Covers the "Package catalog" section of
# ADR-046-provider-model-and-packaging: `d2b.artifacts.<id>` authoring, the
# compiled catalog's sort order, the frozen entry field set, the exact-digest
# requirement, and the private store path being absent from the public
# projection.
{ mkEval, lib, pkgs, flakeRoot, ... }:

let
  digestHelpers = import ../../../../nixos-modules/resources-bundle.nix { inherit lib; };
  providerCatalogModule =
    import ../../../../nixos-modules/provider-catalog.nix;
  shape = import ../../../../nixos-modules/generated/provider-catalog-shape.nix;
  # Nix-unit supplies a fixed catalog projection so bundle consumers never
  # demand artifact-catalog.nix's realised closure/JSON path.
  catalogFixtureArtifactRows = [
    {
      artifactId = "provider-catalog-eval";
      type = "provider";
      storePath = "/nix/store/d2b-provider-catalog-eval";
      packageDigest = "sha256:${builtins.hashString
        "sha256" "d2b:provider-catalog-eval:package"}";
      closureDigest = "sha256:${builtins.hashString
        "sha256" "d2b:provider-catalog-eval:closure"}";
      closureSize = 0;
    }
  ];
  catalogFixtureData = {
    schemaVersion = 3;
    entries = map
      (entry: {
        id = entry.artifactId;
        inherit (entry) type storePath packageDigest;
        closureMetadata = {
          executableDigest = null;
          manifestDigest = null;
          componentDigest = null;
          descriptorDigest = null;
          configDigest = null;
          systems = [ ];
          platform = null;
        };
      })
      catalogFixtureArtifactRows;
  };
  catalogFixturePreimageJson = builtins.toJSON catalogFixtureData;
  catalogFixtureDigest = "sha256:${digestHelpers.framedDigest
    "d2b:v3:artifact-catalog"
    catalogFixturePreimageJson}";
  catalogFixtureDocument = catalogFixtureData // {
    catalogDigest = catalogFixtureDigest;
  };
  catalogFixtureJson = builtins.toJSON catalogFixtureDocument;
  catalogFixturePath = pkgs.writeText
    "d2b-artifact-catalog-eval-fixture.json"
    "${catalogFixtureJson}\n";
  catalogFixtureProjection = {
    ids = map (entry: entry.artifactId) catalogFixtureArtifactRows;
    artifactRows = catalogFixtureArtifactRows;
    preimage = catalogFixtureData;
    preimageJson = catalogFixturePreimageJson;
    catalogDigest = catalogFixtureDigest;
    catalogData = catalogFixtureDocument;
    catalogJson = catalogFixtureJson;
    path = catalogFixturePath;
    publicEntries = map
      (entry: builtins.removeAttrs entry [ "storePath" ])
      catalogFixtureArtifactRows;
  };
  catalogFixtureArtifact = {
    data = catalogFixtureData;
    jsonText = catalogFixtureJson;
    path = catalogFixturePath;
    installFileName = "artifact-catalog.json";
    classification = "contractPrivateNonSecret";
    sensitivity = "nonSecret";
  };
  catalogOverride = { lib, ... }: {
    d2b._nixUnitCatalogFixture = lib.mkForce false;
    d2b._artifactCatalogV3 = lib.mkForce catalogFixtureProjection;
    d2b._bundle.extraArtifacts.artifactCatalog =
      lib.mkOverride 0 catalogFixtureArtifact;
  };
  mkEvalCatalog = modules:
    lib.evalModules {
      modules = [
        providerCatalogModule
        {
          options.assertions = lib.mkOption {
            type = lib.types.listOf lib.types.anything;
            default = [ ];
          };
          options.d2b._bundle.extraArtifacts.providerCatalog =
            lib.mkOption {
              type = lib.types.anything;
              default = { };
            };
        }
      ] ++ modules;
      specialArgs = { inherit pkgs; };
    };
  mkEvalProvider = modules: mkEval (modules ++ [ catalogOverride ]);

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

  # A conformant catalog entry: every frozen field, every digest exact.
  entryFor = name:
    let
      digest = field:
        "sha256:" + builtins.hashString "sha256" "${name}/${field}";
      digestFields = lib.listToAttrs
        (map (field: lib.nameValuePair field (digest field)) shape.digestFields);
      plainFields = lib.listToAttrs
        (map (field: lib.nameValuePair field "${name}/${field}")
          (lib.filter (field: !(lib.elem field shape.digestFields)) shape.fields));
    in
    digestFields // plainFields // {
      publisher = "d2b-official";
      signature = {
        signatureId = "${name}-signature";
        publisherRoot = "d2b-official";
      };
      rootEpoch = 1;
      revocationStatus = "clear";
      denyStatus = "clear";
    };

  artifactFor = name: {
    package = pkgs.writeText "artifact-${name}" name;
    type = "provider";
    catalog = entryFor name;
  };

  artifactForPackage = name: package:
    (artifactFor name) // { inherit package; };

  signedPlacementContract = name: {
    instanceScope = "per-resource-target";
    supportedTargetKinds = [ "guest" "host" ];
    targetCapabilities = [
      {
        artifactDigest = "sha256:${builtins.hashString "sha256" "${name}/guest"}";
        requiredEffectClasses = [ "process" ];
        targetKind = "guest";
      }
      {
        artifactDigest = "sha256:${builtins.hashString "sha256" "${name}/host"}";
        requiredEffectClasses = [ "process" ];
        targetKind = "host";
      }
    ];
    placementAnchor = "execution-ref";
    d2bdDigest = "sha256:${builtins.hashString "sha256" "${name}/d2bd"}";
    brokerDigest = "sha256:${builtins.hashString "sha256" "${name}/broker"}";
  };

  rawMultiOutput = builtins.derivation {
    name = "provider-catalog-raw-multi-output";
    system = pkgs.system;
    builder = "${pkgs.bash}/bin/bash";
    args = [ "-c" "mkdir -p $out $lib" ];
    outputs = [ "out" "lib" ];
  };

  storePathPackage = "${pkgs.writeText "provider-catalog-store-path" "store-path"}";

  # Declared deliberately out of alphabetical order: the compiled catalog must
  # sort by artifactId rather than preserve the authoring order.
  authored = {
    d2b.artifacts = {
      provider-wayland = artifactFor "provider-wayland";
      provider-audio = artifactFor "provider-audio";
      provider-storage = artifactFor "provider-storage";
    };
  };

  cfg = (mkEvalCatalog [ authored ]).config;
  mixedCatalogCfg = (mkEvalCatalog [{
    d2b.artifacts = {
      provider = artifactFor "provider";
      system = {
        package = pkgs.writeText "provider-catalog-system" "system";
        type = "nixos-system";
        catalog = null;
      };
    };
  }]).config;
  catalog = cfg.d2b._providerCatalog;
  signedCfg = (mkEvalCatalog [{
    d2b.artifacts.provider-signed = {
      package = pkgs.writeText "provider-signed" "provider-signed";
      type = "provider";
      catalog = (entryFor "provider-signed") // signedPlacementContract "provider-signed";
    };
  }]).config;
  signedEntry = lib.head signedCfg.d2b._providerCatalog.publicEntries;
  nullCatalogCfg = (mkEvalCatalog [{
    d2b.artifacts.system = {
      package = pkgs.writeText "provider-catalog-null" "system";
      type = "nixos-system";
      catalog = null;
    };
  }]).config;
  signedFailure = artifacts:
    let evaluated = (mkEvalCatalog [{
      d2b.artifacts = artifacts;
    }]).config;
    in lib.head (lib.filter (assertion: !assertion.assertion) evaluated.assertions);
  trustFailure = catalog:
    let
      evaluated = (mkEvalCatalog [{
        d2b.artifacts.trust-test = {
          package = pkgs.writeText "provider-trust-test" "provider-trust-test";
          type = "provider";
          inherit catalog;
        };
      }]).config;
      failures = lib.filter (assertion: !assertion.assertion)
        evaluated.assertions;
    in (lib.head failures).message;

  # The same three artifacts, authored in a different order and built from a
  # reversed list rather than a literal attribute set. The compiled catalog
  # must be identical, because sort order is a function of the identifiers.
  reAuthored = {
    d2b.artifacts = lib.listToAttrs
      (map (name: lib.nameValuePair name (artifactFor name))
        [ "provider-storage" "provider-wayland" "provider-audio" ]);
  };
  cfgReAuthored = (mkEvalCatalog [ reAuthored ]).config;

  evalArtifacts = artifacts:
    (mkEvalCatalog [ ({ ... }: { d2b.artifacts = artifacts; }) ]).config
      .d2b._providerCatalog.ids;

  # Force the assertion list of a configuration that must fail eval.
  failing = artifacts:
    let
      evaluated = (mkEvalCatalog [
        ({ ... }: { d2b.artifacts = artifacts; })
      ]).config;
      broken = lib.filter (a: !a.assertion) evaluated.assertions;
    in
    if broken == [ ] then "no assertion fired" else (lib.head broken).message;

  zoneResourceFixture = { ... }: {
    d2b.artifacts = {
      credential-entra = artifactFor "credential-entra";
      display-wayland = artifactFor "display-wayland";
    };
    d2b.zones.local-root.resources = {
      alice.type = "User";
      credential-entra = {
        type = "Provider";
        spec = {
          artifactId = "credential-entra";
          config = {
            credentialDomains = [ "user" ];
            supportedOperations = [ "acquire-token" "refresh-token" ];
          };
        };
      };
      display-wayland = {
        type = "Provider";
        spec = {
          artifactId = "display-wayland";
          config = { };
        };
      };
      work-access = {
        type = "Credential";
        metadata.labels.team = "platform";
        spec = {
          providerRef = "Provider/credential-entra";
          scope = {
            domainFilter = "user";
            userRef = "User/alice";
          };
          audience = "azure-resource-manager";
          consumerRef = "Provider/display-wayland";
          allowedOperations = [ "refresh-token" "acquire-token" ];
          rotation = {
            policy = "proactive";
            proactiveWindowMs = 300000;
            maxLeaseLifetimeMs = 3600000;
          };
        };
      };
    };
  };

  zoneCfg = (mkEvalProvider [ base zoneResourceFixture ]).config;
  zoneBundle = zoneCfg.d2b._bundle.zoneResourceBundles.local-root.data;
  catalogFixtureWasSelected =
    let
      projection = zoneCfg.d2b._artifactCatalogV3;
      artifact = zoneCfg.d2b._bundle.extraArtifacts.artifactCatalog;
      projectionPath =
        builtins.unsafeDiscardStringContext (toString projection.path);
      fixturePath =
        builtins.unsafeDiscardStringContext (toString catalogFixturePath);
      artifactPath =
        builtins.unsafeDiscardStringContext (toString artifact.path);
    in
    projection.catalogDigest == catalogFixtureDigest
    && projectionPath == fixturePath
    && artifact.data == catalogFixtureData
    && artifact.jsonText == catalogFixtureJson
    && artifactPath == fixturePath;
  providerCaseSource =
    builtins.readFile (flakeRoot + "/tests/unit/nix/cases/provider-catalog.nix");
  artifactCatalogSource =
    builtins.readFile (flakeRoot + "/nixos-modules/artifact-catalog.nix");
  caseAvoidsCatalogPathRead =
    !(lib.hasInfix ("builtins.readFile " + "catalogPath") providerCaseSource);
  digestRendererSource =
    builtins.readFile (flakeRoot + "/nixos-modules/zone-resources-json.nix");

  zoneFailureMessages = module:
    map (assertion: assertion.message)
      (lib.filter (assertion: !assertion.assertion)
        (mkEvalProvider [ base zoneResourceFixture module ]).config.assertions);

  mkNarrowZoneEval = modules:
    lib.evalModules {
      modules = [
        ../../../../nixos-modules/options-zones.nix
        ../../../../nixos-modules/options-resources.nix
        {
          options.assertions = lib.mkOption {
            type = lib.types.listOf lib.types.anything;
            default = [ ];
          };
          options.d2b.site.stateDir = lib.mkOption {
            type = lib.types.str;
            default = "/var/lib/d2b";
          };
          options.d2b.artifacts = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = { };
          };
          options.d2b.providerCatalog = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = { };
          };
        }
      ] ++ modules;
    };
  zoneValidationMessages = module:
    map (assertion: assertion.message)
      (lib.filter (assertion: !assertion.assertion)
        (mkNarrowZoneEval [ zoneResourceFixture module ]).config.assertions);
  zoneRejects = needle: module:
    lib.any (message: lib.hasInfix needle message)
      (zoneValidationMessages module);

  secretShapedCredential = { ... }: {
    d2b.zones.local-root.resources.work-access.spec.audience =
      "-----BEGIN PRIVATE KEY-----";
  };

  duplicateBindingModule = { ... }: {
    d2b.zones.local-root.resources.work-access-copy = {
      type = "Credential";
      spec = {
        providerRef = "Provider/credential-entra";
        scope = {
          domainFilter = "user";
          userRef = "User/alice";
        };
        audience = "azure-resource-manager";
        consumerRef = "Provider/display-wayland";
        allowedOperations = [ "acquire-token" ];
        rotation = {
          policy = "proactive";
          proactiveWindowMs = 300000;
          maxLeaseLifetimeMs = 3600000;
        };
      };
    };
  };

  projectionFixture = { ... }: {
    d2b.artifacts = {
      credential-entra = artifactFor "credential-entra";
      display-wayland = artifactFor "display-wayland";
      runtime-cloud-hypervisor = artifactFor "runtime-cloud-hypervisor";
      system-core = artifactFor "system-core";
      system-systemd = artifactFor "system-systemd";
      d2b-provider-device-tpm = artifactFor "d2b-provider-device-tpm";
    };
    d2b.zones.local-root.resources = {
      alice = {
        type = "User";
        spec = { };
      };
      "credential-entra" = {
        type = "Provider";
        spec = {
          artifactId = "credential-entra";
          config = {
            credentialDomains = [ "system" ];
            supportedOperations = [
              "acquire-token"
              "refresh-token"
              "inspect-metadata"
            ];
          };
        };
      };
      display-wayland = {
        type = "Provider";
        spec = {
          artifactId = "display-wayland";
          config = { };
        };
      };
      runtime-cloud-hypervisor = {
        type = "Provider";
        spec = {
          artifactId = "runtime-cloud-hypervisor";
          config = { };
        };
      };
      system-core = {
        type = "Provider";
        spec = {
          artifactId = "system-core";
          config = { };
        };
      };
      system-systemd = {
        type = "Provider";
        spec = {
          artifactId = "system-systemd";
          config = { };
        };
      };
      device-tpm = {
        type = "Provider";
        spec = {
          artifactId = "d2b-provider-device-tpm";
          config = { };
        };
      };
      host-system = {
        type = "Host";
        spec = {
          providerRef = "Provider/system-core";
          defaultDomain = "system";
          allowedDomains = [ "system" ];
        };
      };
      host-user = {
        type = "Host";
        spec = {
          providerRef = "Provider/system-core";
          defaultDomain = "user";
          allowedDomains = [ "user" ];
          defaultUserRef = "User/alice";
          isolationPosture = "none";
        };
      };
      identity = {
        type = "Guest";
        spec = {
          providerRef = "Provider/runtime-cloud-hypervisor";
          defaultDomain = "system";
          allowedDomains = [ "system" ];
        };
      };
      "vm-tpm" = {
        type = "Device";
        spec = {
          providerRef = "Provider/device-tpm";
          deviceClass = "emulated";
          arbitration = "exclusive";
          maxConcurrentClaims = 1;
          inventory.selector = { };
        };
      };
      "entra-login" = {
        type = "Process";
        metadata = {
          ownerRef = "Provider/credential-entra";
          annotations = {
            "d2b.org/launcher-label" = "Identity";
            "d2b.org/launcher-icon" = "applications-system";
          };
        };
        spec = {
          providerRef = "Provider/system-systemd";
          executionRef = "Guest/identity";
          domain = "system";
          processClass = "service";
          template = "entra-login-token";
          credentialRefs = [ ];
        };
      };
      "entra-login-endpoint" = {
        type = "Endpoint";
        spec = {
          providerRef = "Provider/credential-entra";
          producerRef = "Process/entra-login";
          endpointClass = "service";
          transport = "unix";
          purpose = "credential-entra.d2bus.org/entra-login-token";
          serviceFingerprint = "credential-entra.d2bus.org/EntrablauLoginTokenService/v1";
          locality = "guest-local";
          visibility = "provider";
          attachmentPolicy = {
            supported = false;
            maxAttachments = 0;
          };
          consumerPolicy = {
            allowedSubjects = [
              "Provider/credential-entra"
              "Provider/runtime-cloud-hypervisor"
            ];
            allowedProviderComponents = [ ];
            allowedOperations = [ "resolve" ];
          };
          lifecyclePolicy = "recycle-with-producer";
        };
      };
      "work-entra" = {
        type = "Credential";
        spec = {
          providerRef = "Provider/credential-entra";
          identityGuestRef = "Guest/identity";
          loginEndpointRef = "Endpoint/entra-login-endpoint";
          scope = {
            executionRef = "Guest/identity";
            domainFilter = "system";
          };
          audience = "azure-resource-manager";
          consumerRef = "Provider/runtime-cloud-hypervisor";
          allowedOperations = [ "acquire-token" "inspect-metadata" ];
          rotation = {
            policy = "on-demand";
            maxLeaseLifetimeMs = 0;
          };
        };
      };
      "host-user-process" = {
        type = "Process";
        metadata.annotations."d2b.org/launcher-label" = "Local tools";
        spec = {
          providerRef = "Provider/system-systemd";
          executionRef = "Host/host-user";
          domain = "user";
          userRef = "User/alice";
          processClass = "service";
          template = "shell-terminal";
          credentialRefs = [ "Credential/work-entra" ];
        };
      };
    };
  };

  projectionCfg = (mkEvalProvider [ base projectionFixture ]).config;
  projectionBundle = projectionCfg.d2b._bundle.zoneResourceBundles.local-root.data;
  projectionResource = type: name:
    lib.findFirst
      (resource:
        resource.type == type && resource.metadata.name == name)
      null
      projectionBundle.resources;

  projectionFailureMessages = module:
    map (assertion: assertion.message)
      (lib.filter (assertion: !assertion.assertion)
        (mkEvalProvider [ base projectionFixture module ]).config.assertions);

  projectionRejects = needle: module:
    lib.any (message: lib.hasInfix needle message)
      (projectionFailureMessages module);
in
{
  # An empty catalog is the default: no artifact exists unless it is authored.
  # This is the "no PATH scan, no directory discovery" rule stated as a value.
  "provider-catalog/empty-by-default" = {
    expr = (mkEvalCatalog [ ]).config.d2b._providerCatalog.ids;
    expected = [ ];
  };

  # The catalog is sorted by artifactId, not by authoring order.
  "provider-catalog/sorted-by-artifact-id" = {
    expr = catalog.ids;
    expected = [ "provider-audio" "provider-storage" "provider-wayland" ];
  };

  # Authoring order does not reach the output.
  "provider-catalog/order-independent" = {
    expr = cfgReAuthored.d2b._providerCatalog.json == catalog.json;
    expected = true;
  };

  # The public projection carries the id, the type, and the frozen entry, and
  # never the private store path.
  "provider-catalog/public-entry-shape" = {
    expr = lib.sort (a: b: a < b)
      (lib.attrNames (lib.head catalog.publicEntries));
    expected = [ "entry" "id" "type" ];
  };

  "provider-catalog/public-projection-has-no-store-path" = {
    expr = lib.any (e: e ? storePath) catalog.publicEntries;
    expected = false;
  };

  # The private catalog may retain a store path for activation.
  "provider-catalog/private-entry-retains-store-path" = {
    expr = lib.all (e: e ? storePath) catalog.entries;
    expected = true;
  };

  # The entry field set is exactly the frozen one.
  "provider-catalog/entry-fields-are-the-frozen-set" = {
    expr = lib.sort (a: b: a < b)
      (lib.attrNames (lib.head catalog.publicEntries).entry);
    expected = lib.sort (a: b: a < b) (shape.fields ++ shape.trustFields);
  };

  "provider-catalog/signed-placement-and-runtime-contract-is-retained" = {
    expr = {
      placement = {
        scope = signedEntry.entry.instanceScope;
        targets = signedEntry.entry.supportedTargetKinds;
        anchor = signedEntry.entry.placementAnchor;
        capabilities = signedEntry.entry.targetCapabilities;
      };
      runtime = {
        d2bd = signedEntry.entry.d2bdDigest;
        broker = signedEntry.entry.brokerDigest;
      };
    };
    expected = {
      placement = {
        scope = "per-resource-target";
        targets = [ "guest" "host" ];
        anchor = "execution-ref";
        capabilities = (signedPlacementContract "provider-signed").targetCapabilities;
      };
      runtime = {
        d2bd = (signedPlacementContract "provider-signed").d2bdDigest;
        broker = (signedPlacementContract "provider-signed").brokerDigest;
      };
    };
  };

  "provider-catalog/signed-placement-contract-fails-closed-on-target-drift" = {
    expr =
      let
        broken = signedPlacementContract "broken" // {
          supportedTargetKinds = [ "guest" "host" ];
          targetCapabilities = [
            {
              artifactDigest = "sha256:${builtins.hashString "sha256" "broken/guest"}";
              requiredEffectClasses = [ "process" ];
              targetKind = "guest";
            }
          ];
        };

        failure = signedFailure {
          broken = {
            package = pkgs.writeText "provider-broken" "provider-broken";
            type = "provider";
            catalog = (entryFor "broken") // broken;
          };
        };
      in lib.hasInfix "targetCapabilities" failure.message;
    expected = true;
  };

  "provider-catalog/null-catalog-has-no-signed-contract" = {
    expr = builtins.deepSeq nullCatalogCfg.assertions
      (lib.all (assertion: assertion.assertion) nullCatalogCfg.assertions);
    expected = true;
  };

  # The excluded mechanisms travel with the catalog, so a consumer reading it
  # sees the absences named rather than inferring them.
  "provider-catalog/excluded-mechanisms-recorded" = {
    expr = shape.excludedMechanisms;
    expected = [
      "directory-discovery"
      "latest"
      "path-scan"
      "runtime-download"
      "runtime-marketplace"
      "version-range-solving"
    ];
  };

  "provider-catalog/closed-27-row-matrix" = {
    expr = {
      rowCount = builtins.length shape.providerMatrix;
      idCount = builtins.length shape.providerIds;
      idsMatchRows =
        shape.providerIds == map (row: row.provider) shape.providerMatrix;
      rowsUnique =
        builtins.length (lib.unique shape.providerIds)
        == builtins.length shape.providerIds;
      bootstrapIds = shape.fixedBootstrapProviderIds;
      bootstrapRows = map (row: row.provider)
        (lib.filter (row: row.bootstrap) shape.providerMatrix);
      layout = shape.artifactLayout;
    };
    expected = {
      rowCount = 27;
      idCount = 27;
      idsMatchRows = true;
      rowsUnique = true;
      bootstrapIds = [ "system-core" "system-minijail" ];
      bootstrapRows = [ "system-core" "system-minijail" ];
      layout = {
        executableDirectory = "bin";
        metadataDirectory = "share/d2b/provider";
        multiBinary = true;
        requiredFiles = [
          "share/d2b/provider/provider-manifest.json"
          "share/d2b/provider/provider-manifest.json.sig"
          "share/d2b/provider/config-schema.json"
        ];
        noBinaryBootstrapProvider = "system-core";
        fixedBootstrapProviders = [ "system-core" "system-minijail" ];
      };
    };
  };

  "provider-catalog/provider-only-projection-excludes-system-artifacts" = {
    expr = {
      artifactIds = map (entry: entry.id)
        mixedCatalogCfg.d2b._providerCatalog.providerCatalogEntries;
      publicCatalogIds = map (entry: entry.artifactId)
        mixedCatalogCfg.d2b._providerCatalog.providerCatalogData.entries;
    };
    expected = {
      artifactIds = [ "provider" ];
      publicCatalogIds = [ "provider" ];
    };
  };

  "provider-catalog/trust-epoch-alias-mismatch-fails-closed" = {
    expr =
      let
        message = trustFailure
          ((entryFor "trust-epoch") // {
            trustEpoch = 2;
            rootEpoch = 1;
          });
      in lib.hasInfix "trust epoch" message;
    expected = true;
  };

  "provider-catalog/revocation-ref-shape-fails-closed" = {
    expr =
      let
        message = trustFailure
          ((entryFor "revocation-ref") // { revocationRef = 7; });
      in lib.hasInfix "revocationRef" message;
    expected = true;
  };

  "provider-catalog/deny-status-fails-closed" = {
    expr =
      let
        message = trustFailure
          ((entryFor "deny-status") // { denyStatus = "denied"; });
      in lib.hasInfix "deny status must be clear" message;
    expected = true;
  };

  "provider-catalog/publisher-root-mismatch-fails-closed" = {
    expr =
      let
        message = trustFailure
          ((entryFor "publisher-root") // {
            signature.publisherRoot = "different-root";
          });
      in lib.hasInfix "publisher root must match publisher" message;
    expected = true;
  };

  "provider-catalog/signature-id-alias-mismatch-fails-closed" = {
    expr =
      let
        message = trustFailure
          ((entryFor "signature-id") // {
            signatureId = "different-signature";
          });
      in lib.hasInfix "signature ID aliases disagree" message;
    expected = true;
  };

  # A missing frozen field is rejected, and the message names it.
  "provider-catalog/missing-field-rejected" = {
    expr =
      let
        message = failing {
          incomplete = {
            package = pkgs.writeText "artifact-incomplete" "incomplete";
            catalog = removeAttrs (entryFor "incomplete") [ "supportContact" ];
          };
        };
      in
      lib.hasInfix "supportContact" message;
    expected = true;
  };

  # A field outside the frozen set is rejected.
  "provider-catalog/unknown-field-rejected" = {
    expr =
      let
        message = failing {
          extra = {
            package = pkgs.writeText "artifact-extra" "extra";
            catalog = (entryFor "extra") // { downloadUrl = "https://example.invalid"; };
          };
        };
      in
      lib.hasInfix "downloadUrl" message;
    expected = true;
  };

  # A digest that is not an exact sha256 is rejected. This is the rule that
  # forecloses version-range solving: there is nothing to solve over.
  "provider-catalog/inexact-digest-rejected" = {
    expr =
      let
        message = failing {
          loose = {
            package = pkgs.writeText "artifact-loose" "loose";
            catalog = (entryFor "loose") // { packageDigest = "latest"; };
          };
        };
      in
      lib.hasInfix "packageDigest" message;
    expected = true;
  };

  # `artifactId` is a plain bounded ID, so a ResourceRef-shaped identifier is
  # rejected rather than quietly accepted as one.
  "provider-catalog/resource-ref-shaped-id-rejected" = {
    expr =
      let
        message = failing {
          "Provider/wayland" = {
            package = pkgs.writeText "artifact-ref" "ref";
            catalog = entryFor "ref";
          };
        };
      in
      lib.hasInfix "plain bounded ID" message;
    expected = true;
  };

  # A single authored artifact still compiles, so the sort is not an artefact
  # of having several.
  "provider-catalog/single-artifact" = {
    expr = evalArtifacts { solo = artifactFor "solo"; };
    expected = [ "solo" ];
  };

  "nix-eval-provider-output-ambiguous" = {
    expr =
      let
        wholeMessage = failing {
          provider-openssl = artifactForPackage "provider-openssl" pkgs.openssl;
        };
        rawFirstMessage = failing {
          raw-first = artifactForPackage "raw-first" rawMultiOutput.out;
        };
        selected = evalArtifacts {
          selected-out = artifactForPackage "selected-out" pkgs.openssl.out;
          selected-dev = artifactForPackage "selected-dev" pkgs.openssl.dev;
          raw-lib = artifactForPackage "raw-lib" rawMultiOutput.lib;
        };
      in {
        wholeRejected =
          lib.hasInfix "provider-artifact-output-ambiguous" wholeMessage
          && lib.hasInfix "provider-openssl" wholeMessage
          && lib.hasInfix "\"bin\"" wholeMessage
          && lib.hasInfix "\"debug\"" wholeMessage
          && lib.hasInfix "outputSpecified" wholeMessage
          && lib.hasInfix "builtins.derivation" wholeMessage
          && lib.hasInfix "stdenv.mkDerivation" wholeMessage
          && builtins.stringLength wholeMessage <= 512;
        selectedOutputsAccepted =
          selected == [ "raw-lib" "selected-dev" "selected-out" ];
        rawFirstRejected =
          lib.hasInfix "provider-artifact-output-ambiguous" rawFirstMessage
          && lib.hasInfix "raw-first" rawFirstMessage
          && lib.hasInfix "\"out\"" rawFirstMessage
          && lib.hasInfix "\"lib\"" rawFirstMessage
          && builtins.stringLength rawFirstMessage <= 512;
      };
    expected = {
      wholeRejected = true;
      selectedOutputsAccepted = true;
      rawFirstRejected = true;
    };
  };

  "nix-eval-provider-output-shape-accepted" = {
    expr = evalArtifacts {
      store-path = artifactForPackage "store-path" storePathPackage;
    };
    expected = [ "store-path" ];
  };

  "nix-eval-provider-output-shape-unknown" = {
    expr =
      let
        message = failing {
          malformed = artifactForPackage "malformed"
            (rawMultiOutput // { outputs = "not-a-list"; });
        };
      in
      lib.hasInfix "provider-artifact-output-shape-unknown" message
      && lib.hasInfix "malformed" message
      && lib.hasInfix "non-empty list of strings" message
      && lib.hasInfix "hand-built attrset" message
      && builtins.stringLength message <= 512;
    expected = true;
  };

  "provider-catalog/zone-resource-bundle-credential-envelope-and-digest" = {
    expr = {
      catalogFixtureSelected = catalogFixtureWasSelected;
      noCatalogPathRead = caseAvoidsCatalogPathRead;
      envelope = lib.head zoneBundle.resources;
      order = map (resource: resource.type) zoneBundle.resources;
      evalBundleFields = lib.attrNames zoneBundle;
      evalCatalogFields = lib.attrNames
        zoneCfg.d2b._bundle.extraArtifacts.artifactCatalog.data;
      pathsAreBuildBacked =
        zoneCfg.d2b._bundle.zoneResourceBundles.local-root.path != null
        && zoneCfg.d2b._bundle.extraArtifacts.artifactCatalog.path != null;
      digestContract = {
        noRawNulSeparator = !(lib.hasInfix "printf '%s\\000' \"$domain\""
          digestRendererSource);
        framedObject = lib.hasInfix "\"framing\": \"d2b-digest/v1\""
          digestRendererSource;
        canonicalJson = lib.hasInfix "sort_keys=True" digestRendererSource;
        resourceBundleDomain = lib.hasInfix
          "domain_digest 'd2b:v3:resource-bundle'" digestRendererSource;
        resourceBundleGolden = lib.hasInfix
          "854fc6c314b185ac9f842231e368fc75650729f669e15d0f1e60141ea334cb5e"
          digestRendererSource;
        artifactCatalogDomain = lib.hasInfix
          "domain_digest 'd2b:v3:artifact-catalog'" digestRendererSource;
        artifactCatalogGolden = lib.hasInfix
          "2fa7348cd18ac4f54d28aeb87ef0be5da1fd772c3d173d830ef25e67b7adc63e"
          digestRendererSource;
        productionCatalogReadsPath = lib.hasInfix
          ("builtins.readFile " + "catalogPath")
          artifactCatalogSource;
      };
      role = zoneCfg.d2b._resourceCompiler.zones.local-root.role;
      retention = zoneCfg.d2b._resourceCompiler.zones.local-root.retainedGenerations;
    };
    expected = {
      catalogFixtureSelected = true;
      noCatalogPathRead = true;
      envelope = {
        apiVersion = "resources.d2bus.org/v3";
        type = "Credential";
        metadata = {
          name = "work-access";
          zone = "local-root";
          labels.team = "platform";
        };
        spec = {
          providerRef = "Provider/credential-entra";
          scope = {
            domainFilter = "user";
            userRef = "User/alice";
          };
          audience = "azure-resource-manager";
          consumerRef = "Provider/display-wayland";
          allowedOperations = [ "refresh-token" "acquire-token" ];
          rotation = {
            policy = "proactive";
            proactiveWindowMs = 300000;
            maxLeaseLifetimeMs = 3600000;
          };
        };
      };

      order = [ "Credential" "Provider" "Provider" "User" ];
      evalBundleFields = [
        "artifactCatalogDigest"
        "bundleVersion"
        "contentHash"
        "generatedAt"
        "providerSchemaDigests"
        "resources"
        "schemaVersion"
        "zone"
      ];
      evalCatalogFields = [ "entries" "schemaVersion" ];
      pathsAreBuildBacked = true;
      digestContract = {
        noRawNulSeparator = true;
        framedObject = true;
        canonicalJson = true;
        resourceBundleDomain = true;
        resourceBundleGolden = true;
        artifactCatalogDomain = true;
        artifactCatalogGolden = true;
        productionCatalogReadsPath = true;
      };
      role = {
        type = "Role";
        metadata = {
          name = "activation-nixos";
          zone = "local-root";
        };
        spec.rules = [
          {
            resourceTypes = [ "Credential" ];
            verbs = [ "create" "update-spec" "delete" ];
            subresources = [ ];
            resourceNames = [ ];
            zones = [ "local-root" ];
            executionRefs = [ ];
            sessionVerbs = [ ];
          }
          {
            resourceTypes = [ "Credential" ];
            verbs = [ "admin-credential" ];
            subresources = [ "create" "update-spec" "delete" ];
            resourceNames = [ ];
            zones = [ "local-root" ];
            executionRefs = [ ];
            sessionVerbs = [ ];
          }
        ];
      };
      retention = 3;
    };
  };

  "provider-catalog/zone-resource-owner-ref-is-optional-but-validated" = {
    expr = {
      resourceWithoutOwnerRef = lib.any
        (resource:
          resource.type == "Provider"
          && !(resource.metadata ? ownerRef))
        zoneBundle.resources;
      invalidOwnerRef = zoneRejects
        "metadata.ownerRef must resolve in Zone local-root"
        ({ ... }: {
          d2b.zones.local-root.resources.display-wayland.metadata.ownerRef =
            "User/missing";
        });
    };
    expected = {
      resourceWithoutOwnerRef = true;
      invalidOwnerRef = true;
    };
  };

  "provider-catalog/framed-digest-separates-domain-and-payload-boundaries" = {
    expr = {
      preimagesDiffer =
        digestHelpers.framedDigestPreimage "ab" "c"
        != digestHelpers.framedDigestPreimage "a" "bc";
      digestsDiffer =
        digestHelpers.framedDigest "ab" "c"
        != digestHelpers.framedDigest "a" "bc";
    };
    expected = {
      preimagesDiffer = true;
      digestsDiffer = true;
    };
  };

  "provider-catalog/zone-resource-credential-invalid-inputs-rejected" = {
    expr = {
      providerDomain = zoneRejects "not supported" {
        d2b.zones.local-root.resources.work-access.spec.scope.domainFilter = "system";
      };
      rotation = zoneRejects "less than half" {
        d2b.zones.local-root.resources.work-access.spec.rotation.proactiveWindowMs =
          1800000;
      };
      unresolved = zoneRejects "must resolve" {
        d2b.zones.local-root.resources.work-access.spec.consumerRef = "Provider/missing";
      };
      duplicate = zoneRejects "duplicate Credential binding" duplicateBindingModule;
      missingArtifact = zoneRejects "declared artifactId" {
        d2b.zones.local-root.resources.credential-entra.spec.artifactId = "missing";
      };
      credentialRef = zoneRejects "credential-value-must-be-ref" {
        d2b.zones.local-root.resources.credential-entra.spec.config.sealingCredentialRef =
          "raw-value";
      };
    };
    expected = {
      providerDomain = true;
      rotation = true;
      unresolved = true;
      duplicate = true;
      missingArtifact = true;
      credentialRef = true;
    };
  };

  "provider-catalog/zone-resource-credential-secret-shaped-rejected" = {
    # The converged Zone bundle compiler rejects secret-shaped values while
    # compiling its helper assertions. Keep that expected throw in the
    # harness's explicit error bucket rather than hiding it in a value case.
    expr = zoneFailureMessages secretShapedCredential;
    expectedError = { };
  };

  "provider-catalog/zone-resource-runtime-metadata-and-store-path-absent" = {
    expr = {
      resourceKeys = lib.attrNames (lib.head zoneBundle.resources);
      metadataKeys = lib.attrNames (lib.head zoneBundle.resources).metadata;
      hasStorePath = lib.hasInfix "/nix/store/" (builtins.toJSON zoneBundle);
      artifactEntryKeys = lib.attrNames
        (lib.head zoneCfg.d2b._bundle.extraArtifacts.artifactCatalog.data.entries);
    };
    expected = {
      resourceKeys = [ "apiVersion" "metadata" "spec" "type" ];
      metadataKeys = [ "labels" "name" "zone" ];
      hasStorePath = false;
      artifactEntryKeys = [ "closureMetadata" "id" "packageDigest" "storePath" "type" ];
    };
  };

  "provider-catalog/v3-launcher-annotations-and-credential-refs" = {
    expr =
      let
        launcher = projectionResource "Process" "entra-login";
        consumer = projectionResource "Process" "host-user-process";
        credential = projectionResource "Credential" "work-entra";
        endpoint = projectionResource "Endpoint" "entra-login-endpoint";
        encoded = builtins.toJSON projectionBundle;
      in {
        launcherAnnotations = launcher.metadata.annotations;
        consumerCredentialRefs = consumer.spec.credentialRefs;
        credentialRefs = {
          identityGuestRef = credential.spec.identityGuestRef;
          loginEndpointRef = credential.spec.loginEndpointRef;
          consumerRef = credential.spec.consumerRef;
        };
        endpointPolicy = {
          visibility = endpoint.spec.visibility;
          subjects = endpoint.spec.consumerPolicy.allowedSubjects;
          operations = endpoint.spec.consumerPolicy.allowedOperations;
        };
        noSecretPayload =
          !(lib.hasInfix "PRIVATE KEY" encoded)
          && !(lib.hasInfix "/nix/store/" encoded)
          && !(lib.hasInfix "\"argv\"" encoded);
      };
    expected = {
      launcherAnnotations = {
        "d2b.org/launcher-icon" = "applications-system";
        "d2b.org/launcher-label" = "Identity";
      };
      consumerCredentialRefs = [ "Credential/work-entra" ];
      credentialRefs = {
        identityGuestRef = "Guest/identity";
        loginEndpointRef = "Endpoint/entra-login-endpoint";
        consumerRef = "Provider/runtime-cloud-hypervisor";
      };
      endpointPolicy = {
        visibility = "provider";
        subjects = [ "Provider/credential-entra" "Provider/runtime-cloud-hypervisor" ];
        operations = [ "resolve" ];
      };
      noSecretPayload = true;
    };
  };

  "provider-catalog/v3-user-only-host-process-posture" = {
    expr =
      let
        host = projectionResource "Host" "host-user";
        process = projectionResource "Process" "host-user-process";
      in {
        hostPosture = host.spec.isolationPosture;
        hostDomains = host.spec.allowedDomains;
        processDomain = process.spec.domain;
        processTarget = process.spec.executionRef;
      };
    expected = {
      hostPosture = "none";
      hostDomains = [ "user" ];
      processDomain = "user";
      processTarget = "Host/host-user";
    };
  };

  "provider-catalog/v3-user-only-host-posture-is-not-optional" = {
    expr = {
      missingPosture = projectionRejects "isolationPosture=none is required" {
        d2b.zones.local-root.resources.host-user.spec.isolationPosture = lib.mkForce null;
      };
      systemProcess = projectionRejects "must be user for a no-isolation Host target" {
        d2b.zones.local-root.resources.bad-system-process = {
          type = "Process";
          spec = {
            providerRef = "Provider/system-systemd";
            executionRef = "Host/host-user";
            domain = "system";
            processClass = "service";
            template = "invalid-system-process";
            credentialRefs = [ ];
          };
        };
      };
      zoneVisibleLoginEndpoint = projectionRejects
        "provider-only resolve contract" {
          d2b.zones.local-root.resources.entra-login-endpoint.spec.visibility = "zone";
        };
    };
    expected = {
      missingPosture = true;
      systemProcess = true;
      zoneVisibleLoginEndpoint = true;
    };
  };

  "provider-catalog/v3-device-provider-install-is-explicit" = {
    expr =
      let
        provider = projectionResource "Provider" "device-tpm";
        device = projectionResource "Device" "vm-tpm";
      in {
        providerArtifact = provider.spec.artifactId;
        providerConfig = provider.spec.config;
        deviceProviderRef = device.spec.providerRef;
        deviceClass = device.spec.deviceClass;
        deviceInventorySelector = device.spec.inventory.selector;
        bundleHasProvider = provider != null;
      };
    expected = {
      providerArtifact = "d2b-provider-device-tpm";
      providerConfig = { };
      deviceProviderRef = "Provider/device-tpm";
      deviceClass = "emulated";
      deviceInventorySelector = null;
      bundleHasProvider = true;
    };
  };
}
