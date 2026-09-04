# Canonical monolithic per-Zone v3 resource bundle emitter.
#
# The bundle is immutable Nix output. Runtime generation ordinals,
# configuration ownership, and cleanup are assigned by the controller after
# this document has passed its integrity checks.
{ config, lib, pkgs, ... }:

let
  cfg = config.d2b;
  apiVersion = "resources.d2bus.org/v3";
  resourcesBundle = import ./resources-bundle.nix { inherit lib; };
  providerCatalogEntries = cfg._providerCatalog.entries or [ ];
  phase2 = cfg._resourceCompiler.phase2 or { };
  compilerPackage = phase2.compiler;
  schemaRoot = phase2.schemaRoot;
  strictSecrets = phase2.strictSecrets or true;
  emptyArtifactCatalogPreimageJson = builtins.toJSON {
    entries = [ ];
    schemaVersion = 3;
  };
  runtimeFields = [
    "uid"
    "generation"
    "revision"
    "status"
    "managedBy"
    "configurationGeneration"
    "timestamp"
    "createdAt"
    "updatedAt"
    "finalizers"
  ];
  executionDefaults = {
    providerRef = null;
    defaultDomain = "system";
    allowedDomains = [ "system" ];
    defaultUserRef = null;
    budget = {
      cpu = { request = null; limit = null; };
      memory = { request = null; limit = null; };
      pids = { limit = null; };
      fds = { limit = null; };
      ioWeight = null;
      networkEgressBps = null;
      threadLimit = null;
    };
    networkAttachments = [ ];
    deviceAttachments = [ ];
    volumeAttachmentDefaults = [ ];
  };
  helperAssertions = lib.flatten (lib.mapAttrsToList
    (zoneName: zone:
      let
        # Volume layout paths are anchored policy paths, not host paths. Their
        # dedicated compiler owns the Volume schema, so the generic bundle
        # secret/path lint must not reinterpret LayoutEntry.path.
        genericResources = lib.filterAttrs
          (_: resource: resource.type != "Volume")
          zone.resources;
        validation = resourcesBundle.validateBundle zoneName genericResources;
        # Keep ordinary validation failures visible as assertions, but never
        # downgrade secret-shaped material to a soft assertion.
        hasForbiddenMaterial = lib.any
          (resource:
            builtins.isAttrs resource
            && resourcesBundle.forbiddenRows (resource.spec or { }) != [ ])
          (lib.attrValues genericResources);
      in
      if hasForbiddenMaterial
      then (resourcesBundle.bundleForZone zoneName genericResources).assertions
      else validation.assertions)
    cfg.zones);
  catalogDigest =
    if cfg ? _artifactCatalogV3 && cfg._artifactCatalogV3 ? catalogDigest
    then cfg._artifactCatalogV3.catalogDigest
    else "sha256:${resourcesBundle.framedDigest
      "d2b:v3:artifact-catalog" emptyArtifactCatalogPreimageJson}";
  catalogPath =
    if cfg ? _artifactCatalogV3 && cfg._artifactCatalogV3 ? path
    then cfg._artifactCatalogV3.path
    else null;
  processResources = zoneName:
    let
      compiler = cfg._resourceCompiler or { };
      processes = compiler.processes or { };
      byZone = processes.byZone or { };
    in
    if builtins.hasAttr zoneName byZone
    then byZone.${zoneName}
    else { };

  # Keep this list explicit so every Provider projection has a visible bundle
  # owner and no consumer can register an implicit fallback.
  providerProjectionOwners = [
    "volume-local"
    "volume-virtiofs"
    "device-gpu"
    "device-usbip"
    "device-security-key"
    "device-tpm"
    "display-wayland"
    "audio-pipewire"
    "clipboard-wayland"
    "notification-desktop"
    "activation-nixos"
    "observability-otel"
    "shell-terminal"
    "runtime-qemu-media"
    "runtime-azure-container-apps"
    "runtime-azure-virtual-machine"
  ];

  providerProjectionKeys = {
    "volume-local" = "providerProjectionVolumeLocal";
    "volume-virtiofs" = "providerProjectionVolumeVirtiofs";
    "device-gpu" = "providerProjectionDeviceGpu";
    "device-usbip" = "providerProjectionDeviceUsbip";
    "device-security-key" = "providerProjectionDeviceSecurityKey";
    "device-tpm" = "providerProjectionDeviceTpm";
    "display-wayland" = "providerProjectionDisplayWayland";
    "audio-pipewire" = "providerProjectionAudioPipewire";
    "clipboard-wayland" = "providerProjectionClipboardWayland";
    "notification-desktop" = "providerProjectionNotificationDesktop";
    "activation-nixos" = "providerProjectionActivationNixos";
    "observability-otel" = "providerProjectionObservabilityOtel";
    "shell-terminal" = "providerProjectionShellTerminal";
    "runtime-qemu-media" = "providerProjectionRuntimeQemuMedia";
    "runtime-azure-container-apps" = "providerProjectionRuntimeAzureContainerApps";
    "runtime-azure-virtual-machine" = "providerProjectionRuntimeAzureVirtualMachine";
  };

  providerProjection = owner:
    let
      table = cfg._resourceCompiler or { };
      key = builtins.getAttr owner providerProjectionKeys;
    in if builtins.hasAttr key table
    then builtins.getAttr key table
    else { };

  providerResources = zoneName:
    lib.foldl'
      (result: owner:
        let projection = providerProjection owner;
        in if (projection.enabled or false)
          then result
            // ((projection.resourcesByZone or { }).${zoneName} or { })
          else result)
      { }
      providerProjectionOwners;

  providerGuestPatches = zoneName: resourceName:
    lib.foldl'
      (result: owner:
        let projection = providerProjection owner;
        in if (projection.enabled or false)
          then lib.recursiveUpdate result
            (((projection.guestPatchesByZone or { }).${zoneName}
              or { }).${resourceName} or { })
          else result)
      { }
      providerProjectionOwners;

  providerProjectionArtifacts = lib.mapAttrs
    (owner: projection: {
      data = (projection.privateArtifact or { }) // {
        zoneScopes = map
          (zoneName: {
            zone = zoneName;
            processRefs =
              let processes =
                if builtins.hasAttr zoneName (projection.processesByZone or { })
                then builtins.getAttr zoneName projection.processesByZone
                else { };
              in map
                (name: "${processes.${name}.type}/${name}")
                (lib.attrNames processes);
            resourceNames = lib.attrNames
                (if builtins.hasAttr zoneName (projection.resourcesByZone or { })
                 then builtins.getAttr zoneName projection.resourcesByZone
                 else { });
          })
          (lib.sort lib.lessThan (lib.attrNames cfg.zones));
      };
      installFileName = null;
      classification = "contractPrivateNonSecret";
      sensitivity = "nonSecret";
      enableEtc = false;
    })
    (lib.filterAttrs
      (_: projection: projection.enabled or false)
      (lib.listToAttrs (map
        (owner:
          lib.nameValuePair owner (providerProjection owner))
        providerProjectionOwners)));

  providerProjectionCollisions = lib.concatMap
    (owner:
      let projection = providerProjection owner;
      in lib.concatMap
        (zoneName:
          let
            authored = lib.attrNames (cfg.zones.${zoneName}.resources or { });
            generated =
              lib.attrNames
                (if builtins.hasAttr zoneName (projection.resourcesByZone or { })
                 then builtins.getAttr zoneName projection.resourcesByZone
                 else { })
              ++ lib.attrNames
                (if builtins.hasAttr zoneName (projection.processesByZone or { })
                 then builtins.getAttr zoneName projection.processesByZone
                 else { });
            collisions = lib.filter (name: builtins.elem name authored) generated;
          in map
            (name: {
              assertion = false;
              message = "d2b.zones.${zoneName}.resources.${name} collides with the ${owner} Provider projection.";
            })
            (lib.unique collisions))
        (lib.sort lib.lessThan (lib.attrNames cfg.zones)))
    providerProjectionOwners;

  stripRuntime = value:
    if builtins.isAttrs value
    then builtins.removeAttrs
      (lib.mapAttrs (_: stripRuntime) value)
      runtimeFields
    else if builtins.isList value
    then map stripRuntime value
    else value;

  stripCompilerDefaults = spec:
    builtins.removeAttrs spec (lib.filter
      (field:
        builtins.hasAttr field spec
        && spec.${field} == executionDefaults.${field})
      (lib.attrNames executionDefaults));

  optionalMetadata = resource:
    lib.optionalAttrs ((resource.metadata.ownerRef or null) != null) {
      ownerRef = resource.metadata.ownerRef;
    }
    // lib.optionalAttrs ((resource.metadata.labels or { }) != { }) {
      labels = resource.metadata.labels;
    }
    // lib.optionalAttrs ((resource.metadata.annotations or { }) != { }) {
      annotations = resource.metadata.annotations;
    };

  zoneResources = zoneName: zone:
    zone.resources
    // (cfg._resourceCompiler.volumeShorthand.${zoneName} or { })
    // providerResources zoneName
    // processResources zoneName;

  projectedResource = zoneName: resourceName: resource:
    if resource.type == "Device"
      && builtins.hasAttr "devices" (cfg._resourceCompiler or { })
      && builtins.hasAttr zoneName cfg._resourceCompiler.devices.byZone
      && builtins.hasAttr resourceName cfg._resourceCompiler.devices.byZone.${zoneName}
    then cfg._resourceCompiler.devices.byZone.${zoneName}.${resourceName}
    else resource;

  canonicalResource = zoneName: resourceName: resource:
    let
      projected = projectedResource zoneName resourceName resource;
      guestPatch =
        if projected.type == "Guest"
        then providerGuestPatches zoneName resourceName
        else { };
      patched =
        if projected.type == "Guest" && guestPatch != { }
        then projected // { spec = lib.recursiveUpdate (projected.spec or { }) guestPatch; }
        else projected;
    in {
      inherit apiVersion;
      type = patched.type;
      metadata = {
        name = resourceName;
        zone = zoneName;
      } // optionalMetadata patched;
      spec = stripRuntime
        (if builtins.elem patched.type [ "Host" "Guest" ]
         then (patched.spec or { })
         else stripCompilerDefaults (patched.spec or { }));
    };

  sortResources = resources:
    lib.sort
      (left: right:
        if left.type != right.type
        then left.type < right.type
        else left.metadata.name < right.metadata.name)
      resources;

  resourceList = zoneName: zone:
    sortResources (lib.mapAttrsToList
      (resourceName: resource: canonicalResource zoneName resourceName resource)
      (lib.filterAttrs (_: resource: resource.type != "Zone")
        (zoneResources zoneName zone)));
  canonicalJson = value: builtins.toJSON (resourcesBundle.canonical value);

  providerSchemaDigests = zoneName: zone:
    lib.listToAttrs (lib.filter
      (entry: entry != null)
      (lib.mapAttrsToList
        (resourceName: resource:
          if resource.type != "Provider" then null
          else
            let
              artifactId = resource.spec.artifactId or null;
              catalog = lib.findFirst
                (entry: entry.id == artifactId)
                null
                providerCatalogEntries;
              digest =
                if catalog != null
                  && catalog ? entry
                  && catalog.entry ? configDigest
                then catalog.entry.configDigest
                else null;
            in
            if digest == null
            then null
            else lib.nameValuePair "Provider/${resourceName}" digest)
        (lib.filterAttrs (_: resource: resource.type != "Zone")
          (zoneResources zoneName zone))));

  providerCatalogEntry = artifactId:
    lib.findFirst (entry: entry.id == artifactId) null providerCatalogEntries;

  publisherFor = artifactId:
    let
      artifact = cfg.artifacts.${artifactId};
      catalog = artifact.catalog or { };
      providerEntry = providerCatalogEntry artifactId;
    in
    catalog.publisher
      or (if providerEntry == null then null else providerEntry.entry.publisher or null);

  signatureIdFor = artifactId:
    let
      catalog = cfg.artifacts.${artifactId}.catalog or { };
      signatureValue = catalog.signature or null;
      signature = if builtins.isAttrs signatureValue then signatureValue else { };
    in
    catalog.signatureId or signature.signatureId or signature.id or "default";

  signingKeyFor = zone: publisher: catalog:
    let
      trusted = zone.trustedPublishers.${publisher} or null;
    in
    if trusted == null then catalog.signingKey or "" else trusted.signingKey;

  providerInputs = zone:
    let
      providerArtifacts = lib.filterAttrs
        (_: artifact: artifact.type == "provider" && artifact.catalog != null)
        (cfg.artifacts or { });
    in
    lib.concatMap
      (artifactId:
        let
          artifact = providerArtifacts.${artifactId};
          catalog = artifact.catalog;
          publisher = publisherFor artifactId;
          signingKey =
            if publisher == null
            then ""
            else signingKeyFor zone publisher catalog;
          complete =
            publisher != null
            && catalog ? packageDigest
            && catalog ? executableDigest
            && catalog ? manifestDigest
            && catalog ? configDigest;
        in
        lib.optional complete {
          artifactId = artifactId;
          type = artifact.type;
          storePath = "${artifact.package}";
          inherit publisher signingKey;
          signatureId = signatureIdFor artifactId;
          packageDigest = catalog.packageDigest;
          executableDigest = catalog.executableDigest;
          manifestDigest = catalog.manifestDigest;
          configSchemaDigest = catalog.configDigest;
        })
      (lib.sort lib.lessThan (lib.attrNames providerArtifacts));

  bundleData = zoneName: zone:
    let
      resources = resourceList zoneName zone;
      resourcesJson = canonicalJson resources;
      contentHash =
        "sha256:${resourcesBundle.framedDigest
          "d2b:v3:resource-bundle" resourcesJson}";
    in {
      schemaVersion = 3;
      bundleVersion = 1;
      zoneUid = resourcesBundle.stableUid "d2b:v3:zone-uid" zoneName;
      zone = zoneName;
      inherit contentHash;
      artifactCatalogDigest = catalogDigest;
      generatedAt = "1970-01-01T00:00:00.000Z";
      inherit resources;
      providerSchemaDigests = providerSchemaDigests zoneName zone;
    };

  bundlePath = zoneName: data:
    let
      providers = providerInputs cfg.zones.${zoneName};
      providerPackages = map
        (provider: cfg.artifacts.${provider.artifactId}.package)
        providers;
      compilerClosureInputs =
        providerPackages
        ++ [ schemaRoot ]
        ++ lib.optional (catalogPath != null) catalogPath;
      compilerClosureInputPaths =
        builtins.concatStringsSep "\n" (map toString compilerClosureInputs);
      compilerInputJson = builtins.toJSON {
        zone = zoneName;
        zoneUid = data.zoneUid;
        resources = data.resources;
        providerSchemaDigests = data.providerSchemaDigests;
        inherit providers;
        artifactCatalogPath =
          if catalogPath == null then null else "${catalogPath}";
        expectedArtifactCatalogDigest = catalogDigest;
        schemaRoot = "${schemaRoot}";
        # The compiler appends signed static Provider controller Processes
        # and their private processTemplates metadata. Those generated rows
        # stay out of the processes.json projection.
        expectedContentHash = data.contentHash;
        inherit strictSecrets;
      };
      compilerInput = pkgs.runCommand "d2b-resource-compiler-${zoneName}.json"
        {
          inherit compilerInputJson compilerClosureInputPaths;
          passAsFile = [ "compilerInputJson" "compilerClosureInputPaths" ];
        } ''
          cp "$compilerInputJsonPath" "$out"
        '';
    in pkgs.runCommand "d2b-zone-${zoneName}-resource-bundle.json"
      {
        inherit compilerInput compilerClosureInputPaths;
        passAsFile = [ "compilerClosureInputPaths" ];
        nativeBuildInputs = [ compilerPackage ];
      } ''
        set -euo pipefail
        d2b-resource-compiler compile \
          --input "$compilerInput" \
          --output "$out"
      '';

  bundles = lib.mapAttrs
    (zoneName: zone:
      let data = bundleData zoneName zone;
      in {
        inherit data;
        path = bundlePath zoneName data;
        installFileName = "zones/${zoneName}/resource-bundle.json";
        classification = "contractPrivateNonSecret";
        sensitivity = "nonSecret";
      })
    cfg.zones;
  activeBundles = bundles;
in
{
  options.d2b._bundle = {
    zoneResourceBundlesV3 = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
      internal = true;
      visible = false;
    };
  };

  config = {
    assertions = helperAssertions ++ providerProjectionCollisions;
    d2b._bundle.extraArtifacts = providerProjectionArtifacts;
    d2b._bundle.zoneResourceBundlesV3 = bundles;
    # The v3 emitter owns every installed path. Only the eval-visible data
    # field retains the compatibility projection used by older consumers.
    d2b._bundle.zoneResourceBundles = lib.mkForce activeBundles;
  };
}
