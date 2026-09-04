{ lib, pkgs, system, flakeRoot, ... }:

let
  compilerSource =
    builtins.readFile (flakeRoot + "/nixos-modules/bundle-zones.nix");
  shape = import ../../../../nixos-modules/generated/provider-catalog-shape.nix;
  testDigest = field:
    "sha256:${builtins.hashString "sha256" "bundle-artifacts/${field}"}";
  providerPackage = pkgs.stdenv.mkDerivation {
    pname = "bundle-artifacts-provider";
    version = "0";
    dontUnpack = true;
    installPhase = ''
      mkdir -p "$out/bin" "$out/share/d2b/provider"
      printf '%s\n' provider > "$out/bin/controller"
      chmod 0755 "$out/bin/controller"
      printf '%s\n' manifest \
        > "$out/share/d2b/provider/provider-manifest.json"
      printf '%s\n' signature \
        > "$out/share/d2b/provider/provider-manifest.json.sig"
      printf '%s\n' schema \
        > "$out/share/d2b/provider/config-schema.json"
    '';
  };
  providerCatalog =
    let
      digestFields = lib.listToAttrs (map
        (field: lib.nameValuePair field (testDigest field))
        shape.digestFields);
      plainFields = lib.listToAttrs (map
        (field: lib.nameValuePair field "bundle-artifacts/${field}")
        (lib.filter (field: !(lib.elem field shape.digestFields))
          shape.fields));
    in
    digestFields // plainFields // {
      providerName = "bundle-artifacts-provider";
      packageName = "bundle-artifacts-provider";
      publisher = "bundle-artifacts";
      version = "0.0.0";
      systems = [ system ];
      platform = system;
      signature = {
        signatureId = "bundle-artifacts";
        publisherRoot = "bundle-artifacts";
      };
      rootEpoch = 1;
      revocationStatus = "clear";
      denyStatus = "clear";
      instanceScope = "per-resource-target";
      supportedTargetKinds = [ "host" ];
      targetCapabilities = [{
        artifactDigest = testDigest "host-capability";
        requiredEffectClasses = [ "process" ];
        targetKind = "host";
      }];
      placementAnchor = "execution-ref";
      d2bdDigest = testDigest "d2bd";
      brokerDigest = testDigest "broker";
    };
  compilerPackage = pkgs.writeShellScriptBin
    "d2b-resource-compiler" "exit 0";
  schemaFile = pkgs.writeText "bundle-artifacts-schema" "{}";
  schemaRoot = pkgs.linkFarm "bundle-artifacts-schema-root" [{
    name = "schema.json";
    path = schemaFile;
  }];
  catalogPath = pkgs.writeText "bundle-artifacts-catalog" "{}";
  compilerEval = lib.evalModules {
    modules = [
      (import ../../../../nixos-modules/provider-catalog.nix)
      (import ../../../../nixos-modules/bundle-artifacts.nix)
      (import ../../../../nixos-modules/bundle-zones.nix)
      ({ ... }: {
        options.assertions = lib.mkOption {
          type = lib.types.listOf lib.types.anything;
          default = [ ];
        };
        options.environment.etc = lib.mkOption {
          type = lib.types.anything;
          default = { };
        };
        options.d2b.daemonExperimental.enable = lib.mkOption {
          type = lib.types.bool;
          default = false;
        };
        options.d2b.zones = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = { };
        };
        options.d2b._resourceCompiler = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = { };
          internal = true;
          visible = false;
        };
        options.d2b._artifactCatalogV3 = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = { };
          internal = true;
          visible = false;
        };
        config.d2b.artifacts."bundle-artifacts-provider" = {
          package = providerPackage;
          type = "provider";
          catalog = providerCatalog;
        };
        config.d2b.zones.work.resources."bundle-provider" = {
          type = "Provider";
          metadata = { };
          spec.artifactId = "bundle-artifacts-provider";
        };
        config.d2b._artifactCatalogV3 = {
          catalogDigest = testDigest "catalog";
          path = catalogPath;
        };
        config.d2b._resourceCompiler.phase2 = {
          compiler = compilerPackage;
          inherit schemaRoot;
          strictSecrets = true;
        };
      })
    ];
    specialArgs = { inherit pkgs; };
  };
  compilerBundle =
    compilerEval.config.d2b._bundle.zoneResourceBundles.work;
  compilerInput = compilerBundle.path.compilerInput;
  asStorePath = value:
    builtins.unsafeDiscardStringContext (toString value);
  providerPath = asStorePath providerPackage;
  schemaRootPath = asStorePath schemaRoot;
  catalogStorePath = asStorePath catalogPath;
  compilerPath = asStorePath compilerPackage;
  closurePaths = lib.filter (path: path != "")
    (lib.splitString "\n" (builtins.unsafeDiscardStringContext
      compilerBundle.path.compilerClosureInputPaths));
  compilerInputJson = builtins.unsafeDiscardStringContext
    compilerInput.compilerInputJson;
  publicResourcesJson = builtins.toJSON compilerBundle.data.resources;
  realCompilerClosureProof = {
    providerCatalogEntryCount =
      builtins.length compilerEval.config.d2b._providerCatalog.entries;
    providerCatalogComplete = lib.all
      (field: builtins.hasAttr field providerCatalog)
      shape.fields;
    providerPackageDeclared =
      builtins.isAttrs providerPackage
      && builtins.length (providerPackage.outputs or [ ]) > 0;
    providerClosureNonEmpty =
      builtins.length closurePaths > 0
      && lib.elem providerPath closurePaths;
    catalogClosurePresent = lib.elem catalogStorePath closurePaths;
    schemaClosurePresent = lib.elem schemaRootPath closurePaths;
    compilerIsExplicitInput =
      lib.elem compilerPath
        (map asStorePath compilerBundle.path.nativeBuildInputs);
    outerPassAsFile =
      lib.elem "compilerClosureInputPaths" compilerBundle.path.passAsFile;
    innerPassAsFile = lib.all
      (field: lib.elem field compilerInput.passAsFile)
      [ "compilerInputJson" "compilerClosureInputPaths" ];
    serializedPrivatePaths = lib.all
      (path: lib.hasInfix path compilerInputJson)
      [ providerPath catalogStorePath schemaRootPath ];
    publicResourcesAreStorePathFree =
      !(lib.hasInfix "/nix/store/" publicResourcesJson);
  };
in
{
  "bundle-artifacts/phase2-compiler-uses-real-provider-closure" = {
    expr = realCompilerClosureProof;
    expected = {
      providerCatalogEntryCount = 1;
      providerCatalogComplete = true;
      providerPackageDeclared = true;
      providerClosureNonEmpty = true;
      catalogClosurePresent = true;
      schemaClosurePresent = true;
      compilerIsExplicitInput = true;
      outerPassAsFile = true;
      innerPassAsFile = true;
      serializedPrivatePaths = true;
      publicResourcesAreStorePathFree = true;
    };
  };

  "bundle-artifacts/phase2-compiler-is-the-build-validator" = {
    expr = {
      sourceUsesCompiler =
        lib.hasInfix "d2b-resource-compiler compile" compilerSource
        && !(lib.hasInfix "python3 -" compilerSource);
      sourceWiresCompilerInput =
        lib.hasInfix ("compilerInput = " + "pkgs." + "runCommand") compilerSource
        && lib.hasInfix "compilerClosureInputs =" compilerSource
        && lib.hasInfix
          "passAsFile = [ \"compilerInputJson\" \"compilerClosureInputPaths\" ]"
          compilerSource
        && lib.hasInfix
          ("nativeBuildInputs = [ " + "compilerPackage ]")
          compilerSource;
      commandReceivesExpectedHash =
        lib.hasInfix "expectedContentHash = data.contentHash" compilerSource;
    };
    expected = {
      sourceUsesCompiler = true;
      sourceWiresCompilerInput = true;
      commandReceivesExpectedHash = true;
    };
  };

  "bundle-artifacts/phase2-input-does-not-inline-duplicate-large-payloads" = {
    expr = {
      usesPrivatePathRefs =
        lib.hasInfix "artifactCatalogPath =" compilerSource
        && lib.hasInfix "schemaRoot =" compilerSource;
      noCatalogPayloadCopy = !(lib.hasInfix "catalogData" compilerSource);
      noSchemaPayloadCopy = !(lib.hasInfix "schemaRootData" compilerSource);
      noPythonCompiler = !(lib.hasInfix "python3 -" compilerSource);
    };
    expected = {
      usesPrivatePathRefs = true;
      noCatalogPayloadCopy = true;
      noSchemaPayloadCopy = true;
      noPythonCompiler = true;
    };
  };
}
