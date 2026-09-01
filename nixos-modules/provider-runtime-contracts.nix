# Provider-specific runtime and transport boundary assertions.
#
# These checks are intentionally eval-time: a malformed Provider placement,
# raw locator, or cross-boundary credential scope must fail before any bundle
# or process effect is emitted.
{ config, lib, ... }:

let
  cfg = config.d2b;
  validation = cfg._providerRuntimeValidation or { };
  digestPattern = "sha256:[0-9a-f]{64}";

  validDigest = value:
    builtins.isString value && builtins.match digestPattern value != null;

  configuredArtifactCatalogAssertions =
    let
      expected = validation.expectedArtifactCatalogDigest or null;
      activated = validation.activatedArtifactCatalogDigest or null;
      configured = expected != null || activated != null;
    in
    lib.optionals configured [
      {
        assertion = validDigest expected;
        message = ''
          d2b._providerRuntimeValidation.expectedArtifactCatalogDigest must
          be a lowercase sha256 digest.
        '';
      }
      {
        assertion = validDigest activated;
        message = ''
          d2b._providerRuntimeValidation.activatedArtifactCatalogDigest must
          be a lowercase sha256 digest.
        '';
      }
      {
        assertion = expected != null
          && activated != null
          && expected == activated;
        message = ''
          activation-time artifactCatalogDigest must match the committed
          artifact catalog digest; refusing to apply a different catalog.
        '';
      }
    ];

  bundleArtifactCatalogAssertions =
    let
      artifactCatalog =
        cfg._artifactCatalogV3 or { };
      catalogDigest = artifactCatalog.catalogDigest or null;
      bundles =
        (cfg._bundle or { }).zoneResourceBundles or { };
    in
    lib.optionals (catalogDigest != null) (lib.mapAttrsToList
      (zoneName: bundle:
        let
          data = if builtins.isAttrs bundle then bundle.data or { } else { };
          bundleDigest = data.artifactCatalogDigest or null;
        in {
          assertion = validDigest bundleDigest
            && bundleDigest == catalogDigest;
          message = ''
            d2b.zones.${zoneName} activation-time artifactCatalogDigest must
            match the committed artifact catalog digest.
          '';
        })
      bundles);

  parseRef = value:
    let parts = if builtins.isString value then lib.splitString "/" value else [ ];
    in if builtins.length parts == 2 then {
      type = builtins.elemAt parts 0;
      name = builtins.elemAt parts 1;
    } else null;

  attrOr = attrs: name: fallback:
    if builtins.isAttrs attrs && builtins.hasAttr name attrs
    then attrs.${name}
    else fallback;

  secretKey = key:
    builtins.elem key [
      "accessKey"
      "accessToken"
      "apiKey"
      "clientSecret"
      "connectionString"
      "credential"
      "credentialBytes"
      "key"
      "password"
      "privateKey"
      "rawCredential"
      "sasKey"
      "sasToken"
      "secret"
      "token"
    ]
    || lib.hasSuffix "Password" key
    || lib.hasSuffix "Secret" key
    || lib.hasSuffix "Token" key
    || lib.hasSuffix "Key" key;

  secretText = value:
    if !builtins.isString value
    then false
    else
      let text = lib.toLower value;
      in lib.hasInfix "-----begin" text
        || lib.hasPrefix "eyj" text
        || lib.hasInfix "accountkey" text
        || lib.hasInfix "bearer " text
        || lib.hasInfix "clientsecret" text
        || lib.hasInfix "privatekey" text
        || lib.hasInfix "sharedaccess" text
        || (lib.hasInfix "?sv=" text && lib.hasInfix "&sig=" text);

  containsSecretMaterial = value:
    if builtins.isString value
    then secretText value
    else if builtins.isList value
    then lib.any containsSecretMaterial value
    else if builtins.isAttrs value
    then lib.any
      (key: secretKey key || containsSecretMaterial value.${key})
      (builtins.attrNames value)
    else false;

  locatorKey = key:
    builtins.elem key [
      "argv"
      "binaryPath"
      "cid"
      "command"
      "commandLine"
      "devicePath"
      "env"
      "envVars"
      "environment"
      "hostPath"
      "nodeRegistry"
      "path"
      "program"
      "rawCid"
      "remoteNodeRegistry"
      "socket"
      "socketPath"
      "tapFd"
      "tapName"
      "unit"
    ];

  containsLocator = value:
    if builtins.isAttrs value
    then lib.any
      (key: locatorKey key || containsLocator value.${key})
      (builtins.attrNames value)
    else if builtins.isList value
    then lib.any containsLocator value
    else false;

  resourcesFor = zone:
    lib.mapAttrsToList
      (name: resource: {
        inherit name resource zone;
        path = "d2b.zones.${zone}.resources.${name}";
      })
      (cfg.zones.${zone}.resources or { });

  allResources = lib.concatMap resourcesFor (lib.attrNames cfg.zones);

  refType = value:
    let parsed = parseRef value;
    in if parsed == null then null else parsed.type;

  resourceFor = row: value:
    let
      parsed = parseRef value;
      resources = cfg.zones.${row.zone}.resources or { };
    in
      if parsed != null && builtins.hasAttr parsed.name resources
      then resources.${parsed.name}
      else null;

  resolvesAs = row: expectedType: value:
    let
      parsed = parseRef value;
      resource = resourceFor row value;
    in
      builtins.isString value
      && parsed != null
      && parsed.type == expectedType
      && resource != null
      && resource.type == expectedType;

  runtimeProviderRefs = [
    "Provider/runtime-azure-container-apps"
    "Provider/runtime-azure-virtual-machine"
    "Provider/runtime-cloud-hypervisor"
    "Provider/transport-azure-relay"
    "Provider/transport-unix"
    "Provider/transport-vsock"
  ];

  providerRows = lib.filter
    (row: row.resource.type == "Provider")
    allResources;

  guestRows = lib.filter
    (row: row.resource.type == "Guest")
    allResources;

  processRows = lib.filter
    (row: builtins.elem row.resource.type [ "Process" "EphemeralProcess" ])
    allResources;

  zoneLinkRows = lib.filter
    (row: row.resource.type == "ZoneLink")
    allResources;

  providerAssertions = row:
    let
      spec = row.resource.spec or { };
      configValue = attrOr spec "config" { };
      providerConfig =
        if builtins.isAttrs configValue then configValue else { };
      providerRef =
        if row.resource.type == "Provider"
        then "Provider/${row.name}"
        else spec.providerRef or "";
      credentialRefs =
        if providerRef == "Provider/runtime-azure-container-apps" then
          lib.filter (ref: ref != null) [
            (providerConfig.controlCredentialRef or null)
            (providerConfig.pullCredentialRef or null)
          ]
        else if providerRef == "Provider/runtime-azure-virtual-machine" then
          [
            (providerConfig.armCredentialRef or null)
          ]
        else
          [ ];
      gatewayRef =
        if providerRef == "Provider/runtime-azure-container-apps"
        then providerConfig.gatewayExecutionRef or null
        else providerConfig.controllerExecutionRef or null;
      credentialScopeMatches = credentialRef:
        let
          credential = resourceFor row credentialRef;
        in
        resolvesAs row "Credential" credentialRef
        && ((credential.spec or { }).scope or { }).executionRef == gatewayRef;
      credentialBoundaryMatches = credentialRef:
        let
          credential = resourceFor row credentialRef;
        in
        if credential == null then false else
        let
          credentialSpec = credential.spec or { };
          credentialProviderRef = credentialSpec.providerRef or null;
          allowedProviders = [
            "Provider/credential-managed-identity"
            "Provider/credential-entra"
          ];
        in
          resolvesAs row "Credential" credentialRef
          && resolvesAs row "Provider" credentialProviderRef
          && builtins.elem credentialProviderRef allowedProviders
          && (credentialSpec.consumerRef or null) == providerRef
          && builtins.elem "acquire-token" (credentialSpec.allowedOperations or [ ])
          && (credentialSpec.audience or null) == "https://management.azure.com/"
          && ((credentialSpec.scope or { }).executionRef or null) == gatewayRef;
    in
      (if lib.elem providerRef runtimeProviderRefs then [
        {
          assertion = builtins.isAttrs configValue;
          message = "${row.path}.spec.config must be an attribute set.";
        }
        {
          assertion = !containsSecretMaterial providerConfig;
          message = "${row.path}.spec.config Provider config must not contain credential material.";
        }
        {
          assertion = !containsLocator providerConfig;
          message = "${row.path}.spec.config Provider config must not contain raw host locators or argv.";
        }
      ] else [ ])
      ++ (if providerRef == "Provider/runtime-cloud-hypervisor" then [
        {
          assertion = resolvesAs row "Host" (providerConfig.controllerExecutionRef or null);
          message = "${row.path}.spec.config.controllerExecutionRef must resolve to Host.";
        }
      ] else [ ])
      ++ (if providerRef == "Provider/runtime-azure-virtual-machine" then [
        {
          assertion = resolvesAs row "Guest" (providerConfig.controllerExecutionRef or null);
          message = "${row.path}.spec.config.controllerExecutionRef must resolve to the gateway Guest.";
        }
        {
          assertion = lib.all credentialScopeMatches credentialRefs;
          message = "${row.path}.spec.config ARM credential scope must match controllerExecutionRef.";
        }
        {
          assertion = lib.all credentialBoundaryMatches credentialRefs;
          message = "${row.path}.spec.config ARM credential must use a supported Azure credential Provider, management audience, acquire-token operation, and matching consumerRef.";
        }
        {
          assertion = providerConfig.networkRef or null == null
            || resolvesAs row "Network" providerConfig.networkRef;
          message = "${row.path}.spec.config.networkRef must resolve to a same-Zone Network.";
        }
      ] else [ ])
      ++ (if providerRef == "Provider/runtime-azure-container-apps" then [
        {
          assertion = resolvesAs row "Guest" (providerConfig.gatewayExecutionRef or null);
          message = "${row.path}.spec.config.gatewayExecutionRef must resolve to the gateway Guest.";
        }
        {
          assertion = providerConfig.controlCredentialRef or null != null;
          message = "${row.path}.spec.config.controlCredentialRef is required.";
        }
        {
          assertion = lib.all credentialScopeMatches credentialRefs;
          message = "${row.path}.spec.config credential scopes must match gatewayExecutionRef.";
        }
        {
          assertion = lib.all credentialBoundaryMatches credentialRefs;
          message = "${row.path}.spec.config credentials must use a supported Azure credential Provider, management audience, acquire-token operation, and matching consumerRef.";
        }
        {
          assertion = providerConfig.networkRef or null == null
            || resolvesAs row "Network" providerConfig.networkRef;
          message = "${row.path}.spec.config.networkRef must resolve to a same-Zone Network.";
        }
      ] else [ ])
      ++ (if providerRef == "Provider/transport-azure-relay" then [
        {
          assertion = resolvesAs row "Guest" (providerConfig.executionRef or null);
          message = "${row.path}.spec.config.executionRef must resolve to a gateway Guest.";
        }
        {
          assertion = resolvesAs row "Network" (providerConfig.networkRef or null);
          message = "${row.path}.spec.config.networkRef must resolve to a Network.";
        }
      ] else [ ])
      ++ (if providerRef == "Provider/transport-unix" then [
        {
          assertion = resolvesAs row "Host" (providerConfig.executionRef or null);
          message = "${row.path}.spec.config.executionRef must resolve to a Host.";
        }
      ] else [ ])
      ++ (if providerRef == "Provider/transport-vsock" then [
        {
          assertion = resolvesAs row "Host" (providerConfig.executionRef or null)
            || resolvesAs row "Guest" (providerConfig.executionRef or null);
          message = "${row.path}.spec.config.executionRef must resolve to a same-Zone Host or Guest.";
        }
      ] else [ ]);

  guestAssertions = row:
    let
      spec = row.resource.spec or { };
      providerRef = spec.providerRef or "";
      providerEnvelopeValue = attrOr spec "provider" { };
      providerEnvelope =
        if builtins.isAttrs providerEnvelopeValue
        then providerEnvelopeValue
        else { };
      settingsValue = attrOr providerEnvelope "settings" { };
      settings =
        if builtins.isAttrs settingsValue
        then settingsValue
        else { };
      providerResolution =
        if lib.elem providerRef runtimeProviderRefs then [
          {
            assertion = resolvesAs row "Provider" providerRef;
            message = "${row.path}.spec.providerRef must resolve to an existing same-Zone runtime Provider.";
          }
        ] else [ ];
      forbidden = [
        "hostPath"
        "socketPath"
        "rawCid"
        "cid"
        "tapName"
        "tapFd"
        "argv"
        "commandLine"
      ];
      forbiddenPresent = lib.any (key: builtins.hasAttr key settings) forbidden;
      forbiddenSpecPresent = lib.any (key: builtins.hasAttr key spec) forbidden;
      zoneShape = lib.any
        (key: builtins.hasAttr key spec)
        [ "parentZone" "childZone" "zoneLink" "routeCursor" "authority" ];
    in
      providerResolution
      ++ (if providerRef == "Provider/runtime-cloud-hypervisor" then [
        {
          assertion = (spec.systemArtifactId or null) != null;
          message = "${row.path}.spec.systemArtifactId is required for runtime-cloud-hypervisor.";
        }
        {
          assertion = !((settings.memoryShared or true) == false
            && (spec.volumeAttachmentDefaults or [ ]) != [ ]);
          message = "${row.path}: memoryShared=false is incompatible with virtiofs attachments.";
        }
      ] else [ ])
      ++ (if lib.elem providerRef [
        "Provider/runtime-cloud-hypervisor"
        "Provider/runtime-azure-container-apps"
        "Provider/runtime-azure-virtual-machine"
      ] then [
        {
          assertion = !forbiddenPresent && !forbiddenSpecPresent;
          message = "${row.path}.spec.provider.settings must not contain raw host locators or argv.";
        }
        {
          assertion = !containsSecretMaterial providerEnvelope
            && !containsSecretMaterial spec;
          message = "${row.path}.spec.provider.settings must not contain credential material.";
        }
      ] else [ ])
      ++ (if providerRef == "Provider/runtime-azure-virtual-machine" then [
        {
          assertion = (spec.systemArtifactId or null) == null;
          message = "${row.path}.spec.systemArtifactId must be null for runtime-azure-virtual-machine.";
        }
      ] else [ ])
      ++ (if providerRef == "Provider/runtime-azure-container-apps" then [
        {
          assertion = !zoneShape;
          message = "${row.path}: aca-sandbox-is-not-zone.";
        }
      ] else [ ]);

  processAssertions = row:
    let spec = row.resource.spec or { };
    providerRef = spec.ownerProviderRef or spec.providerRef or "";
    provider = resourceFor row providerRef;
    providerConfig =
      if provider == null then { } else (provider.spec or { }).config or { };
    isGatewayProvider = lib.elem providerRef [
      "Provider/runtime-azure-container-apps"
      "Provider/runtime-azure-virtual-machine"
    ];
    executionRef = spec.executionRef or null;
    providerExecutionRef =
      if providerRef == "Provider/runtime-azure-container-apps"
      then providerConfig.gatewayExecutionRef or null
      else if providerRef == "Provider/transport-azure-relay"
      then providerConfig.executionRef or null
      else if providerRef == "Provider/transport-unix"
      then providerConfig.executionRef or null
      else if providerRef == "Provider/transport-vsock"
      then providerConfig.executionRef or null
      else providerConfig.controllerExecutionRef or null;
    in (lib.optionals (lib.elem providerRef runtimeProviderRefs) [
      {
        assertion = resolvesAs row "Provider" providerRef;
        message = "${row.path}.spec.providerRef must resolve to an existing same-Zone runtime Provider.";
      }
      {
        assertion = resolvesAs row "Host" providerExecutionRef
          || resolvesAs row "Guest" providerExecutionRef;
        message = "${row.path}.spec.owner Provider execution reference must resolve to a same-Zone Host or Guest.";
      }
      {
        assertion = executionRef == providerExecutionRef;
        message = "${row.path}.spec.executionRef must match the owning Provider execution reference.";
      }
    ]) ++ lib.optionals isGatewayProvider [
      {
        assertion = refType executionRef == "Guest";
        message = "${row.path}.spec.executionRef must be the configured gateway Guest; Host placement is forbidden.";
      }
    ];

  zoneLinkAssertions = row:
    let
      spec = row.resource.spec or { };
      settings = spec.transportSettings or { };
      providerRef = spec.transportProviderRef or "";
      provider = resourceFor row providerRef;
      providerConfig =
        if provider == null then { } else (provider.spec or { }).config or { };
      credentialRefs = spec.transportCredentials or [ ];
      credentialRows = map (ref: resourceFor row ref) credentialRefs;
      credentialAudiences = map
        (credential:
          if credential == null then null else (credential.spec or { }).audience or null)
        credentialRows;
      credentialBoundaryMatches = credential:
        if credential == null then false else
        let
          credentialSpec = credential.spec or { };
          credentialProviderRef = credentialSpec.providerRef or null;
        in
          resolvesAs row "Provider" credentialProviderRef
          && builtins.elem credentialProviderRef [
            "Provider/credential-managed-identity"
            "Provider/credential-entra"
          ]
          && (credentialSpec.consumerRef or null) == providerRef
          && builtins.elem "acquire-token" (credentialSpec.allowedOperations or [ ])
          && builtins.elem (credentialSpec.audience or null) [
            "azure-relay-listen"
            "azure-relay-send"
          ]
          && ((credentialSpec.scope or { }).executionRef or null)
            == (providerConfig.executionRef or null);
      forbidden = [
        "socketPath"
        "hostPath"
        "password"
        "token"
        "key"
        "credential"
        "credentialRef"
      ];
      secretKey = key:
        builtins.elem key forbidden
        || lib.hasSuffix "CredRef" key
        || lib.hasSuffix "Credential" key;
      exactRelaySettings = [
        "relayEntityId"
        "relayNamespaceId"
      ];
      unixSettings = [ "socketKind" ];
      vsockSettings = [
        "connectTimeoutSeconds"
        "guestRef"
        "portClass"
      ];
    in [
      {
        assertion = lib.all (key: !secretKey key) (lib.attrNames settings)
          && !containsSecretMaterial settings
          && !containsLocator settings;
        message = "${row.path}.spec.transportSettings must not contain credential or locator fields.";
      }
    ]
      ++ lib.optionals (providerRef == "Provider/transport-azure-relay") [
        {
          assertion = lib.sort builtins.lessThan (lib.attrNames settings) == exactRelaySettings;
          message = "${row.path}.spec.transportSettings must contain exactly relayNamespaceId and relayEntityId.";
        }
        {
          assertion = builtins.isString (settings.relayNamespaceId or null)
            && builtins.match "^[a-zA-Z0-9][a-zA-Z0-9-]{1,48}[a-zA-Z0-9]$" settings.relayNamespaceId != null;
          message = "${row.path}.spec.transportSettings.relayNamespaceId has an invalid Azure Relay namespace shape.";
        }
        {
          assertion = builtins.isString (settings.relayEntityId or null)
            && builtins.match "^[a-z][a-z0-9-]{1,49}$" settings.relayEntityId != null;
          message = "${row.path}.spec.transportSettings.relayEntityId has an invalid Azure Relay entity shape.";
        }
        {
          assertion = builtins.length credentialRefs == 2
            && builtins.length (lib.unique credentialRefs) == 2
            && lib.all (credential: credential != null && credential.type == "Credential")
              credentialRows
            && lib.sort builtins.lessThan credentialAudiences
              == [ "azure-relay-listen" "azure-relay-send" ];
          message = "${row.path}.spec.transportCredentials must contain exactly one same-Zone azure-relay-listen and one azure-relay-send Credential.";
        }
        {
          assertion = lib.all
            (credential:
              ((credential.spec or { }).scope or { }).executionRef
              == (providerConfig.executionRef or null))
            credentialRows;
          message = "${row.path}.spec.transportCredentials scope must match the Relay Provider executionRef.";
        }
        {
          assertion = lib.all credentialBoundaryMatches credentialRows;
          message = "${row.path}.spec.transportCredentials must use supported credential Providers, acquire-token, and the Relay consumerRef.";
        }
      ]
      ++ lib.optionals (providerRef == "Provider/transport-unix") [
        {
          assertion = lib.all (key: builtins.elem key unixSettings) (lib.attrNames settings)
            && (!builtins.hasAttr "socketKind" settings
              || builtins.elem settings.socketKind [ "seqpacket" "stream" ]);
          message = "${row.path}.spec.transportSettings for Provider/transport-unix accepts only socketKind=seqpacket or socketKind=stream.";
        }
        {
          assertion = credentialRefs == [ ];
          message = "${row.path}.spec.transportCredentials must be empty for Provider/transport-unix.";
        }
      ]
      ++ lib.optionals (providerRef == "Provider/transport-vsock") [
        {
          assertion = lib.all (key: builtins.elem key vsockSettings) (lib.attrNames settings)
            && builtins.hasAttr "guestRef" settings
            && resolvesAs row "Guest" settings.guestRef;
          message = "${row.path}.spec.transportSettings for Provider/transport-vsock must contain a same-Zone guestRef and only allocator-owned fields.";
        }
        {
          assertion = (settings.portClass or "d2b-link") == "d2b-link";
          message = "${row.path}.spec.transportSettings.portClass must be d2b-link.";
        }
        {
          assertion = builtins.isInt (settings.connectTimeoutSeconds or 30)
            && (settings.connectTimeoutSeconds or 30) >= 1
            && (settings.connectTimeoutSeconds or 30) <= 60;
          message = "${row.path}.spec.transportSettings.connectTimeoutSeconds must be between 1 and 60.";
        }
        {
          assertion = credentialRefs == [ ];
          message = "${row.path}.spec.transportCredentials must be empty for Provider/transport-vsock.";
        }
      ];

  allAssertions =
    lib.concatMap providerAssertions providerRows
    ++ lib.concatMap guestAssertions guestRows
    ++ lib.concatMap processAssertions processRows
    ++ lib.concatMap zoneLinkAssertions zoneLinkRows;
in
{
  options.d2b._providerRuntimeValidation = {
    expectedArtifactCatalogDigest = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      internal = true;
      visible = false;
      description = "Committed artifact catalog digest expected at activation.";
    };
    activatedArtifactCatalogDigest = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      internal = true;
      visible = false;
      description = "Artifact catalog digest observed by activation.";
    };
  };

  config.assertions =
    allAssertions
    ++ configuredArtifactCatalogAssertions
    ++ bundleArtifactCatalogAssertions;
}
