# Focused positive and negative coverage for the eval-time Provider runtime
# boundary assertions.
{ lib, pkgs, ... }:

let
  providerRuntimeContracts =
    import ../../../../nixos-modules/provider-runtime-contracts.nix;

  mkEvalContracts = modules:
    lib.evalModules {
      modules = [
        providerRuntimeContracts
        {
          options.assertions = lib.mkOption {
            type = lib.types.listOf lib.types.anything;
            default = [ ];
          };
          options.d2b.zones = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = { };
          };
          options.d2b._artifactCatalogV3 = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = { };
          };
          options.d2b._bundle = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = { };
          };
        }
      ] ++ modules;
    };

  contractBase = { ... }: {
    d2b.zones.local-root.resources = {
      host = {
        type = "Host";
        spec = { };
      };
      gateway = {
        type = "Guest";
        spec = {
          providerRef = "Provider/runtime-azure-container-apps";
          gateway = { };
        };
      };
      control-network = {
        type = "Network";
        spec = { };
      };
      system = {
        type = "Provider";
        spec = {
          artifactId = "system";
          config = { };
        };
      };
      credential-managed-identity = {
        type = "Provider";
        spec = {
          artifactId = "credential-managed-identity";
          config = { };
        };
      };
      credential-entra = {
        type = "Provider";
        spec = {
          artifactId = "credential-entra";
          config = { };
        };
      };
      runtime-azure-container-apps = {
        type = "Provider";
        spec = {
          config = {
            gatewayExecutionRef = "Guest/gateway";
            controlCredentialRef = "Credential/aca-control";
            pullCredentialRef = "Credential/aca-pull";
            networkRef = "Network/control-network";
          };
        };
      };
      runtime-azure-virtual-machine = {
        type = "Provider";
        spec = {
          config = {
            controllerExecutionRef = "Guest/gateway";
            armCredentialRef = "Credential/vm-arm";
            networkRef = "Network/control-network";
          };
        };
      };
      runtime-cloud-hypervisor = {
        type = "Provider";
        spec = {
          config = {
            controllerExecutionRef = "Host/host";
          };
        };
      };
      transport-azure-relay = {
        type = "Provider";
        spec = {
          config = {
            executionRef = "Guest/gateway";
            networkRef = "Network/control-network";
          };
        };
      };
      aca-control = {
        type = "Credential";
        spec = {
          providerRef = "Provider/credential-managed-identity";
          scope.executionRef = "Guest/gateway";
          audience = "https://management.azure.com/";
          allowedOperations = [ "acquire-token" ];
          consumerRef = "Provider/runtime-azure-container-apps";
        };
      };
      aca-pull = {
        type = "Credential";
        spec = {
          providerRef = "Provider/credential-entra";
          scope.executionRef = "Guest/gateway";
          audience = "https://management.azure.com/";
          allowedOperations = [ "acquire-token" ];
          consumerRef = "Provider/runtime-azure-container-apps";
        };
      };
      vm-arm = {
        type = "Credential";
        spec = {
          providerRef = "Provider/credential-managed-identity";
          scope.executionRef = "Guest/gateway";
          audience = "https://management.azure.com/";
          allowedOperations = [ "acquire-token" ];
          consumerRef = "Provider/runtime-azure-virtual-machine";
        };
      };
      relay-listen = {
        type = "Credential";
        spec = {
          providerRef = "Provider/credential-managed-identity";
          audience = "azure-relay-listen";
          scope.executionRef = "Guest/gateway";
          allowedOperations = [ "acquire-token" ];
          consumerRef = "Provider/transport-azure-relay";
        };
      };
      relay-send = {
        type = "Credential";
        spec = {
          providerRef = "Provider/credential-entra";
          audience = "azure-relay-send";
          scope.executionRef = "Guest/gateway";
          allowedOperations = [ "acquire-token" ];
          consumerRef = "Provider/transport-azure-relay";
        };
      };
      system-guest = {
        type = "Guest";
        spec = {
          providerRef = "Provider/runtime-cloud-hypervisor";
          systemArtifactId = "system";
          provider.settings.memoryShared = true;
        };
      };
      relay-link = {
        type = "ZoneLink";
        spec = {
          childZoneName = "child";
          transportProviderRef = "Provider/transport-azure-relay";
          transportSettings = {
            relayNamespaceId = "relay-prod";
            relayEntityId = "gateway";
          };
          transportCredentials = [
            "Credential/relay-listen"
            "Credential/relay-send"
          ];
          disabled = false;
          limits = {
            maxActiveStreams = 32;
            maxPendingIntents = 256;
            reconnectMaxAttempts = 10;
            reconnectWindowSecs = 300;
          };
        };
      };
    };
    d2b.zones.child = {
      parentZone = "local-root";
      resources = {
        child-guest = {
          type = "Guest";
          spec = { };
        };
        transport-vsock = {
          type = "Provider";
          spec = {
            config = {
              executionRef = "Guest/child-guest";
            };
          };
        };
        child-vsock-link = {
          type = "ZoneLink";
          spec = {
            childZoneName = "child";
            transportProviderRef = "Provider/transport-vsock";
            transportSettings = {
              guestRef = "Guest/child-guest";
              portClass = "d2b-link";
              connectTimeoutSeconds = 30;
            };
            transportCredentials = [ ];
            disabled = false;
            limits = {
              maxActiveStreams = 32;
              maxPendingIntents = 256;
              reconnectMaxAttempts = 10;
              reconnectWindowSecs = 300;
            };
          };
        };
      };
    };
  };

  failureMessages = modules:
    map (assertion: assertion.message)
      (lib.filter (assertion: !assertion.assertion)
        (mkEvalContracts modules).config.assertions);

  hasFailure = needle: modules:
    lib.any (message: lib.hasInfix needle message)
      (failureMessages modules);

  positive = mkEvalContracts [ contractBase ];
in
{
  "provider-runtime-contracts/accepts-valid-runtime-provider-bindings" = {
    expr = lib.filter (assertion: !assertion.assertion)
      positive.config.assertions;
    expected = [ ];
  };

  "provider-runtime-contracts/rejects-unknown-same-zone-provider-reference" = {
    expr = hasFailure "existing same-Zone runtime Provider" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.gateway.spec.providerRef =
          lib.mkForce "Provider/runtime-cloud-hypervisor";
        d2b.zones.local-root.resources.runtime-cloud-hypervisor.type =
          lib.mkForce "Network";
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts/rejects-cross-zone-provider-reference" = {
    expr = hasFailure "existing same-Zone runtime Provider" [
      contractBase
      ({ ... }: {
        d2b.zones.child.resources.gateway = {
          type = "Guest";
          spec.providerRef = "Provider/runtime-azure-container-apps";
        };
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-enforces-vm-arm-credential-scope" = {
    expr = hasFailure "ARM credential scope must match controllerExecutionRef" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.vm-arm.spec.scope.executionRef =
          lib.mkForce "Guest/other";
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-requires-exact-relay-settings" = {
    expr = hasFailure "must contain exactly relayNamespaceId and relayEntityId" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.relay-link.spec.transportSettings.extra =
          "rejected";
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-validates-relay-identifiers" = {
    expr = hasFailure "relayEntityId has an invalid Azure Relay entity shape" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.relay-link.spec.transportSettings.relayEntityId =
          lib.mkForce "Not_An_Entity";
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-requires-provider-resolution-for-processes" = {
    expr = hasFailure "spec.providerRef must resolve to an existing same-Zone runtime Provider" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.runtime-cloud-hypervisor.type =
          lib.mkForce "Network";
        d2b.zones.local-root.resources.worker = {
          type = "Process";
          spec = {
            providerRef = "Provider/runtime-cloud-hypervisor";
            executionRef = "Guest/gateway";
          };
        };
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-rejects-process-on-wrong-owning-guest" = {
    expr = hasFailure "must match the owning Provider execution reference" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.worker = {
          type = "Process";
          spec = {
            providerRef = "Provider/runtime-azure-container-apps";
            executionRef = "Guest/system-guest";
          };
        };
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-allows-aca-without-optional-pull-credential" = {
    expr = lib.filter (assertion: !assertion.assertion)
      (mkEvalContracts [
        contractBase
        ({ ... }: {
          d2b.zones.local-root.resources.runtime-azure-container-apps.spec.config.pullCredentialRef =
            lib.mkForce null;
        })
      ]).config.assertions;
    expected = [ ];
  };

  "provider-runtime-contracts-rejects-relay-role-credential-shape" = {
    expr = hasFailure "exactly one same-Zone azure-relay-listen and one azure-relay-send" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.relay-send.spec.audience =
          lib.mkForce "azure-relay-listen";
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-rejects-missing-required-credential" = {
    expr = hasFailure "controlCredentialRef is required" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.runtime-azure-container-apps.spec.config =
          lib.mkForce {
            gatewayExecutionRef = "Guest/gateway";
            controlCredentialRef = null;
            pullCredentialRef = "Credential/aca-pull";
            networkRef = "Network/control-network";
          };
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-rejects-runtime-credential-with-wrong-provider" = {
    expr = hasFailure "ARM credential must use a supported Azure credential Provider" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.vm-arm.spec.providerRef =
          lib.mkForce "Provider/transport-azure-relay";
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-requires-acquire-token-for-runtime-credential" = {
    expr = hasFailure "credentials must use a supported Azure credential Provider" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.aca-control.spec.allowedOperations =
          lib.mkForce [ "refresh-token" ];
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-requires-relay-credential-consumer" = {
    expr = hasFailure "Relay consumerRef" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.relay-send.spec.consumerRef =
          lib.mkForce "Provider/runtime-azure-container-apps";
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-accepts-vsock-settings" = {
    expr = hasFailure "Provider/transport-vsock" [
      contractBase
    ];
    expected = false;
  };

  "provider-runtime-contracts-rejects-vsock-raw-cid" = {
    expr = hasFailure "allocator-owned fields" [
      contractBase
      ({ ... }: {
        d2b.zones.child.resources.child-vsock-link.spec.transportSettings.cid =
          lib.mkForce 42;
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-rejects-vsock-credentials" = {
    expr = hasFailure "must be empty for Provider/transport-vsock" [
      contractBase
      ({ ... }: {
        d2b.zones.child.resources.child-vsock-link.spec.transportCredentials =
          lib.mkForce [ "Credential/relay-listen" ];
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-rejects-vsock-timeout" = {
    expr = hasFailure "connectTimeoutSeconds must be between 1 and 60" [
      contractBase
      ({ ... }: {
        d2b.zones.child.resources.child-vsock-link.spec.transportSettings.connectTimeoutSeconds =
          lib.mkForce 61;
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-rejects-provider-config-secret-material" = {
    expr = hasFailure "Provider config must not contain credential material" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.transport-azure-relay.spec.config =
          lib.mkForce {
            executionRef = "Guest/gateway";
            networkRef = "SharedAccessSignature sr=canary";
          };
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-rejects-guest-settings-secret-material" = {
    expr = hasFailure "spec.provider.settings must not contain credential material" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.gateway.spec.provider.settings =
          lib.mkForce {
            configuredImageId = "SharedAccessSignature sr=canary";
          };
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-rejects-transport-settings-secret-value" = {
    expr = hasFailure "transportSettings must not contain credential or locator fields" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.relay-link.spec.transportSettings.relayEntityId =
          lib.mkForce "SharedAccessSignature sr=canary";
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-rejects-provider-config-locator" = {
    expr = hasFailure "Provider config must not contain raw host locators or argv" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.transport-azure-relay.spec.config =
          lib.mkForce {
            executionRef = "Guest/gateway";
            networkRef = "Network/control-network";
            socketPath = "/run/transport.sock";
          };
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-rejects-guest-settings-locator" = {
    expr = hasFailure "spec.provider.settings must not contain raw host locators or argv" [
      contractBase
      ({ ... }: {
        d2b.zones.local-root.resources.gateway.spec.provider.settings =
          lib.mkForce {
            argv = [ "/bin/sh" ];
          };
      })
    ];
    expected = true;
  };

  "provider-runtime-contracts-accepts-matching-activation-artifact-catalog-digest" = {
    expr = lib.filter (assertion: !assertion.assertion)
      (mkEvalContracts [
        contractBase
        ({ ... }: {
          d2b._artifactCatalogV3 = {
            catalogDigest =
              "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
          };
          d2b._bundle = {
            zoneResourceBundles = {
              "local-root" = {
                path = pkgs.writeText "matching-resource-bundle" (builtins.toJSON {
                  artifactCatalogDigest =
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                });
              };
            };
          };
        })
      ]).config.assertions;
    expected = [ ];
  };

  "provider-runtime-contracts-rejects-activation-artifact-catalog-digest-mismatch" = {
    expr =
      let
        failures = lib.filter (assertion: !assertion.assertion)
          (mkEvalContracts [
            contractBase
            ({ ... }: {
              d2b._artifactCatalogV3 = {
                catalogDigest =
                  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
              };
              d2b._bundle = {
                zoneResourceBundles = {
                  "local-root" = {
                    path = pkgs.writeText "mismatched-resource-bundle"
                      (builtins.toJSON {
                        artifactCatalogDigest =
                          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
                      });
                  };
                };
              };
            })
          ]).config.assertions;
      in
      lib.any
        (assertion:
          lib.hasInfix "activation-time artifactCatalogDigest" assertion.message
          && lib.hasInfix "canonical activation bundle" assertion.message)
        failures;
    expected = true;
  };
}
