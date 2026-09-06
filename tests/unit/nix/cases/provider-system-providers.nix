# Focused Provider option and carrier contracts for the system Provider family.
{ lib, pkgs, ... }:

let
  modules = [
    ({ ... }: {
      options.assertions = lib.mkOption {
        type = lib.types.listOf lib.types.anything;
        default = [ ];
      };
    })
    ../../../../nixos-modules/host-generation-rebuild-ref.nix
    ../../../../packages/d2b-provider-activation-nixos/nix/default.nix
    ../../../../nixos-modules/providers/system-minijail.nix
    ../../../../nixos-modules/providers/system-systemd.nix
    ../../../../packages/d2b-provider-audio-pipewire/nix/default.nix
  ];
  eval = extra:
    lib.evalModules {
      modules = modules ++ extra;
      specialArgs = { inherit pkgs; };
    };
  valid = eval [
    {
      d2b.site.hostGenerationRebuildRef = "github:example/d2b#system";
      d2b.providers.activationNixos.retainedGenerations = 4;
      d2b.providers.systemSystemd.maxConcurrentLaunches = 128;
      d2b.audio.v3 = {
        enable = true;
        captureAlias = "default";
      };
    }
  ];
  invalid = eval [
    {
      d2b.site.hostGenerationRebuildRef = "contains whitespace #bad";
    }
  ];
  failedAssertions = lib.filter (assertion: !assertion.assertion) invalid.config.assertions;
in
{
  "provider-system/defaults-and-bounds" = {
    expr = {
      activation = builtins.removeAttrs valid.config.d2b._activationNixos [
        "mkProviderResource"
        "mkNixosGenerationResource"
      ];
      generation = valid.config.d2b._activationNixos.mkNixosGenerationResource {
        name = "dev-vm-gen-7";
        executionRef = "Guest/dev-vm";
        systemArtifactId = "dev-vm-system";
      };
      metadataBoundary = {
        managedBy = builtins.hasAttr "managedBy"
          (valid.config.d2b._activationNixos.mkNixosGenerationResource {
            name = "dev-vm-gen-7";
            executionRef = "Guest/dev-vm";
            systemArtifactId = "dev-vm-system";
          });
        configurationGeneration = builtins.hasAttr "configurationGeneration"
          (valid.config.d2b._activationNixos.mkNixosGenerationResource {
            name = "dev-vm-gen-7";
            executionRef = "Guest/dev-vm";
            systemArtifactId = "dev-vm-system";
          });
      };
      minijail = valid.config.d2b._systemMinijail;
      systemd = valid.config.d2b._systemSystemd.config;
      audio = builtins.removeAttrs valid.config.d2b._audioV3 [
        "mkServiceResource"
        "mkBindingResource"
      ];
      service = valid.config.d2b._audioV3.mkServiceResource {
        name = "host-audio";
        endpointRefs = [ "Endpoint/audio-authority" ];
      };
      carrier = builtins.readFile valid.config.d2b._hostGenerationRebuildRef.carrier;
    };
    expected = {
      activation = {
        providerRef = "Provider/activation-nixos";
        retainedGenerations = 4;
        resourceType = "activation-nixos.d2bus.org.NixosGeneration";
        stateVolume = null;
      };
      generation = {
        name = "dev-vm-gen-7";
        type = "activation-nixos.d2bus.org.NixosGeneration";
        spec = {
          providerRef = "Provider/activation-nixos";
          executionRef = "Guest/dev-vm";
          systemArtifactId = "dev-vm-system";
          activationMode = "switch";
        };
      };
      metadataBoundary = {
        managedBy = false;
        configurationGeneration = false;
      };
      minijail = {
        providerRef = "Provider/system-minijail";
        resourceTypes = [ "Process" "EphemeralProcess" ];
        minimumKernel = "5.14";
        declaresStateVolume = false;
        persistentRootUnit = null;
      };
      systemd = {
        launchTimeoutSec = 30;
        terminationGraceSec = 30;
        userManagerCheckTimeout = 5;
        maxConcurrentLaunches = 128;
      };
      audio = {
        enabled = true;
        providerRef = "Provider/audio-pipewire";
        serviceType = "audio.d2bus.org.AudioService";
        bindingType = "audio.d2bus.org.AudioBinding";
        microphone = "exclusive";
        speaker = "multiplexed";
        captureAlias = "default";
        declaresStateVolume = false;
      };
      service = {
        name = "host-audio";
        type = "audio.d2bus.org.AudioService";
        spec = {
          providerRef = "Provider/audio-pipewire";
          serviceRole = "owner";
          implementationEndpointRefs = [ "Endpoint/audio-authority" ];
          operations = [ "playback" "capture" ];
        };
      };
      carrier = "github:example/d2b#system";
    };
  };

  "provider-system/rejects-invalid-carrier" = {
    expr = {
      count = builtins.length failedAssertions;
      message = (builtins.head failedAssertions).message;
    };
    expected = {
      count = 1;
      message = "d2b.site.hostGenerationRebuildRef must be one bounded single-line reference with a selector.";
    };
  };
}
