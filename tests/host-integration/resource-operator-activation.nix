# Type-G runNixOSTest: authenticated Resource operator and framework census.
#
# This fixture is intentionally separate from the native controller canaries:
# it reaches the installed d2b CLI, public socket, systemd restart boundary,
# and the framework-declared daemon unit surface in a real NixOS guest. The
# census does not sweep every d2b-prefixed unit on an operator host, because
# optional or managed infrastructure is outside this fixture's ownership.
{ pkgs, self }:

let
  inherit (pkgs) lib;
  d2bLib = import ./lib.nix {
    inherit self;
    inherit lib;
  };
  providerArtifact = d2bLib.mkAcceptanceProviderArtifact pkgs;
  acceptancePublisherKey = providerArtifact.trustedPublisher.signingKey;
  artifacts = {
    acceptance-provider = {
      inherit (providerArtifact) package type catalog;
    };
  };
  hostRuntime = pkgs.writeText "d2b-acceptance-host-runtime.json" (builtins.toJSON {
    schemaVersion = "v1";
    bundleVersion = 1;
    generatedAt = "1970-01-01T00:00:00.000Z";
    nftAppliedHash = null;
    ifnames = [ ];
  });
in
pkgs.testers.runNixOSTest {
  name = "d2b-resource-operator-activation";

  nodes.machine = d2bLib.d2bDaemonNode {
      extra = { ... }: {
        networking.nftables.enable = true;
        networking.nftables.ruleset = lib.mkAfter ''
          table inet d2b {}
        '';
        systemd.tmpfiles.rules = [
          "d /etc/NetworkManager/conf.d 0755 root root -"
        ];
        environment.etc."d2b/acceptance-host-runtime.json".source = hostRuntime;
        d2b.site.adminUsers = [ "alice" ];
        systemd.services.d2bd.serviceConfig.ExecStartPre = lib.mkAfter [
          "+${pkgs.writeShellScript "d2b-acceptance-hosts-prep" ''
            if [ -L /etc/hosts ]; then
              ${pkgs.coreutils}/bin/cat /etc/hosts > /run/d2b-acceptance-hosts
              ${pkgs.coreutils}/bin/rm -f /etc/hosts
              ${pkgs.coreutils}/bin/install -o root -g root -m 0644 \
                /run/d2b-acceptance-hosts /etc/hosts
            fi
          ''}"
          "+${pkgs.writeShellScript "d2b-acceptance-host-runtime-prep" ''
            ${pkgs.coreutils}/bin/install -D -o root -g d2bd -m 0640 \
              /etc/d2b/acceptance-host-runtime.json \
              /var/lib/d2b/runtime/host-runtime.json
          ''}"
        ];
        users.users.bob = {
          isNormalUser = true;
          uid = 1001;
        };
        d2b.artifacts = artifacts;
        d2b.zones.local-root.trustedPublishers.d2b-u20-acceptance.signingKey =
          acceptancePublisherKey;
      d2b.zones.work.parentZone = "local-root";
      d2b.zones.work.trustedPublishers.d2b-u20-acceptance.signingKey =
        acceptancePublisherKey;
      d2b.zones.work.resources = {
        alice = {
          type = "User";
          spec = {
            displayName = "Alice";
            groups = [ ];
            osUsername = "alice";
          };
        };
        d2bd = {
          type = "User";
          spec = {
            displayName = "d2bd";
            groups = [ ];
            osUsername = "d2bd";
          };
        };
        operator-reader = {
          type = "Role";
          spec.rules = [
            {
              resourceTypes = [
                "Host"
                "Process"
                "Provider"
                "User"
              ];
              verbs = [ "get" "list" ];
              subresources = [ ];
              resourceNames = [ ];
              zones = [ "work" ];
              executionRefs = [ ];
              sessionVerbs = [ "connect" "invoke" ];
            }
          ];
        };
        operator-reader-binding = {
          type = "RoleBinding";
          spec = {
            roleRef = "Role/operator-reader";
            subjects = [ "User/alice" ];
            externalPrincipalSelector = null;
            scopeNarrowing = null;
          };
        };
        host-system = {
            type = "Host";
            spec = {
              providerRef = "Provider/system-core";
              defaultDomain = "system";
              allowedDomains = [ "system" ];
            budget = { };
            networkAttachments = [ ];
            deviceAttachments = [ ];
            volumeAttachmentDefaults = [ ];
          };
        };
          network-local = {
            type = "Provider";
            spec = {
              artifactId = "acceptance-provider";
              config.controllerExecutionRef = "Host/host-system";
            };
          };
        };
        environment.systemPackages = [ pkgs.jq ];
      };
  };

  testScript = ''
    start_all()
    machine.wait_for_unit("nftables.service", timeout=180)
    machine.succeed("nft list table inet d2b")
    machine.wait_for_unit("d2b-broker.socket", timeout=30)
    machine.wait_for_unit("d2bd.service", timeout=180)
    machine.wait_for_file("/run/d2b/public.sock", timeout=30)
    machine.succeed("runuser -u alice -- d2b auth status --json >/run/d2b-auth-before.json")

    machine.wait_until_succeeds(
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Host >/run/d2b-host-before.json && "
        "jq -e '.resources[] | select(.type == \"Host\" and "
        ".metadata.name == \"host-system\") | "
        "(.status.phase == \"Ready\" and "
        ".status.observedGeneration == .metadata.generation)' "
        "/run/d2b-host-before.json",
        timeout=60,
    )
    machine.succeed(
          "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
          "d2b --zone work --json list User "
          ">/run/d2b-user-before.json && "
          "jq -e '.resources[] | select(.type == \"User\" and "
          ".metadata.name == \"alice\") | "
          "(.status.phase == \"Ready\" and "
          ".status.observedGeneration == .metadata.generation)' "
          "/run/d2b-user-before.json"
    )
    machine.succeed(
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Provider "
        ">/run/d2b-provider-before.json && "
        "jq -e '.resources[] | select(.type == \"Provider\" and "
        ".metadata.name == \"network-local\") | "
        "(.metadata.uid != null and .metadata.generation > 0)' "
        "/run/d2b-provider-before.json"
    )
    machine.wait_until_succeeds(
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Process "
        ">/run/d2b-process-before.json && "
        "jq -e '.resources[] | select(.type == \"Process\" and "
        ".metadata.ownerRef == \"Provider/network-local\") | "
        "(.status.phase == \"Ready\" and "
        ".status.observedGeneration == .metadata.generation)' "
        "/run/d2b-process-before.json",
        timeout=60,
    )
    machine.fail(
        "runuser -u bob -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Process "
        ">/run/d2b-unauthorized-resource.log 2>&1"
    )

    machine.succeed("systemctl restart d2bd.service")
    machine.wait_for_unit("d2bd.service", timeout=180)
    machine.wait_for_file("/run/d2b/public.sock", timeout=30)
    machine.wait_until_succeeds(
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Process "
        ">/run/d2b-process-after.json && "
        "jq -e '.resources[] | select(.type == \"Process\" and "
        ".metadata.ownerRef == \"Provider/network-local\") | "
        "(.status.phase == \"Ready\" and .status.observedGeneration == "
        ".metadata.generation and .status.resource.adopted == true)' "
        "/run/d2b-process-after.json",
        timeout=60,
    )
    machine.succeed("runuser -u alice -- d2b auth status --json >/run/d2b-auth-after.json")
    machine.succeed(
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Host "
        ">/run/d2b-host-after.json && "
        "jq -e --slurpfile before /run/d2b-host-before.json "
        "'.resources[] | select(.type == \"Host\" and "
        ".metadata.name == \"host-system\") as $after | "
        "($before[0].resources[] | select(.type == \"Host\" and "
        ".metadata.name == \"host-system\")) as $old | "
        "($after.metadata.uid == $old.metadata.uid and "
        "$after.metadata.generation == $old.metadata.generation and "
        "$after.metadata.revision >= $old.metadata.revision and "
        "$after.status.phase == \"Ready\")' /run/d2b-host-after.json"
    )

    declared = set(
        machine.succeed("cat /etc/d2b/daemon-acceptance-units").split()
    )
    required = {
        "d2bd.service",
        "d2b-broker.socket",
        "d2b-broker.service",
    }
    assert declared == required, (
        f"unexpected framework acceptance census: {declared}"
    )
    unit_names = set(
        machine.succeed(
            "systemctl list-units --no-pager --all --plain "
            "| awk '{print $1}' | sort"
        ).split()
    )
    assert required <= unit_names, (
        f"framework daemon units missing: {required - unit_names}"
    )

    # Provider packages are code loaded by d2bd, never framework-declared
    # persistent services. Optional or managed host units are outside this
    # fixture's census.
    provider_units = sorted(
        unit
        for unit in declared
        if "provider" in unit and (unit.endswith(".service") or unit.endswith(".socket"))
    )
    assert not provider_units, f"Provider-owned persistent units found: {provider_units}"
  '';
}
