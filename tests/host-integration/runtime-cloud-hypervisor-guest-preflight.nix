# Type-G runNixOSTest: Zone-native Cloud Hypervisor Guest acceptance.
#
# This is the public host selector for the controller-owned Guest lifecycle.
# It requires the nested KVM posture and fails closed when the host cannot
# provide it; an environment block is not acceptance evidence.
{ pkgs, self }:

let
  inherit (pkgs) lib;
  d2bLib = import ./lib.nix {
    inherit self;
    inherit lib;
  };
  cloudHypervisorArtifact =
    d2bLib.mkRuntimeCloudHypervisorArtifact pkgs;
  volumeProviderArtifact = d2bLib.mkVolumeProviderArtifact pkgs;
  fixtureKeys = pkgs.runCommand "acceptance-component-session-keys" { } ''
    mkdir -p "$out"
    printf '\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037\040' > "$out/host.key"
    printf '\007\243\174\274\024\040\223\310\267\125\334\033\020\350\154\264\046\067\112\321\152\250\123\355\013\337\300\262\270\155\034\174' > "$out/host.pub"
    printf '\041\042\043\044\045\046\047\050\051\052\053\054\055\056\057\060\061\062\063\064\065\066\067\070\071\072\073\074\075\076\077\100' > "$out/guest.key"
    printf '\130\151\257\364\120\124\227\062\313\252\355\136\135\371\263\012\155\243\034\260\345\164\053\255\132\324\241\247\150\361\246\173' > "$out/guest.pub"
  '';
  guestBundle = pkgs.runCommand "acceptance-guest-bundle" {
    nativeBuildInputs = [ pkgs.python3 ];
  } ''
    mkdir -p "$out"
    cat > "$out/host.json" <<'EOF'
    {"schemaVersion":"v2","site":{"allowUnsafeEastWest":false},"environments":[],"nftables":{"family":"inet","table":"d2b","chains":[],"tableHashAfterApply":null,"ownershipId":"host-integration"},"networkManager":{"filePath":"/etc/NetworkManager/conf.d/00-d2b-unmanaged.conf","matchCriteria":[],"reloadBehavior":"atomic-reload","ownership":{"owner":"root","group":"root","mode":"0644","driftPolicy":"replace"}},"hostsFile":{"startMarker":"# d2b-managed begin","endMarker":"# d2b-managed end","rule":"replace-managed-block"},"kernelModules":[],"fdOwnership":[],"cloudHypervisorCapabilities":[],"ifNameMappings":[],"ch":null,"firewallCoexistencePolicy":null}
    EOF
    printf '%s\n' '{"schemaVersion":"v2","vms":[]}' > "$out/processes.json"
    printf '%s\n' '{"schemaVersion":"v2","publicOperations":[],"brokerOperations":[]}' > "$out/privileges.json"
    printf '%s\n' '{"_manifest":{"manifestVersion":6},"_observability":{"enabled":false,"signozUrl":"http://127.0.0.1:8080","signozOtlpGrpcPort":4317,"signozOtlpHttpPort":4318,"obsVsockCid":0,"obsVsockHostSocket":"","vmName":""}}' > "$out/vms.json"
    python3 - "$out/bundle.json" <<'PY'
    import hashlib
    import json
    import sys

    bundle = {
        "artifactHashes": None,
        "bundleVersion": 4,
        "closures": [],
        "generation": {
            "generatedAt": None,
            "generator": "host-integration",
            "sourceRevision": None,
        },
        "hostPath": "host.json",
        "managedKeys": {
            "keysDir": "/var/lib/d2b/keys",
            "knownHostsPath": "/var/lib/d2b/known_hosts.d2b",
            "overrides": [],
        },
        "minijailProfiles": [],
        "privilegesPath": "privileges.json",
        "processesPath": "processes.json",
        "publicManifestPath": "vms.json",
        "schemaVersion": "v2",
    }
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
    bundle["bundleHash"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    with open(sys.argv[1], "w", encoding="utf-8") as output:
        json.dump(bundle, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    PY
  '';

  cloudHypervisorConfig = {
    controllerExecutionRef = "Host/host-system";
    defaultVcpus = 2;
    defaultMemoryMb = 512;
    defaultMachineType = "microvm";
    watchdog = true;
    adoptionWindowMs = 30000;
    healthCheckIntervalMs = 5000;
    healthCheckTimeoutMs = 1000;
    healthCheckFailureThreshold = 3;
    startupDeadlineMs = 120000;
  };
  guestSystem = d2bLib.mkGuestSystem {
    inherit pkgs;
    name = "acceptance-guest";
    modules = [
      ({ lib, ... }: {
        boot.kernelParams = [ "console=ttyS0" "loglevel=7" ];
        environment.etc."d2b/component-session/guest.key".source =
          "${fixtureKeys}/guest.key";
        environment.etc."d2b/component-session/parent.pub".source =
          "${fixtureKeys}/host.pub";
        systemd.services.d2bd-guest = {
          environment = {
            RUST_LOG = "d2bd=debug";
          };
          serviceConfig = {
            ReadOnlyPaths = [
              "/etc/d2b/component-session/guest.key"
              "/etc/d2b/component-session/parent.pub"
            ];
            StandardOutput = lib.mkForce "journal+console";
            StandardError = lib.mkForce "journal+console";
          };
        };
        systemd.services.d2b-test-boot-identity = {
          wantedBy = [ "basic.target" ];
          before = [ "d2bd-guest.service" ];
          serviceConfig.Type = "oneshot";
          script = ''
            printf 'D2B_GUEST_BOOT_ID=%s\n' \
              "$(${pkgs.coreutils}/bin/cat /proc/sys/kernel/random/boot_id)" \
              > /dev/console
          '';
        };
        d2b.componentSession.localPrivateKeyPath =
          "/etc/d2b/component-session/guest.key";
        d2b.componentSession.parentPublicKeyPath =
          "/etc/d2b/component-session/parent.pub";
        d2b.componentSession.bundlePath =
          "/var/lib/d2b/guest-bundle/bundle.json";
        d2b.guestBroker.bundlePath =
          "/var/lib/d2b/guest-bundle/bundle.json";
        systemd.services.d2b-install-guest-bundle = {
          requiredBy = [ "d2b-broker-guest.service" "d2bd-guest.service" ];
          before = [ "d2b-broker-guest.service" "d2bd-guest.service" ];
          serviceConfig.Type = "oneshot";
          script = ''
            install -d -o root -g d2bd -m 0750 /var/lib/d2b/guest-bundle
            for file in bundle.json host.json processes.json privileges.json; do
              install -o root -g d2bd -m 0640 \
                ${guestBundle}/"$file" /var/lib/d2b/guest-bundle/"$file"
            done
            install -o root -g d2bd -m 0644 \
              ${guestBundle}/vms.json /var/lib/d2b/guest-bundle/vms.json
          '';
        };
        networking.useDHCP = lib.mkForce false;
        networking.networkmanager.enable = lib.mkForce false;
        systemd.network.enable = lib.mkForce false;
        services.dbus.enable = lib.mkForce false;
        services.resolved.enable = lib.mkForce false;
        systemd.services.systemd-vconsole-setup.enable = false;
        microvm.storeOnDisk = true;
        microvm.storeDisk = guestStoreDisk;
        microvm.shares = lib.mkForce [ ];
        fileSystems."/nix/store" = {
          device = "/dev/vda";
          fsType = "ext4";
          options = [ "ro" "x-initrd.mount" ];
          neededForBoot = true;
        };
      })
    ];
  };
  guestClosure = pkgs.closureInfo {
    rootPaths = [ guestSystem.config.system.build.toplevel ];
  };
  guestStoreDisk = pkgs.runCommand "acceptance-guest-store.img" {
    nativeBuildInputs = [ pkgs.coreutils pkgs.e2fsprogs ];
  } ''
    mkdir -p root
    while IFS= read -r path; do
      cp -r --no-preserve=ownership,xattr,context "$path" root/
    done < ${guestClosure}/store-paths
    truncate -s 4096M "$out"
    mkfs.ext4 -q -F -d root "$out"
  '';
  artifacts = {
    runtime-cloud-hypervisor = {
      inherit (cloudHypervisorArtifact) package type catalog;
    };
    volume-acceptance-provider = {
      inherit (volumeProviderArtifact) package type catalog;
    };
    acceptance-system = {
      package = guestSystem.config.system.build.toplevel;
      type = "nixos-system";
    };
  };
in
pkgs.testers.runNixOSTest {
  name = "d2b-runtime-cloud-hypervisor-guest-preflight";

  nodes.machine = d2bLib.d2bCloudHypervisorNode {
    extra = { ... }: {
      d2b.site.adminUsers = [ "alice" ];
      environment.systemPackages = with pkgs; [
        iproute2
        jq
        iputils
        procps
      ];
      d2b.artifacts = artifacts;
      d2b.guestSystems.work.acceptance-guest = guestSystem;
      d2b.zones.local-root.trustedPublishers.d2b-cloud-hypervisor.signingKey =
        cloudHypervisorArtifact.trustedPublisher.signingKey;
      d2b.zones.local-root.trustedPublishers.d2b-volume-acceptance.signingKey =
        volumeProviderArtifact.trustedPublisher.signingKey;
      d2b.zones.work.trustedPublishers.d2b-cloud-hypervisor.signingKey =
        cloudHypervisorArtifact.trustedPublisher.signingKey;
      d2b.zones.work.trustedPublishers.d2b-volume-acceptance.signingKey =
        volumeProviderArtifact.trustedPublisher.signingKey;
      d2b.zones.local-root.resources.host-system = {
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
      d2b.zones.work = {
        parentZone = "local-root";
        resources = {
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
          lifecycle-operator = {
            type = "Role";
            spec.rules = [
              {
                resourceTypes = [ "Endpoint" "Guest" "Host" "Process" "Provider" "Volume" ];
                verbs = [ "get" "list" ];
                subresources = [ ];
                resourceNames = [ ];
                zones = [ "work" ];
                executionRefs = [ ];
                sessionVerbs = [ "connect" "invoke" ];
              }
              {
                resourceTypes = [ "Guest" ];
                verbs = [ "delete" ];
                subresources = [ ];
                resourceNames = [ "acceptance-guest" ];
                zones = [ "work" ];
                executionRefs = [ ];
                sessionVerbs = [ "connect" "invoke" ];
              }
            ];
          };
          lifecycle-operator-binding = {
            type = "RoleBinding";
            spec = {
              roleRef = "Role/lifecycle-operator";
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
          volume-local = {
            type = "Provider";
            spec = {
              artifactId = "volume-acceptance-provider";
              config = {
                controllerExecutionRef = "Host/host-system";
                sourcePolicies = [
                  {
                    id = "default-state";
                    class = "local-path";
                    volumeKinds = [ "durable" "state" "cache" ];
                  }
                ];
              };
            };
          };
          volume-virtiofs = {
            type = "Provider";
            spec = {
              artifactId = "volume-acceptance-provider";
              config.controllerExecutionRef = "Host/host-system";
            };
          };
          runtime-cloud-hypervisor = {
            type = "Provider";
            spec = {
              artifactId = "runtime-cloud-hypervisor";
              config = cloudHypervisorConfig;
            };
          };
          acceptance-guest = {
            type = "Guest";
            spec = {
              providerRef = "Provider/runtime-cloud-hypervisor";
              executionRef = "Host/host-system";
              systemArtifactId = "acceptance-system";
              defaultDomain = "system";
              allowedDomains = [ "system" ];
              budget = { };
              volumeAttachmentDefaults = [ ];
              networkAttachments = [ ];
              deviceAttachments = [ ];
            };
          };
        };
      };
    };
  };

  testScript = ''
    start_all()
    machine.wait_for_unit("d2bd.service", timeout=180)
    machine.wait_for_unit("d2b-broker.socket", timeout=30)
    machine.wait_for_file("/run/d2b/public.sock", timeout=30)
    machine.succeed("systemctl start d2b-broker.service")
    machine.wait_for_unit("d2b-broker.service", timeout=30)

    # Capture only the public, redacted Resource projection before waiting on
    # the nested VMM. This keeps a missing API socket diagnostic without
    # waiting for unrelated fixture controller sessions.
    machine.succeed(
        "set -o pipefail; "
        ": > /run/d2b-preflight-summary.log; "
        "for resource_type in Guest Process Endpoint Volume Provider; do "
        "printf '%s: ' \"$resource_type\" >> /run/d2b-preflight-summary.log; "
        "timeout 5s runuser -u alice -- env "
        "D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list \"$resource_type\" "
        "2>/dev/null | "
        "jq -c '[.resources[] | "
        "{type: .type, "
        "metadata: {name: .metadata.name, uid: .metadata.uid, "
        "generation: .metadata.generation, ownerRef: .metadata.ownerRef, "
        "zone: .metadata.zone}, "
        "spec: {providerRef: .spec.providerRef, "
        "executionRef: .spec.executionRef, "
        "processClass: .spec.processClass, template: .spec.template}, "
        "status: {phase: .status.phase, "
        "observedGeneration: .status.observedGeneration, "
        "conditions: [.status.conditions[]? | "
        "{type: .type, status: .status, reason: .reason}], "
        "outcome: (.status.outcome | "
        "if . == null then null else "
        "{code: .code, retryable: .retryable} end), "
        "resource: .status.resource}}]' "
        ">> /run/d2b-preflight-summary.log 2>/dev/null || "
        "printf 'unavailable\\n' >> /run/d2b-preflight-summary.log; "
        "done; "
        "session_errors=$(journalctl -u d2bd.service --no-pager -b "
        "2>/dev/null | grep -Ec "
        "'session-authentication-failed|session-generation-stale' || true); "
        "printf 'ComponentSession terminal error count: %s\\n' \"$session_errors\" "
        ">> /run/d2b-preflight-summary.log; "
        "cat /run/d2b-preflight-summary.log >&2"
    )

    # The VMM API socket is the first nested-VM proof. Its 30-second bound is
    # deliberately shorter than Guest boot/readiness, which has its own
    # bounded checks below, so a missing socket cannot consume 900 seconds.
    machine.succeed(
        "for attempt in $(seq 1 30); do "
        "test -S /var/lib/d2b/zones/work/guests/acceptance-guest/acceptance-guest.sock "
        "&& exit 0; "
        "sleep 1; "
        "done; "
        "echo 'Cloud Hypervisor API socket did not become ready within 30s' >&2; "
        "cat /run/d2b-preflight-summary.log >&2; "
        "exit 1"
    )
    machine.wait_until_succeeds(
        "journalctl --no-pager -b "
        "| grep -q 'D2B_GUEST_BOOT_ID='",
        timeout=30,
    )
    machine.sleep(5)
    machine.succeed(
        "guest_uid=$(runuser -u alice -- env "
        "D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Guest | "
        "jq -er '.resources[] | select(.metadata.name == \"acceptance-guest\") "
        "| .metadata.uid') && "
        "boot_id=$(journalctl --no-pager -b "
        "| sed -n 's/.*D2B_GUEST_BOOT_ID=\\([0-9a-f-]*\\).*/\\1/p' "
        "| tail -1) && "
        "boot_digest=$(printf 'd2b-kernel-boot-id-v1\\0%s' \"$boot_id\" "
        "| sha256sum | cut -d' ' -f1) && "
        "install -d -o d2bd -g d2bd -m 0700 "
        "/var/lib/d2b/zones/work/guests/acceptance-guest/component-session && "
        "install -o d2bd -g d2bd -m 0600 ${fixtureKeys}/host.key "
        "/var/lib/d2b/zones/work/guests/acceptance-guest/component-session/host.key && "
        "install -o d2bd -g d2bd -m 0600 ${fixtureKeys}/guest.pub "
        "/var/lib/d2b/zones/work/guests/acceptance-guest/component-session/guest.pub && "
        "cat > /var/lib/d2b/zones/work/guests/acceptance-guest/component-session/guest.json <<EOF\n"
        "{\"guestRef\":\"Guest/acceptance-guest\","
        "\"guestUid\":\"$guest_uid\","
        "\"zone\":\"work\","
        "\"bootIdentityDigest\":\"sha256:$boot_digest\","
        "\"purpose\":\"zone-link\","
        "\"schemaFingerprint\":\"sha256:65e20cc53efdd2354931c5cf2ad722612dd9bc4e26e0b238b9048f244db6c737\","
        "\"reconnectGeneration\":1,"
        "\"providerGeneration\":1,"
        "\"controllerGeneration\":1,"
        "\"assignmentEpoch\":1}\n"
        "EOF\n"
        "chown d2bd:d2bd "
        "/var/lib/d2b/zones/work/guests/acceptance-guest/component-session/guest.json && "
        "chmod 0600 "
        "/var/lib/d2b/zones/work/guests/acceptance-guest/component-session/guest.json"
    )
    machine.succeed(
        "test -e /dev/kvm && test -r /dev/kvm && test -w /dev/kvm || "
        "{ echo 'required KVM capability unavailable: /dev/kvm' >&2; exit 1; }"
    )
    machine.succeed(
        "test -e /dev/vhost-net && test -r /dev/vhost-net && test -w /dev/vhost-net || "
        "{ echo 'required Cloud Hypervisor vhost capability unavailable: /dev/vhost-net' >&2; exit 1; }"
    )
    machine.succeed(
        "test -r /sys/fs/cgroup/cgroup.controllers || "
        "{ echo 'required cgroup v2 capability unavailable' >&2; exit 1; }"
    )
    machine.succeed(
        "for controller in cpu memory io pids cpuset; do "
        "grep -qw \"$controller\" /sys/fs/cgroup/cgroup.controllers || "
        "{ echo \"required cgroup controller unavailable: $controller\" >&2; exit 1; }; "
        "done"
    )
    machine.succeed(
        "test -d /sys/fs/cgroup/d2b.slice && "
        "grep -qw 'cpu' /sys/fs/cgroup/d2b.slice/cgroup.subtree_control && "
        "grep -qw 'memory' /sys/fs/cgroup/d2b.slice/cgroup.subtree_control && "
        "grep -qw 'pids' /sys/fs/cgroup/d2b.slice/cgroup.subtree_control || "
        "{ echo 'required delegated d2b.slice cgroup posture unavailable' >&2; exit 1; }"
    )
    machine.succeed(
        "! journalctl -u d2bd.service --no-pager -b 2>/dev/null "
        "| grep -F 'Bundle resolver could not load'"
    )

    machine.succeed(
        "test -r /etc/d2b/artifact-catalog.json && "
        "jq -e '"
        "(.guestSetupDescriptors | any(.[]; "
        ".zone == \"work\" and .guest == \"acceptance-guest\" and "
        ".providerArtifactId == \"runtime-cloud-hypervisor\" and "
        ".descriptor.providerRef == \"Provider/runtime-cloud-hypervisor\" and "
        ".descriptor.systemArtifactId == \"acceptance-system\" and "
        ".descriptor.childRoles == [\"vmm\", \"ch-api\", \"guest-control\", \"system\"])) and "
        "(.guestClosures | any(.[]; "
        ".zone == \"work\" and .guest == \"acceptance-guest\" and "
        ".artifactId == \"acceptance-system\" and (.closurePaths | length > 0) and "
        "(. as $guest | ($guest.closurePaths | index($guest.toplevel)) != null) and "
        ".storeView.mountPoint == \"/nix/store\" and "
        "(.storeView.root | endswith(\"/zones/work/guests/acceptance-guest/store-view\")) and "
        "(.vmm.binaryPath | endswith(\"/bin/cloud-hypervisor\"))))' "
        "/etc/d2b/artifact-catalog.json"
    )
    machine.succeed(
        "test -r /etc/d2b/closures/zones/work/acceptance-guest.json && "
        "jq -e '"
        ".schemaVersion == \"v3\" and .artifactId == \"acceptance-system\" and "
        "(.closurePaths | length > 0) and "
        "(. as $guest | ($guest.closurePaths | index($guest.toplevel)) != null) and "
        ".storeView.mountPoint == \"/nix/store\" and "
        ".storeView.sync == \"broker-store-sync\" and "
        "(.vmm.argv | index(\"--api-socket\")) != null' "
        "/etc/d2b/closures/zones/work/acceptance-guest.json"
    )
    machine.succeed(
        "jq -e '"
        ".resources | any(.[]; .type == \"Guest\" and "
        ".metadata.name == \"acceptance-guest\" and "
        ".spec.providerRef == \"Provider/runtime-cloud-hypervisor\" and "
        ".spec.systemArtifactId == \"acceptance-system\") and "
        "all(.[]; (tostring | contains(\"/nix/store/\") | not) and "
        "(tostring | contains(\"\\\"argv\\\"\") | not))' "
        "/etc/d2b/zones/work/resource-bundle.json"
    )

    machine.succeed(
        "for attempt in $(seq 1 45); do "
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Guest >/run/d2b-guest-ready.json && "
        "jq -e '"
        "(.resources | map(select(.type == \"Guest\" and "
        ".metadata.name == \"acceptance-guest\"))) as $guests | "
        "($guests | length) == 1 and "
        "$guests[0].status.phase == \"Ready\" and "
        "$guests[0].status.observedGeneration == $guests[0].metadata.generation and "
        "$guests[0].status.resource.runtimeReady == true and "
        "$guests[0].status.resource.bootstrapReady == true and "
        "$guests[0].status.resource.activeProcessCount == 1' "
        "/run/d2b-guest-ready.json && exit 0; "
        "if jq -e 'any(.resources[]; "
        ".metadata.name == \"acceptance-guest\" and "
        ".status.phase == \"Failed\")' "
        "/run/d2b-guest-ready.json >/dev/null; then "
        "echo 'Guest reported a terminal failure' >&2; exit 1; fi; "
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Process >/run/d2b-vmm-fast-fail.json && "
        "if jq -e 'any(.resources[]; "
        ".metadata.name == \"acceptance-guest-vmm\" and "
        ".status.phase == \"Failed\" and "
        ".status.outcome.retryable != true)' "
        "/run/d2b-vmm-fast-fail.json >/dev/null; then "
        "echo 'VMM Process reported a terminal failure' >&2; exit 1; fi; "
        "if journalctl -u d2bd.service --no-pager -b "
        "| grep -q 'session-authentication-failed\\|session-generation-stale'; then "
        "echo 'ComponentSession reported a terminal failure' >&2; exit 1; fi; "
        "sleep 1; done; "
        "echo 'Guest readiness failed:' >&2; "
        "jq -c '.resources[] | select(.type == \"Guest\" and "
        ".metadata.name == \"acceptance-guest\") | "
        "{name: .metadata.name, uid: .metadata.uid, "
        "owner: .metadata.ownerRef, phase: .status.phase, "
        "observedGeneration: .status.observedGeneration, "
        "conditions: [.status.conditions[]? | "
        "{type: .type, status: .status, reason: .reason}], "
        "outcome: (.status.outcome | "
        "if . == null then null else "
        "{code: .code, retryable: .retryable} end), "
        "resource: .status.resource}' "
        "/run/d2b-guest-ready.json >&2; "
        "echo 'Dependent Process status:' >&2; "
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Process | "
        "jq -c '.resources[] | "
        "{name: .metadata.name, uid: .metadata.uid, "
        "owner: .metadata.ownerRef, provider: .spec.providerRef, "
        "execution: .spec.executionRef, processClass: .spec.processClass, "
        "template: .spec.template, phase: .status.phase, "
        "observedGeneration: .status.observedGeneration, "
        "conditions: [.status.conditions[]? | "
        "{type: .type, status: .status, reason: .reason}], "
        "outcome: (.status.outcome | "
        "if . == null then null else "
        "{code: .code, retryable: .retryable} end), "
        "resource: .status.resource}' >&2; "
        "for resource_type in Endpoint Volume Provider; do "
        "echo \"$resource_type status:\" >&2; "
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list \"$resource_type\" | "
        "jq -c '.resources[] | {name: .metadata.name, uid: .metadata.uid, "
        "owner: .metadata.ownerRef, provider: .spec.providerRef, "
        "execution: .spec.executionRef, phase: .status.phase, "
        "observedGeneration: .status.observedGeneration, "
        "conditions: [.status.conditions[]? | "
        "{type: .type, status: .status, reason: .reason}], "
        "outcome: (.status.outcome | "
        "if . == null then null else "
        "{code: .code, retryable: .retryable} end), "
        "resource: .status.resource}' >&2; done; exit 1"
    )
    machine.wait_until_succeeds(
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Process "
        ">/run/d2b-process-ready.json && "
        "jq -e '"
        "([.resources[] | select(.type == \"Process\" and "
        ".metadata.name == \"acceptance-guest-vmm\" and "
        ".metadata.ownerRef == \"Guest/acceptance-guest\" and "
        ".spec.providerRef == \"Provider/system-minijail\" and "
        ".spec.executionRef == \"Host/host-system\" and "
        ".spec.processClass == \"worker\" and "
        ".spec.template == \"cloud-hypervisor-runner\" and "
        ".status.phase == \"Ready\")] | length == 1) and "
        "([.resources[] | select(.type == \"Process\" and "
        ".metadata.ownerRef == \"Provider/runtime-cloud-hypervisor\" and "
        ".spec.providerRef == \"Provider/system-minijail\" and "
        ".spec.executionRef == \"Host/host-system\" and "
        ".spec.processClass == \"controller\" and "
        ".spec.template == \"controller-runtime-cloud-hypervisor-cloud-hypervisor-controller\" and "
        ".status.phase == \"Ready\")] | length == 1)' "
        "/run/d2b-process-ready.json",
        timeout=30,
    )
    machine.wait_until_succeeds(
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Endpoint "
        ">/run/d2b-endpoint-ready.json && "
        "jq -e '"
        "([.resources[] | select(.type == \"Endpoint\" and "
        ".metadata.ownerRef == \"Guest/acceptance-guest\" and "
        ".status.phase == \"Ready\")] | length == 2)' "
        "/run/d2b-endpoint-ready.json",
        timeout=30,
    )
    machine.wait_until_succeeds(
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Volume "
        ">/run/d2b-volume-ready.json && "
        "jq -e '"
        "([.resources[] | select(.type == \"Volume\" and "
        ".metadata.name == \"acceptance-guest-system\" and "
        ".metadata.ownerRef == \"Guest/acceptance-guest\" and "
        ".spec.source.settings.kind == \"nix-closure\" and "
        ".spec.source.settings.sourcePolicyId == null and "
        ".spec.source.settings.systemArtifactId == \"acceptance-system\" and "
        ".status.phase == \"Ready\" and "
        ".status.observedGeneration == .metadata.generation)] | length == 1)' "
        "/run/d2b-volume-ready.json",
        timeout=180,
    )
    machine.succeed(
        "jq -e '"
        "([.resources[] | select(.type == \"Volume\" and "
        ".metadata.name == \"store-view-acceptance-guest\" and "
        ".spec.source.settings.kind == \"nix-closure\" and "
        ".spec.source.settings.sourcePolicyId == null and "
        ".spec.source.settings.systemArtifactId == \"acceptance-system\" and "
        ".status.phase == \"Ready\" and "
        ".status.observedGeneration == .metadata.generation)] | length == 1)' "
        "/run/d2b-volume-ready.json"
    )
    machine.wait_until_succeeds(
        "test -S "
        "/var/lib/d2b/zones/work/guests/acceptance-guest/acceptance-guest.sock",
        timeout=30,
    )
    machine.succeed(
        "test -S /var/lib/d2b/zones/work/guests/acceptance-guest/acceptance-guest.sock && "
        "test -L /var/lib/d2b/zones/work/guests/acceptance-guest/store-view/state/current && "
        "test -L /var/lib/d2b/zones/work/guests/acceptance-guest/store-view/meta/current && "
        "test -d /var/lib/d2b/zones/work/guests/acceptance-guest/store-view/live"
    )

    runner = machine.succeed(
        "set -- $(for proc in /proc/[0-9]*; do "
        "exe=$(readlink \"$proc/exe\" 2>/dev/null || true); "
        "case \"$exe\" in */bin/cloud-hypervisor) "
        "cmd=$(tr '\\0' ' ' < \"$proc/cmdline\"); "
        "case \"$cmd\" in *--api-socket*acceptance-guest*) "
        "pid=''${proc#/proc/}; "
        "printf '%s %s ' \"$pid\" \"$(awk '{print $22}' \"$proc/stat\")\";; "
        "esac;; esac; done); "
        "test \"$#\" -eq 2; printf '%s %s' \"$1\" \"$2\""
    ).strip()
    runner_pid, runner_start = runner.split()
    machine.succeed(f"test -d /proc/{runner_pid}")
    machine.succeed(
        f"test \"$(awk '{{print $22}}' /proc/{runner_pid}/stat)\" = {runner_start}"
    )
    machine.succeed(
        f"tr '\\0' ' ' < /proc/{runner_pid}/cmdline | "
        "grep -F -- '--api-socket' | grep -F -- 'acceptance-guest'"
    )

    machine.succeed(
        "guest_uid=$(runuser -u alice -- env "
        "D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Guest | "
        "jq -er '.resources[] | select(.type == \"Guest\" and "
        ".metadata.name == \"acceptance-guest\" and "
        ".spec.providerRef == \"Provider/runtime-cloud-hypervisor\" and "
        ".spec.executionRef == \"Host/host-system\") | .metadata.uid') && "
        "jq -c "
        "'{guestRef, guestUid, zone, reconnectGeneration, "
        "providerGeneration, controllerGeneration, assignmentEpoch}' "
        "/var/lib/d2b/zones/work/guests/acceptance-guest/component-session/guest.json "
        ">/run/d2b-guest-session-before.json && "
        "jq -e --arg guest_uid \"$guest_uid\" "
        "'.guestRef == \"Guest/acceptance-guest\" and .guestUid == $guest_uid "
        "and .zone == \"work\" and .reconnectGeneration > 0 and "
        ".providerGeneration > 0 and .controllerGeneration > 0 and "
        ".assignmentEpoch > 0' "
        "/run/d2b-guest-session-before.json >/dev/null && "
        "session_generation=$(journalctl --no-pager -b 2>/dev/null | "
        "grep -F 'Guest ComponentSession Resource API server starting' | "
        "grep -oE 'generation[[:space:]]*=[[:space:]]*[0-9]+' | "
        "grep -oE '[0-9]+' | tail -1) && "
        "test -n \"$session_generation\" && "
        "test \"$session_generation\" -ge 1 && "
        "printf '%s\\n' \"$session_generation\" "
        ">/run/d2b-guest-session-generation-before"
    )

    machine.succeed("systemctl restart d2bd.service")
    machine.wait_for_unit("d2bd.service", timeout=180)
    machine.wait_for_file("/run/d2b/public.sock", timeout=30)
    machine.wait_until_succeeds(
        "test -S "
        "/var/lib/d2b/zones/work/guests/acceptance-guest/acceptance-guest.sock",
        timeout=30,
    )
    machine.succeed(f"test -d /proc/{runner_pid}")
    machine.succeed(
        f"test \"$(awk '{{print $22}}' /proc/{runner_pid}/stat)\" = {runner_start}"
    )
    machine.succeed(
        "rm -f /run/d2b-guest-adopted.json /run/d2b-process-adopted.json; "
        "for attempt in $(seq 1 60); do "
        "session_generation_before=$(cat "
        "/run/d2b-guest-session-generation-before) && "
        "session_generation_after=$(journalctl --no-pager -b 2>/dev/null | "
        "grep -F 'Guest ComponentSession Resource API server starting' | "
        "grep -oE 'generation[[:space:]]*=[[:space:]]*[0-9]+' | "
        "grep -oE '[0-9]+' | tail -1) && "
        "test -n \"$session_generation_after\" && "
        "test \"$session_generation_after\" -gt \"$session_generation_before\" && "
        "jq -c '{guestRef, guestUid, zone, reconnectGeneration, "
        "providerGeneration, controllerGeneration, assignmentEpoch}' "
        "/var/lib/d2b/zones/work/guests/acceptance-guest/component-session/guest.json "
        ">/run/d2b-guest-session-after.json && "
        "jq -e --slurpfile expected /run/d2b-guest-session-before.json "
        "'. == $expected[0]' /run/d2b-guest-session-after.json >/dev/null && "
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Guest "
        ">/run/d2b-guest-adopted.json && "
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Process "
        ">/run/d2b-process-adopted.json && "
        "jq -e '"
        "([.resources[] | select(.type == \"Process\" and "
        ".metadata.name == \"acceptance-guest-vmm\" and "
        ".metadata.ownerRef == \"Guest/acceptance-guest\" and "
        ".spec.providerRef == \"Provider/system-minijail\" and "
        ".spec.executionRef == \"Host/host-system\" and "
        ".spec.processClass == \"worker\" and "
        ".spec.template == \"cloud-hypervisor-runner\" and "
        ".status.phase == \"Ready\")] | length == 1) and "
        "([.resources[] | select(.type == \"Process\" and "
        ".metadata.ownerRef == \"Provider/runtime-cloud-hypervisor\" and "
        ".spec.providerRef == \"Provider/system-minijail\" and "
        ".spec.executionRef == \"Host/host-system\" and "
        ".spec.processClass == \"controller\" and "
        ".spec.template == \"controller-runtime-cloud-hypervisor-cloud-hypervisor-controller\" and "
        ".status.phase == \"Ready\")] | length == 1)' "
        "/run/d2b-process-adopted.json && "
        "jq -e --slurpfile session /run/d2b-guest-session-after.json "
        "'any(.resources[]; "
        ".type == \"Guest\" and "
        ".metadata.name == \"acceptance-guest\" and "
        ".metadata.zone == \"work\" and "
        ".metadata.uid == $session[0].guestUid and "
        ".spec.providerRef == \"Provider/runtime-cloud-hypervisor\" and "
        ".spec.executionRef == \"Host/host-system\" and "
        ".status.phase == \"Ready\" and "
        ".status.observedGeneration == .metadata.generation and "
        ".status.resource.runtimeReady == true and "
        ".status.resource.bootstrapReady == true and "
        ".status.resource.activeProcessCount == 1)' "
        "/run/d2b-guest-adopted.json && exit 0; "
        "sleep 1; done; "
        "echo 'Guest ComponentSession generation did not advance after restart:' >&2; "
        "printf 'before=%s after=%s\\n' "
        "\"$(cat /run/d2b-guest-session-generation-before 2>/dev/null || true)\" "
        "\"$(journalctl --no-pager -b 2>/dev/null | "
        "grep -F 'Guest ComponentSession Resource API server starting' | "
        "grep -oE 'generation[[:space:]]*=[[:space:]]*[0-9]+' | "
        "grep -oE '[0-9]+' | tail -1)\" >&2; "
        "jq -c '.' /run/d2b-guest-session-before.json >&2 || true; "
        "jq -c '.' /run/d2b-guest-session-after.json >&2 || true; "
        "echo 'Post-restart Guest readiness failed:' >&2; "
        "jq -c '.resources[] | select(.type == \"Guest\" and "
        ".metadata.name == \"acceptance-guest\") | "
        "{name: .metadata.name, uid: .metadata.uid, "
        "owner: .metadata.ownerRef, phase: .status.phase, "
        "observedGeneration: .status.observedGeneration, "
        "conditions: [.status.conditions[]? | "
        "{type: .type, status: .status, reason: .reason}], "
        "outcome: (.status.outcome | "
        "if . == null then null else "
        "{code: .code, retryable: .retryable} end), "
        "resource: .status.resource}' "
        "/run/d2b-guest-adopted.json >&2 || true; "
        "echo 'Post-restart Process readiness failed:' >&2; "
        "jq -c '.resources[] | "
        "{name: .metadata.name, uid: .metadata.uid, "
        "owner: .metadata.ownerRef, provider: .spec.providerRef, "
        "execution: .spec.executionRef, processClass: .spec.processClass, "
        "template: .spec.template, phase: .status.phase, "
        "observedGeneration: .status.observedGeneration, "
        "conditions: [.status.conditions[]? | "
        "{type: .type, status: .status, reason: .reason}], "
        "outcome: (.status.outcome | "
        "if . == null then null else "
        "{code: .code, retryable: .retryable} end), "
        "resource: .status.resource}' "
        "/run/d2b-process-adopted.json >&2 || true; "
        "exit 1"
    )
    machine.succeed(
        "set -- $(for proc in /proc/[0-9]*; do "
        "exe=$(readlink \"$proc/exe\" 2>/dev/null || true); "
        "case \"$exe\" in */bin/cloud-hypervisor) "
        "cmd=$(tr '\\0' ' ' < \"$proc/cmdline\"); "
        "case \"$cmd\" in *--api-socket*acceptance-guest*) "
        "pid=''${proc#/proc/}; "
        "printf '%s %s ' \"$pid\" \"$(awk '{print $22}' \"$proc/stat\")\";; "
        "esac;; esac; done); "
        f"test \"$#\" -eq 2 && test \"$1\" = {runner_pid} && "
        f"test \"$2\" = {runner_start}"
    )
    machine.succeed(
        "for attempt in $(seq 1 30); do "
        "guest_revision=$(runuser -u alice -- env "
        "D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Guest "
        "| jq -er '.resources[] | select(.type == \"Guest\" and "
        ".metadata.name == \"acceptance-guest\") | .metadata.revision') && "
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json delete Guest/acceptance-guest "
        "--revision \"$guest_revision\" "
        ">/run/d2b-guest-delete.json 2>/run/d2b-guest-delete.err && exit 0; "
        "sleep 1; done; "
        "echo 'Guest deletion did not complete within 30s:' >&2; "
        "jq -c '{resourceRef: .resourceRef, revision: .revision}' "
        "/run/d2b-guest-delete.json >&2 || true; "
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Guest | "
        "jq -c '.resources[] | select(.type == \"Guest\" and "
        ".metadata.name == \"acceptance-guest\") | "
        "{name: .metadata.name, uid: .metadata.uid, "
        "owner: .metadata.ownerRef, phase: .status.phase, "
        "observedGeneration: .status.observedGeneration, "
        "conditions: [.status.conditions[]? | "
        "{type: .type, status: .status, reason: .reason}], "
        "outcome: (.status.outcome | "
        "if . == null then null else "
        "{code: .code, retryable: .retryable} end), "
        "resource: .status.resource}' >&2 || true; "
        "exit 1"
    )
    machine.succeed(
        "jq -e '.resourceRef == \"Guest/acceptance-guest\" and "
        ".revision > 0' "
        "/run/d2b-guest-delete.json"
    )
    machine.wait_until_succeeds(
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json reconcile Guest/acceptance-guest "
        ">/run/d2b-guest-finalize.json 2>/dev/null || true; "
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Guest "
        ">/run/d2b-guest-draining.json && "
        "jq -e 'any(.resources[]; .type == \"Guest\" and "
        ".metadata.name == \"acceptance-guest\" and "
        ".metadata.deletionRequestedAt != null)' "
        "/run/d2b-guest-draining.json",
        timeout=30,
    )
    machine.wait_until_succeeds(
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json reconcile Guest/acceptance-guest "
        ">/run/d2b-guest-finalize.json 2>/dev/null || true; "
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Guest "
        "| jq -e 'all(.resources[]; .metadata.name != \"acceptance-guest\")'",
        timeout=60,
    )
    machine.wait_until_succeeds(
        "runuser -u alice -- env D2B_PUBLIC_SOCKET=/run/d2b/public.sock "
        "d2b --zone work --json list Process "
        "| jq -e 'all(.resources[]; .metadata.name != \"acceptance-guest-vmm\")'",
        timeout=30,
    )
    machine.succeed(
        "test ! -S /var/lib/d2b/zones/work/guests/acceptance-guest/acceptance-guest.sock"
    )
  '';
}
