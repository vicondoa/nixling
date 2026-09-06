# Type-G runNixOSTest: guest persistent-shell service wiring.
#
# Applies the component-session module directly to a NixOS test node and asserts the
# real systemd/PAM/linger boundary for the guest-local shell pool. This avoids a
# nested d2b-managed VM while still exercising NixOS module realization.
{ pkgs, self }:

pkgs.testers.runNixOSTest {
  name = "d2b-guest-shell-service";

  nodes.machine = { lib, pkgs, ... }: {
    imports = [
      ../../nixos-modules/component-session.nix
      ../../nixos-modules/guest-broker.nix
      {
        options.d2b.sshUser = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
        };
      }
      {
        _module.args = {
          d2bInputs = { inherit self; };
          d2bHostTools = {
            broker = self.packages.${pkgs.system}.d2b-broker-guest-static;
          };
          d2bHostToolOverrides = self.lib.d2bHostToolOverrides;
        };

        users.users.alice = {
          isNormalUser = true;
          uid = 1000;
        };

        # The host consumer supplies the target user through this guest field.
        d2b.sshUser = "alice";
        d2b.componentSession = {
          enable = lib.mkForce true;
          guestConfigPath = lib.mkForce null;
          shell = {
            enable = lib.mkForce true;
            defaultName = lib.mkForce "default";
            maxSessions = lib.mkForce 8;
            maxAttached = lib.mkForce 1;
          };
        };

        system.stateVersion = "25.11";
      }
    ];
  };

  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target", timeout=180)

    # The shell pool daemon is declared but dormant: the target-local Process
    # owner starts or adopts the pool.
    machine.succeed("systemctl cat d2b-shpool-daemon.service")
    machine.succeed(
        "test \"$(systemctl show -P PAMName d2b-shpool-daemon.service)\" = d2b-shpool-daemon"
    )
    machine.succeed(
        "test \"$(systemctl show -P User d2b-shpool-daemon.service)\" = alice"
    )
    machine.succeed(
        "test \"$(systemctl show -P KillMode d2b-shpool-daemon.service)\" = control-group"
    )
    machine.succeed(
        "test \"$(systemctl show -P Delegate d2b-shpool-daemon.service)\" = yes"
    )
    machine.succeed(
        "! find /etc/systemd/system -path '*wants/d2b-shpool-daemon.service' | grep -q ."
    )
    machine.fail("systemctl is-active --quiet d2b-shpool-daemon.service")

    pam_file = "/etc/pam.d/d2b-shpool-daemon"
    machine.succeed(f"test -f {pam_file}")
    pam = machine.succeed(f"cat {pam_file}")
    assert "pam_loginuid.so" in pam, pam
    assert "pam_systemd.so" not in pam, (
        "d2b-shpool-daemon must not start a pam_systemd session; "
        "that would migrate the daemon out of the delegated service cgroup"
    )

    machine.succeed("test -f /var/lib/systemd/linger/alice")
    machine.succeed("id -u alice | grep -qx 1000")
  '';
}
