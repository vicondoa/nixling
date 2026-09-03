{
  description = "Opinionated NixOS desktop microVM workspaces";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Package-only Rust build helper for shared host-tool dependency
    # artifacts. It is deliberately not used as an overlay.
    crane = {
      url = "github:ipetkov/crane";
    };

    # `microvm` flake input DROPPED per ADR 0018.
    # The d2b NixOS substrate owns its per-VM evaluator via
    # `nixos-modules/vm-evaluator.nix` + `nixos-modules/vm-options.nix`.
    # Runner argv planning lives in the owning Provider crates; the broker
    # consumes the trusted bundle's prebuilt argv.

    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    home-manager,
    ...
  }@inputs:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      # crates.io's /api/v1/crates/.../download endpoint 403s from GitHub
      # Actions IPs (WAF / rate limit). Rewrite fetchurl only so Cargo still
      # sees the crates-io source (extraRegistries duplicates it and cargo
      # 1.77+ errors). See https://github.com/rust-lang/crates.io/issues/13482
      cratesIoApiPrefix = "https://crates.io/api/v1/crates/";
      cratesIoCdnPrefix = "https://static.crates.io/crates/";
      nixpkgsFor = forAllSystems (system: import nixpkgs {
        inherit system;
        overlays = [
          (final: prev: {
            fetchurl = args:
              let
                url = args.url or null;
              in
              prev.fetchurl (
                if url != null && prev.lib.hasPrefix cratesIoApiPrefix url then
                  args // {
                    url = cratesIoCdnPrefix + prev.lib.removePrefix cratesIoApiPrefix url;
                  }
                else
                  args
              );
          })
        ];
      });
      bazel920For = system:
        import ./pkgs/bazel-9.2.0 {
          pkgs = nixpkgsFor.${system};
        };
      bazelWorkerImageFor = system:
        import ./nix/bazel-worker-image.nix {
          pkgs = nixpkgsFor.${system};
          bazel = bazel920For system;
          inherit system;
        };

      providerElfShim = import ./nix/provider-elf-shim.nix;
      # The Guest static workspace mirrors the shared daemon/broker dependency
      # closure. Guest packaging contains only the shared daemon, broker,
      # and signed Provider workspace inputs.
      mkGuestRustPackagesSrc = pkgs:
        pkgs.runCommand "d2b-guest-rust-src" { } ''
          mkdir -p $out/packages
          cp -r ${./packages/d2b-audit} $out/packages/d2b-audit
          cp -r ${./packages/d2b-broker} $out/packages/d2b-broker
          cp -r ${./packages/d2b-bus} $out/packages/d2b-bus
          cp -r ${./packages/d2b-contracts} $out/packages/d2b-contracts
          cp -r ${./packages/d2b-contracts-broker} $out/packages/d2b-contracts-broker
          cp -r ${./packages/d2b-contracts-control} $out/packages/d2b-contracts-control
          cp -r ${./packages/d2b-contracts-provider} $out/packages/d2b-contracts-provider
          cp -r ${./packages/d2b-contracts-resource} $out/packages/d2b-contracts-resource
          cp -r ${./packages/d2b-contracts-zone-session} $out/packages/d2b-contracts-zone-session
          cp -r ${./packages/d2b-controller-toolkit} $out/packages/d2b-controller-toolkit
          cp -r ${./packages/d2b-core} $out/packages/d2b-core
          cp -r ${./packages/d2b-core-controller} $out/packages/d2b-core-controller
          cp -r ${./packages/d2b-host} $out/packages/d2b-host
          cp -r ${./packages/d2b-sk-frontend} $out/packages/d2b-sk-frontend
          cp -r ${./packages/d2b-process} $out/packages/d2b-process
          cp -r ${./packages/d2b-process-conformance} $out/packages/d2b-process-conformance
          cp -r ${./packages/d2b-provider} $out/packages/d2b-provider
          cp -r ${./packages/d2b-provider-activation-nixos} $out/packages/d2b-provider-activation-nixos
          cp -r ${./packages/d2b-provider-audio-pipewire} $out/packages/d2b-provider-audio-pipewire
          cp -r ${./packages/d2b-provider-clipboard-wayland} $out/packages/d2b-provider-clipboard-wayland
          cp -r ${./packages/d2b-provider-config-nixos} $out/packages/d2b-provider-config-nixos
          cp -r ${./packages/d2b-provider-credential-entra} $out/packages/d2b-provider-credential-entra
          cp -r ${./packages/d2b-provider-credential-managed-identity} $out/packages/d2b-provider-credential-managed-identity
          cp -r ${./packages/d2b-provider-credential-secret-service} $out/packages/d2b-provider-credential-secret-service
          cp -r ${./packages/d2b-provider-device-gpu} $out/packages/d2b-provider-device-gpu
          cp -r ${./packages/d2b-provider-device-security-key} $out/packages/d2b-provider-device-security-key
          cp -r ${./packages/d2b-provider-device-tpm} $out/packages/d2b-provider-device-tpm
          cp -r ${./packages/d2b-provider-device-usbip} $out/packages/d2b-provider-device-usbip
          cp -r ${./packages/d2b-provider-display-wayland} $out/packages/d2b-provider-display-wayland
          cp -r ${./packages/d2b-provider-network-local} $out/packages/d2b-provider-network-local
          cp -r ${./packages/d2b-provider-notification-desktop} $out/packages/d2b-provider-notification-desktop
          cp -r ${./packages/d2b-provider-observability-otel} $out/packages/d2b-provider-observability-otel
          cp -r ${./packages/d2b-provider-runtime-azure-container-apps} $out/packages/d2b-provider-runtime-azure-container-apps
          cp -r ${./packages/d2b-provider-runtime-azure-virtual-machine} $out/packages/d2b-provider-runtime-azure-virtual-machine
          cp -r ${./packages/d2b-provider-runtime-cloud-hypervisor} $out/packages/d2b-provider-runtime-cloud-hypervisor
          cp -r ${./packages/d2b-provider-runtime-qemu-media} $out/packages/d2b-provider-runtime-qemu-media
          cp -r ${./packages/d2b-provider-shell-terminal} $out/packages/d2b-provider-shell-terminal
          cp -r ${./packages/d2b-provider-supervisor} $out/packages/d2b-provider-supervisor
          cp -r ${./packages/d2b-provider-system-core} $out/packages/d2b-provider-system-core
          cp -r ${./packages/d2b-provider-system-minijail} $out/packages/d2b-provider-system-minijail
          cp -r ${./packages/d2b-provider-system-systemd} $out/packages/d2b-provider-system-systemd
          cp -r ${./packages/d2b-provider-toolkit} $out/packages/d2b-provider-toolkit
          cp -r ${./packages/d2b-provider-transport-azure-relay} $out/packages/d2b-provider-transport-azure-relay
          cp -r ${./packages/d2b-provider-volume-local} $out/packages/d2b-provider-volume-local
          cp -r ${./packages/d2b-provider-volume-virtiofs} $out/packages/d2b-provider-volume-virtiofs
          cp -r ${./packages/d2b-resource-api} $out/packages/d2b-resource-api
          cp -r ${./packages/d2b-resource-store} $out/packages/d2b-resource-store
          cp -r ${./packages/d2b-resource-store-redb} $out/packages/d2b-resource-store-redb
          cp -r ${./packages/d2b-session} $out/packages/d2b-session
          cp -r ${./packages/d2b-session-unix} $out/packages/d2b-session-unix
          cp -r ${./packages/d2b-telemetry} $out/packages/d2b-telemetry
          cp -r ${./packages/d2b-zone-routing} $out/packages/d2b-zone-routing
          cp -r ${./packages/d2bd} $out/packages/d2bd
          cp -r ${./packages/d2bd-runtime} $out/packages/d2bd-runtime
          mkdir -p $out/docs/reference/schemas/v3/providers
          cp ${./docs/reference/schemas/v3/providers/transport-azure-relay.transport-settings.json} \
            $out/docs/reference/schemas/v3/providers/transport-azure-relay.transport-settings.json
          cp ${./docs/reference/schemas/v3/providers/transport-vsock.transport-binding.json} \
            $out/docs/reference/schemas/v3/providers/transport-vsock.transport-binding.json
          cp ${./packages/Cargo.guest.lock} $out/packages/Cargo.lock
          chmod -R u+w $out/packages
          cp ${./tests/fixtures/guest-rust-workspace/d2b-contracts.Cargo.toml} \
            $out/packages/d2b-contracts/Cargo.toml
          cp ${./tests/fixtures/guest-rust-workspace/d2b-core.Cargo.toml} \
            $out/packages/d2b-core/Cargo.toml
          cp ${./tests/fixtures/guest-rust-workspace/Cargo.toml} \
            $out/packages/Cargo.toml
        '';
    in
    {
      # The public surface area - populated incrementally by the
      # refactor plan. This wires `nixosModules.default` for real
      # after refactoring `host.nix`'s `{ inputs, ... }:`
      # module-arg into a closure-passed partial application (see
      # `./nixos-modules/default.nix` for the wiring + rationale).
      #
      # Downstream consumers:
      #
      #   imports = [ inputs.d2b.nixosModules.default ];
      #
      # Future work will populate the remaining surface:
      #   packages.<sys>       - patched cloud-hypervisor, crosvm, etc.
      #   templates.default    - `nix flake init -t github:vicondoa/d2b`
      #   checks.<sys>         - flake-eval CI gates
      #   lib                  - re-exported helpers (subnetIp, mkMac, …)
      nixosModules.default = import ./nixos-modules { inherit inputs; };
      # Developer shell: everything the Layer-1 gates need, in one place.
      #
      # Without this each focused gate would provision its own toolchain.
      # Enter this shell once so Bazel, Cargo, Nix, and the policy tools use
      # the pinned versions throughout the fixed graph.
      #
      # rustup rather than pkgs.rustc: rust-toolchain.toml pins a
      # version nixpkgs does not carry (the pin is 1.97.0; this nixpkgs has
      # 1.95.0), and rustup reads that file itself. Once the nixpkgs input
      # advances far enough to supply the pinned release, rustup can be dropped
      # for pkgs.rustc/pkgs.cargo and the pin will be served natively.
      devShells = forAllSystems (system: let
        pkgs = nixpkgsFor.${system};
        bazel920 = bazel920For system;
        bazelActionShell = pkgs.buildFHSEnv {
          name = "d2b-bazel-action-shell";
          executableName = "bash";
          targetPkgs = fhsPkgs: with fhsPkgs; [
            bash
            coreutils
            gnugrep
          ];
          runScript = "${pkgs.bash}/bin/bash";
        };
        mkBazelShellHook = testPath: ''
          export D2B_PROJECT_SHELL=d2b
          export D2B_BAZEL_BIN="${bazel920}/bin/bazel"
          if [ -z "''${BAZEL_SH:-}" ]; then
            if [ -x /bin/bash ]; then
              export BAZEL_SH=/bin/bash
            else
              export BAZEL_SH="${bazelActionShell}/bin/bash"
            fi
          fi
          export D2B_SHELLCHECK_BIN="${pkgs.shellcheck}/bin/shellcheck"
          export D2B_BAZEL_TEST_PATH="${testPath}"
        '';
      in {
        default = pkgs.mkShell {
          name = "d2b-dev";
          packages = with pkgs; [
            # Toolchain. rustup resolves rust-toolchain.toml.
            bazel920
            gnumake
            rustup
            stdenv.cc
            # Compiler cache. The cargo configs route rustc through
            # .cargo/rustc-wrapper.sh, which uses this when present and plain
            # rustc when absent, so the shell never has to clear RUSTC_WRAPPER.
            sccache
            # Test and audit tooling the gates otherwise fetch per invocation.
            cargo-nextest
            cargo-deny
            cargo-audit
            # Shell and data tooling used by the gate scripts themselves.
            shellcheck
            jq
            ripgrep
            acl
          ];
          shellHook = ''
            ${mkBazelShellHook (pkgs.lib.makeBinPath [
              bazel920
              pkgs.bash
              pkgs.coreutils
              pkgs.findutils
              pkgs.gnugrep
              pkgs.gnused
              pkgs.git
              pkgs.gnumake
              pkgs.jq
              pkgs.rustup
              pkgs.shellcheck
            ])}
            export SCCACHE_DIR="''${SCCACHE_DIR:-$HOME/.cache/d2b-sccache}"
            echo "d2b dev shell: rust $(sed -n 's/.*channel = "\(.*\)".*/\1/p' rust-toolchain.toml) via rustup, sccache at $SCCACHE_DIR"
          '';
        };
        # Focused shell for the evaluation-only Nix-unit runner. Keeping this
        # output separate lets the target acquire only its locked external
        # tools instead of entering the full Rust development shell.
        nix-unit = pkgs.mkShellNoCC {
          name = "d2b-nix-unit";
          packages = with pkgs; [
            jq
          ];
        };
        # Focused U1 shell: the compatibility proof must use the exact
        # official Bazel release rather than an ambient toolchain.
        # Only Bazel shell actions enter the standard FHS action shell;
        # Bazel itself and local tests stay in the caller's environment.
        bazel = pkgs.mkShellNoCC {
          name = "d2b-bazel-compat";
          packages = with pkgs; [
            bazel920
            bash
            coreutils
            findutils
            gawk
            git
            gnumake
            gnugrep
            gnused
            jq
            rustup
            shellcheck
          ];
          shellHook = ''
            ${mkBazelShellHook (pkgs.lib.makeBinPath [
              bazel920
              pkgs.bash
              pkgs.coreutils
              pkgs.findutils
              pkgs.gawk
              pkgs.git
              pkgs.gnumake
              pkgs.gnugrep
              pkgs.gnused
              pkgs.jq
              pkgs.rustup
              pkgs.shellcheck
            ])}
            echo "d2b Bazel compatibility shell: $(${bazel920}/bin/bazel --version)"
          '';
        };
      });

      packages = forAllSystems (system: let
        pkgs = nixpkgsFor.${system};
        bazel920 = bazel920For system;
        rustPackagesSrc = pkgs.runCommand "d2b-rust-src" { } ''
          mkdir -p $out/packages
          cp ${./Cargo.toml} $out/Cargo.toml
          cp ${./Cargo.lock} $out/Cargo.lock
          cp ${./deny.toml} $out/deny.toml
          cp -r ${./packages}/. $out/packages/
          mkdir -p $out/docs/reference/schemas/v3/providers
          cp ${./docs/reference/schemas/v3/providers/transport-azure-relay.transport-settings.json} \
            $out/docs/reference/schemas/v3/providers/transport-azure-relay.transport-settings.json
          cp ${./docs/reference/schemas/v3/providers/transport-vsock.transport-binding.json} \
            $out/docs/reference/schemas/v3/providers/transport-vsock.transport-binding.json
        '';
        rustWorkspace = args: pkgs.rustPlatform.buildRustPackage ({
          pname = "d2b-rust-workspace";
          version = "0.0.0-bootstrap";
          src = rustPackagesSrc;
          sourceRoot = "d2b-rust-src";
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes."wl-proxy-0.1.2" = "sha256-1yO1zgzSyzQ2DnDMpVxcnI5BsTNvXfzIUS+RNlPj4A8=";
          };
          RUSTC_WRAPPER = "";
          SCCACHE_DIR = "";
        } // args);
        guestRustPackagesSrc = mkGuestRustPackagesSrc pkgs;
        cargoLock = {
          lockFile = ./packages/Cargo.guest.lock;
        };
        guestStaticPackage = packageName: binName:
          pkgs.pkgsStatic.rustPlatform.buildRustPackage {
            pname = "${binName}-static";
            version = "0.0.0-bootstrap";
            src = guestRustPackagesSrc;
            sourceRoot = "d2b-guest-rust-src/packages";
            cargoLock = {
              lockFile = ./packages/Cargo.guest.lock;
              outputHashes."wl-proxy-0.1.2" = "sha256-1yO1zgzSyzQ2DnDMpVxcnI5BsTNvXfzIUS+RNlPj4A8=";
            };
            cargoBuildFlags = [ "--package" packageName "--bin" binName ];
            doCheck = false;
            RUSTC_WRAPPER = "";
            SCCACHE_DIR = "";
            nativeBuildInputs = [ pkgs.pkgsStatic.binutils ];
            postInstall = ''
              readelf=${pkgs.pkgsStatic.binutils.bintools}/bin/readelf
              bin="$out/bin/${binName}"
              test -x "$bin"
              "$readelf" -h "$bin" >/dev/null
              "$readelf" -l "$bin" > "$TMPDIR/${binName}.program-headers"
              if grep -q 'Requesting program interpreter' "$TMPDIR/${binName}.program-headers"; then
                echo "${binName}: unexpected ELF interpreter" >&2
                cat "$TMPDIR/${binName}.program-headers" >&2
                exit 1
              fi
              if "$readelf" -d "$bin" > "$TMPDIR/${binName}.dynamic" 2> "$TMPDIR/${binName}.dynamic.err"; then
                if grep -q '(NEEDED)' "$TMPDIR/${binName}.dynamic"; then
                  echo "${binName}: unexpected dynamic dependency" >&2
                  cat "$TMPDIR/${binName}.dynamic" >&2
                  exit 1
                fi
              elif ! grep -qi 'no dynamic section' "$TMPDIR/${binName}.dynamic.err"; then
                echo "${binName}: readelf -d failed unexpectedly" >&2
                cat "$TMPDIR/${binName}.dynamic.err" >&2
                exit 1
              fi
            '';
          };
        guestShellRunnerStatic =
          pkgs.pkgsStatic.rustPlatform.buildRustPackage {
            pname = "d2b-guest-shell-runner-static";
            version = "0.0.0-bootstrap";
            src = rustPackagesSrc;
            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes."wl-proxy-0.1.2" = "sha256-1yO1zgzSyzQ2DnDMpVxcnI5BsTNvXfzIUS+RNlPj4A8=";
            };
            sourceRoot = "d2b-rust-src";
            cargoBuildFlags = [
              "--package" "d2b-guest-shell-runner"
              "--features" "real-libshpool"
            ];
            doCheck = false;
            RUSTC_WRAPPER = "";
            SCCACHE_DIR = "";
            nativeBuildInputs = [
              pkgs.pkgsStatic.binutils
              pkgs.pkgsStatic.rustPlatform.bindgenHook
            ];
            postInstall = ''
              readelf=${pkgs.pkgsStatic.binutils.bintools}/bin/readelf
              bin="$out/bin/d2b-guest-shell-runner"
              test -x "$bin"
              "$readelf" -h "$bin" >/dev/null
              "$readelf" -l "$bin" > "$TMPDIR/d2b-guest-shell-runner.program-headers"
              if grep -q 'Requesting program interpreter' "$TMPDIR/d2b-guest-shell-runner.program-headers"; then
                echo "d2b-guest-shell-runner: unexpected ELF interpreter" >&2
                cat "$TMPDIR/d2b-guest-shell-runner.program-headers" >&2
                exit 1
              fi
              if "$readelf" -d "$bin" > "$TMPDIR/d2b-guest-shell-runner.dynamic" 2> "$TMPDIR/d2b-guest-shell-runner.dynamic.err"; then
                if grep -q '(NEEDED)' "$TMPDIR/d2b-guest-shell-runner.dynamic"; then
                  echo "d2b-guest-shell-runner: unexpected dynamic dependency" >&2
                  cat "$TMPDIR/d2b-guest-shell-runner.dynamic" >&2
                  exit 1
                fi
              elif ! grep -qi 'no dynamic section' "$TMPDIR/d2b-guest-shell-runner.dynamic.err"; then
                echo "d2b-guest-shell-runner: readelf -d failed unexpectedly" >&2
                cat "$TMPDIR/d2b-guest-shell-runner.dynamic.err" >&2
                exit 1
              fi
            '';
          };
        providerArtifact = import ./nix/provider-artifact.nix {
          inherit pkgs;
        };
        providerCatalogShape =
          import ./nixos-modules/generated/provider-catalog-shape.nix;
        providerMatrixJson = builtins.toJSON {
          schemaVersion = 1;
          artifactLayout = providerCatalogShape.artifactLayout;
          fixedBootstrapProviderIds =
            providerCatalogShape.fixedBootstrapProviderIds;
          providerIds = providerCatalogShape.providerIds;
          providers = providerCatalogShape.providerMatrix;
        };
        providerMatrix = pkgs.writeText
          "d2b-provider-matrix.json"
          "${providerMatrixJson}\n";
        cloudHypervisorController = rustWorkspace {
          pname = "d2b-cloud-hypervisor-controller";
          cargoBuildFlags = [
            "--package"
            "d2b-provider-runtime-cloud-hypervisor"
            "--bin"
            "d2b-cloud-hypervisor-controller"
          ];
          doCheck = false;
          meta.mainProgram = "d2b-cloud-hypervisor-controller";
        };
        cloudHypervisorArtifact = providerArtifact {
          artifactId = "runtime-cloud-hypervisor";
          binary = cloudHypervisorController;
          binaryRef = "d2b-cloud-hypervisor-controller";
          manifest = ./packages/d2b-provider-runtime-cloud-hypervisor/provider-manifest.json;
          signature = ./packages/d2b-provider-runtime-cloud-hypervisor/provider-manifest.json.sig;
          configSchema = ./packages/d2b-provider-runtime-cloud-hypervisor/root-config.schema.json;
          publicKey = ./packages/d2b-provider-runtime-cloud-hypervisor/publisher-public-key.pem;
          providerName = "runtime-cloud-hypervisor";
          packageName = "d2b-provider-runtime-cloud-hypervisor";
          signatureId = "default";
        };
      in {
        manpages = pkgs.runCommand "d2b-manpages" { } ''
          install -Dm644 ${./docs/manpages/d2b.1} "$out/share/man/man1/d2b.1"
          ${pkgs.gzip}/bin/gzip -n -c ${./docs/manpages/d2b.1} > "$out/share/man/man1/d2b.1.gz"
        '';

        completions = pkgs.runCommand "d2b-completions" { } ''
          install -Dm644 ${./completions/d2b.bash} "$out/share/bash-completion/completions/d2b"
          install -Dm644 ${./completions/d2b.zsh}  "$out/share/zsh/site-functions/_d2b"
          install -Dm644 ${./completions/d2b.fish} "$out/share/fish/vendor_completions.d/d2b.fish"
        '';
        d2bd-guest-static = guestStaticPackage "d2bd" "d2bd";
        d2b-broker-guest-static =
          guestStaticPackage "d2b-broker" "d2b-broker";
        d2b-sk-frontend-static =
          guestStaticPackage "d2b-sk-frontend" "d2b-sk-frontend";
        d2b-guest-shell-runner-static = guestShellRunnerStatic;
        d2b-clipd = rustWorkspace {
          pname = "d2b-provider-clipboard-wayland";
          cargoBuildFlags = [
            "--package"
            "d2b-provider-clipboard-wayland"
            "--bin"
            "d2b-clipd"
          ];
          doCheck = false;
        };
        d2b-wayland-proxy = rustWorkspace {
          pname = "d2b-provider-display-wayland";
          cargoBuildFlags = [
            "--package"
            "d2b-provider-display-wayland"
            "--bin"
            "d2b-wayland-proxy"
          ];
          doCheck = false;
          meta.mainProgram = "d2b-wayland-proxy";
        };
        d2b-sk-waybar-helper = rustWorkspace {
          pname = "d2b-provider-notification-desktop";
          cargoBuildFlags = [
            "--package"
            "d2b-provider-notification-desktop"
            "--bin"
            "d2b-sk-waybar-helper"
          ];
          doCheck = false;
          meta.mainProgram = "d2b-sk-waybar-helper";
        };
        d2b-unsafe-local-helper = rustWorkspace {
          pname = "d2b-unsafe-local-helper";
          cargoBuildFlags = [
            "--package"
            "d2b-unsafe-local-helper"
            "--bin"
            "d2b-unsafe-local-helper"
          ];
          doCheck = false;
          meta.mainProgram = "d2b-unsafe-local-helper";
        };
        d2b-resource-compiler = rustWorkspace {
          pname = "d2b-resource-compiler";
          cargoBuildFlags = [
            "--package"
            "d2b-resource-compiler"
            "--bin"
            "d2b-resource-compiler"
          ];
          doCheck = false;
          meta.mainProgram = "d2b-resource-compiler";
        };
        d2b-provider-runtime-cloud-hypervisor =
          cloudHypervisorArtifact.package;
        provider-matrix = providerMatrix;

        signoz = import ./pkgs/signoz { inherit pkgs; };
        signozOtelCollector = import ./pkgs/signoz-otel-collector { inherit pkgs; };
        signozSchemaMigrator = import ./pkgs/signoz-schema-migrator { inherit pkgs; };
        bazel-9_2_0 = bazel920;
        bazel-worker-image = bazelWorkerImageFor system;
      });

      # Container-based integration test images (the type-G layer), built by
      # Nix and run with podman, rootless. Exposed under `containerImages`,
      # NOT `checks`, so the Layer-1 `nix flake check --no-build --all-systems`
      # never builds an image. The `make test-integration` target
      # (tests/integration/containers/*.sh, driven via podman) builds + runs them; the same
      # target runs on a GitHub Actions ubuntu-latest job (podman is
      # preinstalled there) and locally.
      #
      # Scope: this layer is ONLY for things that need a foreign (non-Nix)
      # userland - e.g. proving a static d2b binary runs on stock Ubuntu.
      # It deliberately does NOT boot systemd for daemon/socket activation;
      # that is covered natively by
      # packages/d2b-broker/tests/socket_activation.rs plus nix-unit.
      # See tests/integration/containers/README.md.
      #
      # Auto-discovered from tests/integration/containers/images/*.nix: each image module is
      # `{ pkgs, self, system }: <dockerTools-built OCI image>`, so adding a new
      # container test is one new image file + its tests/integration/containers/<name>.sh
      # runner - no edit here. x86_64-linux only (the project's CI runners +
      # this host are x86_64; aarch64 images need an aarch64 builder).
      containerImages = forAllSystems (system:
        if system == "x86_64-linux" then
          let
            pkgs = nixpkgsFor.${system};
            imageDir = ./tests/integration/containers/images;
            imageFiles = if builtins.pathExists imageDir
              then builtins.attrNames (nixpkgs.lib.filterAttrs
                (name: type: type == "regular" && nixpkgs.lib.hasSuffix ".nix" name)
                (builtins.readDir imageDir))
              else [ ];
            mkImage = file: {
              name = nixpkgs.lib.removeSuffix ".nix" file;
              value = import (imageDir + "/${file}") { inherit pkgs self system; };
            };
          in builtins.listToAttrs (map mkImage imageFiles)
        else { });

      # Type-G runNixOSTest integration tests (the additive real-kernel
      # coverage layer). Each test boots a real NixOS VM with the d2b
      # daemon surface and asserts live broker/daemon/host-posture behaviour
      # (socket activation, SO_PEERCRED, bridge isolation, state-dir ACLs,
      # broker privilege posture) that the fake-backed native Rust canaries and
      # pure-eval gates cannot exercise. This is the hermetic, non-destructive
      # successor to the `D2B_LIVE`-against-the-real-host bash scripts.
      #
      # Exposed under `vmChecks`, NOT `checks`, so the Layer-1 `nix flake check
      # --no-build --all-systems` never realizes a VM. Selected explicitly by
      # `make test-host-integration` (`nix build .#vmChecks.<system>.<name>`),
      # which needs KVM (a local NixOS host; TCG fallback otherwise).
      #
      # Auto-discovered from tests/host-integration/*.nix (excluding lib.nix): each test is
      # `{ pkgs, self }: pkgs.testers.runNixOSTest { ... }`, so adding a VM test
      # is one new file - no edit here. x86_64-linux only: a runNixOSTest VM is
      # built + booted for the builder's own system, and the hosted CI runners
      # are x86_64 - aarch64 VM coverage needs an aarch64 builder.
      vmChecks = forAllSystems (system:
        if system == "x86_64-linux" then
          let
            pkgs = nixpkgsFor.${system};
            hostToolBundleEnv = builtins.getEnv "D2B_HOST_TOOL_BUNDLE";
            cloudHypervisorControllerBundleEnv =
              builtins.getEnv "D2B_CH_CONTROLLER_BUNDLE";
            bazelHostTools =
              if hostToolBundleEnv == "" then
                null
              else
                import ./nix/test-support/bazel-host-tools.nix {
                  inherit pkgs;
                  rawBundle = builtins.path {
                    path = /. + hostToolBundleEnv;
                    name = "d2b-bazel-host-tools";
                  };
                  rawCloudHypervisorController =
                    if cloudHypervisorControllerBundleEnv == "" then null else
                    builtins.path {
                      path = /. + cloudHypervisorControllerBundleEnv;
                      name = "d2b-bazel-cloud-hypervisor-controller";
                    };
                };
            testSelf =
              if bazelHostTools == null then
                self
              else
                self // {
                  lib = self.lib // {
                    d2bHostToolOverrides =
                      bazelHostTools.d2bHostToolOverrides;
                    evalGuest = args: self.lib.evalGuest (args // {
                      d2bHostToolOverrides =
                        bazelHostTools.d2bHostToolOverrides;
                    });
                  };
                  nixosModules = self.nixosModules // {
                    default = {
                      imports = [ self.nixosModules.default ];
                      _module.args.d2bHostToolOverrides =
                        bazelHostTools.d2bHostToolOverrides;
                    };
                  };
                  packages = self.packages // {
                    ${system} = self.packages.${system}
                      // {
                        d2b-wayland-proxy = bazelHostTools.package;
                      }
                      // nixpkgs.lib.optionalAttrs
                        (bazelHostTools.cloudHypervisorControllerPackage != null)
                        {
                          d2b-cloud-hypervisor-controller =
                            bazelHostTools.cloudHypervisorControllerPackage;
                        };
                  };
                };
            testDir = ./tests/host-integration;
            testFiles = if builtins.pathExists testDir
              then builtins.attrNames (nixpkgs.lib.filterAttrs
                (name: type:
                  type == "regular"
                  && nixpkgs.lib.hasSuffix ".nix" name
                  && name != "lib.nix")
                (builtins.readDir testDir))
              else [ ];
            mkTest = file: {
              name = nixpkgs.lib.removeSuffix ".nix" file;
              value = import (testDir + "/${file}") {
                inherit pkgs;
                self = testSelf;
              };
            };
          in builtins.listToAttrs (map mkTest testFiles)
        else { });

      templates.default = {
        path = ./templates/default;
        description = "Minimal d2b host scaffold - one Zone";
      };

      # Eval-only gates for the current Zone module and fixture. The
      # `system.build.toplevel.drvPath` access is enough to force a
      # full module-system instantiation (option types, assertions,
      # CIDR validators, etc.) without actually realising the closure
      # - which is what we want from a `nix flake check` gate.
      #
      checks = forAllSystems (system: let
        pkgs = nixpkgsFor.${system};
        bazel920 = bazel920For system;
        d2bModule = import ./nixos-modules { inherit inputs; };
        mkEval = modules: nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            d2bModule
            ({ lib, ... }: {
              # Cross-system eval cannot use x86-only release prebuilts.
              # Native x86 eval keeps the consumer default to avoid forcing
              # source host-tool derivations through every lightweight check.
              d2b.site.usePrebuiltHostTools = lib.mkDefault (system == "x86_64-linux");
            })
          ] ++ modules;
        };
        mkCheck = name: cfg: pkgs.runCommand "d2b-check-${name}" { } ''
          echo ${builtins.unsafeDiscardStringContext cfg.config.system.build.toplevel.drvPath} > $out
        '';
        mkEvalOnlyCheck = name: value: pkgs.runCommand "d2b-check-${name}" { } ''
          echo ${builtins.unsafeDiscardStringContext (builtins.toJSON value)} > $out
        '';
        smokeConfigModule = { ... }: {
          boot.loader.grub.enable = false;
          boot.loader.systemd-boot.enable = false;
          boot.initrd.includeDefaultModules = false;
          fileSystems."/" = {
            device = "tmpfs";
            fsType = "tmpfs";
          };
          environment.etc."machine-id".text =
            "00000000000000000000000000000000";
          system.stateVersion = "25.11";

          users.users.alice = {
            isNormalUser = true;
            uid = 1000;
          };

          d2b.site = {
            waylandUser = "alice";
            launcherUsers = [ "alice" ];
            yubikey.enable = false;
          };
          d2b.zones.local-root = { };
        };
        # The eval-only fixtures contain no authored v3 artifacts. Keep their
        # catalog projection deterministic instead of forcing the production
        # artifact-catalog IFD (`runCommand` + `builtins.readFile`) while
        # rendering an otherwise unrelated VM fixture. The production module
        # remains the authority for real configurations with authored
        # artifacts; this is only the fixture boundary for the empty case.
        fixtureArtifactCatalogData = {
          schemaVersion = 3;
          entries = [ ];
        };
        fixtureArtifactCatalogPreimageJson =
          builtins.toJSON fixtureArtifactCatalogData;
        fixtureArtifactCatalogDigest = "sha256:${builtins.hashString
          "sha256"
          (builtins.toJSON {
            domain = "d2b:v3:artifact-catalog";
            framing = "d2b-digest/v1";
            payload = fixtureArtifactCatalogPreimageJson;
          })}";
        fixtureArtifactCatalogDocument = fixtureArtifactCatalogData // {
          catalogDigest = fixtureArtifactCatalogDigest;
        };
        fixtureArtifactCatalogJson =
          builtins.toJSON fixtureArtifactCatalogDocument;
        fixtureArtifactCatalogPath = pkgs.writeText
          "d2b-artifact-catalog-eval-fixture.json"
          "${fixtureArtifactCatalogJson}\n";
        fixtureArtifactCatalogProjection = {
          ids = [ ];
          artifactRows = [ ];
          preimage = fixtureArtifactCatalogData;
          preimageJson = fixtureArtifactCatalogPreimageJson;
          catalogDigest = fixtureArtifactCatalogDigest;
          catalogData = fixtureArtifactCatalogDocument;
          catalogJson = fixtureArtifactCatalogJson;
          path = fixtureArtifactCatalogPath;
          publicEntries = [ ];
        };
        fixtureArtifactCatalogArtifact = {
          data = fixtureArtifactCatalogData;
          jsonText = fixtureArtifactCatalogJson;
          path = fixtureArtifactCatalogPath;
          installFileName = "artifact-catalog.json";
          classification = "contractPrivateNonSecret";
          sensitivity = "nonSecret";
        };
        fixtureArtifactCatalogOverride = { lib, ... }: {
          d2b._artifactCatalogV3 = lib.mkForce
            fixtureArtifactCatalogProjection;
          d2b._bundle.extraArtifacts.artifactCatalog =
            lib.mkOverride 0 fixtureArtifactCatalogArtifact;
        };
        fixtureResourceCompilerEnv =
          builtins.getEnv "D2B_FIXTURE_RESOURCE_COMPILER";
        fixtureResourceCompiler =
          if fixtureResourceCompilerEnv == "" then
            self.packages.${system}.d2b-resource-compiler
          else
            pkgs.stdenv.mkDerivation {
              pname = "d2b-fixture-resource-compiler";
              version = "0";
              src = builtins.path {
                path = /. + fixtureResourceCompilerEnv;
                name = "d2b-resource-compiler";
              };
              dontUnpack = true;
              nativeBuildInputs = [ pkgs.autoPatchelfHook ];
              buildInputs = [ pkgs.glibc pkgs.stdenv.cc.cc.lib ];
              installPhase = ''
                install -Dm755 "$src" "$out/bin/d2b-resource-compiler"
              '';
            };
        fixtureHostToolPackage = pkgs.runCommand "d2b-fixture-host-tools" { } ''
          mkdir -p "$out/bin"
          for name in \
            d2b \
            d2bd \
            d2b-broker \
            d2b-activation-helper \
            d2b-host-activation-helper \
            d2b-unsafe-local-helper \
            d2b-wayland-proxy
          do
            printf '#!%s\nexit 0\n' '${pkgs.runtimeShell}' > "$out/bin/$name"
            chmod 0755 "$out/bin/$name"
          done
        '';
        fixtureHostToolOverrides =
          (pkgs.lib.genAttrs [
            "d2b"
            "d2bd"
            "broker"
            "activationHelper"
            "hostActivationHelper"
            "unsafeLocalHelper"
            "resourceCompiler"
            "waylandProxy"
          ] (_: fixtureHostToolPackage))
          // { resourceCompiler = fixtureResourceCompiler; };
        smokeEval = mkEval [
          smokeConfigModule
          ({ lib, ... }: {
            # Bazel fixture actions inject their already-built host tools so
            # rendered paths and argv track the current workspace without a
            # second Rust build through Nix.
            d2b.site.usePrebuiltHostTools = lib.mkForce false;
            _module.args.d2bHostToolOverrides =
              lib.mkForce fixtureHostToolOverrides;
          })
          fixtureArtifactCatalogOverride
        ];
        renderEvalFixture = {
          evaluated
        }: let
          bundle = evaluated.config.d2b._bundle;
          top = name: bundle.${name}.fixtureData;
        in {
          files = {
            "privileges.json" = top "privilegesJson";
            "realm-workloads-launcher-v2.json" = top "realmWorkloadsLauncherV2Json";
            "bundle.json" = top "bundle";
          };
          zones = pkgs.lib.mapAttrs
            (_: artifact: artifact.fixtureData)
            bundle.zoneResourceBundles;
        };
        fixtureHostJson = pkgs.writeText "d2b-fixture-host.json" (builtins.toJSON {
          schemaVersion = "v2";
          site = {
            allowUnsafeEastWest = false;
          };
          environments = [ ];
          nftables = {
            family = "inet";
            table = "d2b";
            chains = [ ];
            tableHashAfterApply = null;
            ownershipId = "";
          };
          networkManager = {
            filePath = "/etc/NetworkManager/conf.d/d2b-unmanaged.conf";
            matchCriteria = [ ];
            reloadBehavior = "none";
            ownership = {
              owner = "root";
              group = "d2bd";
              mode = "0640";
              driftPolicy = "preserve";
            };
          };
          hostsFile = {
            startMarker = "# d2b-managed begin";
            endMarker = "# d2b-managed end";
            rule = "none";
          };
          kernelModules = [
            {
              module = "kvm";
              feature = "virtualization";
              requirement = "required";
              gate = "always";
              sysctls = [ ];
              jailVisibleDevice = false;
            }
            {
              module = "kvm_intel";
              feature = "virtualization";
              requirement = "alternatives";
              gate = "host-cpu-vendor=intel";
              sysctls = [ ];
              jailVisibleDevice = false;
            }
          ];
          fdOwnership = [ ];
          cloudHypervisorCapabilities = [ ];
        });
        fixtureProcessesJson = pkgs.writeText "d2b-fixture-processes.json"
          (builtins.toJSON {
            schemaVersion = "v2";
            vms = [ ];
          });
        fixtureManifest = pkgs.writeText "d2b-fixture-manifest.json"
          (builtins.toJSON {
            _manifest = {
              manifestVersion = 7;
            };
            _observability = {
              enabled = false;
              obsVsockCid = 1000;
              obsVsockHostSocket = "/var/lib/d2b/vms/sys-obs/vsock.sock";
              signozOtlpGrpcPort = 4317;
              signozOtlpHttpPort = 4318;
              signozUrl = "http://127.0.0.1:8080";
              vmName = "sys-obs";
            };
          });
        fixtureClosure = pkgs.writeText "d2b-fixture-corp-vm-closure.json"
          (builtins.toJSON {
            schemaVersion = "v3";
            vm = "corp-vm";
            toplevel = "/nix/store/d2b-corp-vm-system";
            closurePaths = [ "/nix/store/d2b-corp-vm-system" ];
            dbDumpPath = "/var/lib/d2b/vms/corp-vm/store-view/db-dump";
            declaredRunner = "/run/current-system/sw/bin/cloud-hypervisor";
            runnerParityPath = "/run/current-system/sw/bin/cloud-hypervisor";
            runnerParityOk = true;
            generation = {
              hostGeneration = null;
              vmGeneration = null;
              sourceRevision = null;
              generatedAt = null;
            };
          });
        fixtureBundleDataWithoutHash = {
          bundleVersion = 11;
          schemaVersion = "v2";
          publicManifestPath = "manifest.json";
          hostPath = "host.json";
          processesPath = "processes.json";
          privilegesPath = "privileges.json";
          closures = [
            {
              vm = "corp-vm";
              path = "closures/corp-vm.json";
            }
          ];
          minijailProfiles = [ ];
          managedKeys = {
            keysDir = "/var/lib/d2b/keys";
            knownHostsPath = "/var/lib/d2b/known_hosts.d2b";
            overrides = [ ];
          };
          generation = {
            generator = "d2b-u15-fixture";
            sourceRevision = null;
            generatedAt = null;
          };
          bundleHash = null;
          artifactHashes = null;
        };
        fixtureBundle = fixtureBundleDataWithoutHash // {
          bundleHash = "sha256:${builtins.hashString "sha256"
            (builtins.toJSON (builtins.removeAttrs
              fixtureBundleDataWithoutHash [ "bundleHash" ]))}";
        };
        fixtureBundlePath = pkgs.writeText "d2b-fixture-bundle.json"
          (builtins.toJSON fixtureBundle);
        smokeFixture = let
          bundle = smokeEval.config.d2b._bundle;
        in pkgs.runCommand "d2b-fixture-smoke" { } ''
          mkdir -p $out/closures $out/zones/local-root
          cp ${fixtureHostJson} $out/host.json
          cp ${fixtureProcessesJson} $out/processes.json
          cp ${fixtureManifest} $out/manifest.json
          cp ${fixtureClosure} $out/closures/corp-vm.json
          cp ${bundle.privilegesJson.path} $out/privileges.json
          cp ${bundle.realmWorkloadsLauncherV2Json.path} $out/realm-workloads-launcher-v2.json
          cp ${fixtureBundlePath} $out/bundle.json
          cp ${bundle.zoneResourceBundles.local-root.path} $out/zones/local-root/resource-bundle.json
          cp ${bundle.extraArtifacts."zoneStorage-local-root".path} $out/zones/local-root/storage.json
        '';
        evalFixtureData = {
          minimal = renderEvalFixture {
            evaluated = smokeEval;
          };
          full = renderEvalFixture {
            evaluated = smokeEval;
          };
        };
        # Rust tests reach repo-level fixtures under tests/golden/
        # (compile-time
        # include_str! goldens) and tests/fixtures/ (compile-time +
        # runtime fixture-path reads from unit/integration tests).
        # Compose a sandbox src that holds packages/, the runtime schemas
        # embedded by provider crates, plus those fixture
        # trees so the cargo workspace never reads outside its packaged
        # source in the Nix sandbox. Operators running cargo OUTSIDE
        # the sandbox use the raw ./packages tree and the same relative
        # paths still resolve against the checkout.
        rustPackagesSrc = pkgs.runCommand "d2b-rust-src" { } ''
          mkdir -p $out/packages
          cp ${./Cargo.toml} $out/Cargo.toml
          cp ${./Cargo.lock} $out/Cargo.lock
          cp ${./deny.toml} $out/deny.toml
          cp -r ${./packages}/. $out/packages/
          mkdir -p $out/docs/reference/schemas/v3/providers
          cp ${./docs/reference/schemas/v3/providers/transport-azure-relay.transport-settings.json} \
            $out/docs/reference/schemas/v3/providers/transport-azure-relay.transport-settings.json
          cp ${./docs/reference/schemas/v3/providers/transport-vsock.transport-binding.json} \
            $out/docs/reference/schemas/v3/providers/transport-vsock.transport-binding.json
          mkdir -p $out/tests
          cp -r ${./tests/golden} $out/tests/golden
          cp -r ${./tests/fixtures} $out/tests/fixtures
        '';
        guestRustPackagesSrc = mkGuestRustPackagesSrc pkgs;
        rustWorkspace = args: pkgs.rustPlatform.buildRustPackage ({
          pname = "d2b-rust-workspace";
          version = "0.0.0-bootstrap";
          src = rustPackagesSrc;
          sourceRoot = "d2b-rust-src";
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes."wl-proxy-0.1.2" = "sha256-1yO1zgzSyzQ2DnDMpVxcnI5BsTNvXfzIUS+RNlPj4A8=";
          };
          # Repo-local .cargo/config.toml files set
          # `rustc-wrapper = "sccache"`, but the Nix sandbox doesn't
          # have sccache on PATH (and even if it did, sccache wants
          # a writable cache dir + network for distributed builds).
          # Disable the wrapper for sandbox builds. Operators running
          # cargo OUTSIDE the sandbox (worktrees, dev shells) still
          # get the sccache speedup from the config files.
          RUSTC_WRAPPER = "";
          SCCACHE_DIR = "";
        } // args);
        rustToolchainChannel =
          (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain.channel;
        brokerManifestToml = builtins.fromTOML (builtins.readFile ./packages/d2b-broker/Cargo.toml);
        mainManifestToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        assertRustToolchain = ''
          rustc --version | grep -F "${rustToolchainChannel}"
        '';
        assertRustSupplyChainInputs = ''
          test -f ${rustPackagesSrc}/Cargo.lock
          test -f ${rustPackagesSrc}/packages/Cargo.guest.lock
          test -f ${rustPackagesSrc}/deny.toml
          printf '%s\n' '${builtins.toJSON mainManifestToml.workspace.members}' >/dev/null
          printf '%s\n' '${brokerManifestToml.package.name}' >/dev/null
        '';

        # Pinned RustSec advisory DB snapshot for offline cargo-deny /
        # cargo-audit checks in the Nix sandbox.  Update the rev + hash
        # periodically to pick up new advisories.
        advisoryDbSrc = pkgs.fetchFromGitHub {
          owner = "rustsec";
          repo = "advisory-db";
          rev = "831c50f4a4304068f125e603add6a8839f08b3eb";
          hash = "sha256-wXKYURZz76ZC5lbuDA1oVQA/MxSB3pSJ1raF1HG0oIc=";
        };

        # cargo-deny and cargo-audit (via the rustsec crate) require the
        # advisory DB to be a git repository.  Wrap the fetchFromGitHub
        # source tree in a minimal git repo so gix::open succeeds.
        advisoryDbGit = pkgs.runCommand "rustsec-advisory-db-git" {
          nativeBuildInputs = [ pkgs.git ];
        } ''
          cp -r ${advisoryDbSrc} $out
          chmod -R u+w $out
          cd $out
          git init -q
          git add .
          git -c user.email=nixbld@localhost -c user.name=nixbld \
            commit -q -m 'advisory-db snapshot'
        '';

      in {
        eval-fixture-contracts =
          if system == "x86_64-linux" then
            (mkEvalOnlyCheck "eval-fixture-contracts" evalFixtureData) // {
              fixtureData = evalFixtureData;
            }
          else
            (pkgs.runCommand "d2b-eval-fixture-contracts-unsupported" { } ''
              echo "eval-fixture-contracts is x86_64-linux only (graphics gate)" > $out
            '') // {
              fixtureData = { };
            };
        fixture-smoke = smokeFixture;
        bazel-9_2_0-provider-smoke =
          import ./tests/unit/smoke/bazel-provider.nix {
            inherit pkgs bazel920 system;
          };

        eval-zone =
          let
            cfg = mkEval [ smokeConfigModule fixtureArtifactCatalogOverride ];
            observed = {
              assertionsGreen = pkgs.lib.all (a: a.assertion) cfg.config.assertions;
              zoneCount = builtins.length (builtins.attrNames cfg.config.d2b.zones);
              launcherArtifact =
                cfg.config.d2b._bundle.realmWorkloadsLauncherV2Json.installFileName;
            };
          in
          mkEvalOnlyCheck "eval-zone" (
            if observed.assertionsGreen
              && observed.zoneCount == 1
              && observed.launcherArtifact == "realm-workloads-launcher-v2.json"
            then observed
            else throw "eval-zone failed: ${builtins.toJSON observed}"
          );

        rust-build = rustWorkspace {
          pname = "d2b-rust-build";
          preBuild = assertRustToolchain;
          cargoBuildFlags = [ "--workspace" ];
          doCheck = false;
        };

        rust-tests = rustWorkspace {
          pname = "d2b-rust-tests";
          preBuild = assertRustToolchain;
          cargoBuildFlags = [ "--workspace" ];
          cargoTestFlags = [ "--workspace" ];
          installPhase = ''
            runHook preInstall
            mkdir -p $out
            echo ok > $out/rust-tests
            runHook postInstall
          '';
        };

        rust-clippy = rustWorkspace {
          pname = "d2b-rust-clippy";
          nativeBuildInputs = [ pkgs.clippy ];
          cargoBuildFlags = [ "--workspace" ];
          doCheck = false;
          buildPhase = ''
            runHook preBuild
            ${assertRustToolchain}
            cargo clippy --workspace --all-targets -- -D warnings
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out
            echo ok > $out/rust-clippy
            runHook postInstall
          '';
        };

        guest-static-elf = import ./tests/unit/smoke/guest-static-elf.nix {
          inherit system pkgs;
          flake = self;
        };

        # Build-level determinism proof for the Provider package catalog
        # emitter. The drift gate proves the generator's output matches what is
        # committed; only this proves it emits the same bytes across two
        # independent evaluations of the same input. The eval file throws on a
        # mismatch, so `nix flake check --no-build` fails at evaluation rather
        # than producing an unbuilt derivation.
        provider-catalog-determinism = let
          evidence = import ./tests/unit/smoke/provider-catalog-determinism-eval.nix {
            inherit system pkgs;
            flake = self;
          };
        in pkgs.runCommand "d2b-provider-catalog-determinism" {
          nativeBuildInputs = [ pkgs.nix pkgs.python3 ];
        } ''
          mkdir -p "$out"
          printf '%s\n' '${evidence}' > "$out/provider-catalog-determinism.json"
          python3 - "$out/provider-catalog-determinism.json" <<'PY'
          import json
          import subprocess
          import sys

          with open(sys.argv[1], encoding="utf-8") as handle:
              contract = json.load(handle)["digestContract"]
          entries = {
              entry["artifactId"]: entry["packageDigest"]
              for entry in contract["entries"]
          }
          provider_hash = subprocess.run(
              [
                  "nix",
                  "--extra-experimental-features",
                  "nix-command",
                  "hash",
                  "path",
                  "--type",
                  "sha256",
                  "--base16",
                  contract["providerPath"],
              ],
              check=True,
              capture_output=True,
              text=True,
          ).stdout.strip()
          expected_provider = "sha256:" + provider_hash
          if entries["provider-digest"] != expected_provider:
              raise SystemExit(
                  f"provider packageDigest {entries['provider-digest']} "
                  f"does not match NAR digest {expected_provider}"
              )
          if entries["system-digest"] != contract["systemExpected"]:
              raise SystemExit(
                  f"system packageDigest {entries['system-digest']} "
                  f"does not match path-and-content digest "
                  f"{contract['systemExpected']}"
              )
          system_nar = "sha256:" + subprocess.run(
              [
                  "nix",
                  "--extra-experimental-features",
                  "nix-command",
                  "hash",
                  "path",
                  "--type",
                  "sha256",
                  "--base16",
                  contract["systemPath"],
              ],
              check=True,
              capture_output=True,
              text=True,
          ).stdout.strip()
          if entries["system-digest"] == system_nar:
              raise SystemExit(
                  "system packageDigest unexpectedly used the Provider NAR mode"
              )
          PY
        '';

        guest-static-consumption = let
          evidence = import ./tests/unit/smoke/guest-static-consumption-eval.nix {
            inherit system pkgs;
            flake = self;
          };
        in pkgs.runCommand "d2b-guest-static-consumption" { } ''
          mkdir -p "$out"
          printf '%s\n' '${evidence}' > "$out/guest-static-consumption.json"
        '';

        # Real cargo-deny gate: bans, licenses, and sources for the
        # repository-root product workspace. Advisory checks are handled by
        # rust-audit below (cargo-deny requires
        # a fetchable URL for the advisory DB which is incompatible
        # with the Nix sandbox's no-network constraint).
        #
        # cargo-deny shells out to `cargo metadata`, so we vendor
        # the crate registry and override the sccache wrapper that
        # the repo-local .cargo/config.toml enables.
        rust-deny = let
          mainVendor = pkgs.rustPlatform.importCargoLock {
            lockFile = ./Cargo.lock;
            outputHashes."wl-proxy-0.1.2" = "sha256-1yO1zgzSyzQ2DnDMpVxcnI5BsTNvXfzIUS+RNlPj4A8=";
          };
          cargoConfig = vendorDir: ''
            [source.crates-io]
            replace-with = "vendored-sources"
            [source."git+https://github.com/vicondoa/wl-proxy.git?rev=072945b59fef21a2a8166460454280d543f48772#072945b59fef21a2a8166460454280d543f48772"]
            git = "https://github.com/vicondoa/wl-proxy.git"
            rev = "072945b59fef21a2a8166460454280d543f48772"
            replace-with = "vendored-sources"
            [source.vendored-sources]
            directory = "${vendorDir}"
          '';
        in pkgs.runCommand "d2b-rust-deny" {
          nativeBuildInputs = [ pkgs.cargo-deny pkgs.cargo pkgs.rustc ];
        } ''
          export HOME="$TMPDIR"

          run_deny() {
            local label=$1 src=$2 manifest=$3 vendor_cfg=$4 deny_cfg=$5
            local ws="$TMPDIR/$label"
            cp -r "$src/." "$ws"
            chmod -R u+w "$ws"
            # Override all .cargo/config.toml files to disable sccache
            # and enable vendored dependencies.
            find "$ws" -path '*/.cargo/config.toml' -exec sh -c \
              'printf "%s\n" "$1" > "$0"' {} "$vendor_cfg" \;
            mkdir -p "$ws/.cargo"
            printf '%s\n' "$vendor_cfg" > "$ws/.cargo/config.toml"
            echo "==> cargo deny check ($label)"
            cargo-deny --manifest-path "$ws/$manifest" \
              check --config "$deny_cfg" bans licenses sources
            rm -rf "$ws"
          }

          run_deny "main" \
            "${rustPackagesSrc}" \
            "Cargo.toml" \
            '${cargoConfig mainVendor}' \
            "${rustPackagesSrc}/deny.toml"

          echo ok > $out
        '';

        guest-rust-deny = let
          guestVendor = pkgs.rustPlatform.importCargoLock {
            lockFile = ./packages/Cargo.guest.lock;
            outputHashes."wl-proxy-0.1.2" = "sha256-1yO1zgzSyzQ2DnDMpVxcnI5BsTNvXfzIUS+RNlPj4A8=";
          };
          cargoConfig = ''
            [source.crates-io]
            replace-with = "vendored-sources"
            [source."git+https://github.com/vicondoa/wl-proxy.git?rev=072945b59fef21a2a8166460454280d543f48772#072945b59fef21a2a8166460454280d543f48772"]
            git = "https://github.com/vicondoa/wl-proxy.git"
            rev = "072945b59fef21a2a8166460454280d543f48772"
            replace-with = "vendored-sources"
            [source.vendored-sources]
            directory = "${guestVendor}"
          '';
        in pkgs.runCommand "d2b-guest-rust-deny" {
          nativeBuildInputs = [ pkgs.cargo-deny pkgs.cargo pkgs.rustc ];
        } ''
          export HOME="$TMPDIR"
          ws="$TMPDIR/guest"
          cp -r "${guestRustPackagesSrc}/packages" "$ws"
          chmod -R u+w "$ws"
          mkdir -p "$ws/.cargo"
          printf '%s\n' '${cargoConfig}' > "$ws/.cargo/config.toml"
          cargo-deny --manifest-path "$ws/Cargo.toml" \
            check             --config "${rustPackagesSrc}/deny.toml" bans licenses sources
          echo ok > "$out"
        '';

        # Real cargo-audit gate: vulnerability scan of each checked-in
        # context policy lock against the pinned advisory DB snapshot. The
        # filtered locks are audit-only projections; Cargo resolution still
        # uses the repository-root lock. Advisory ignores, when approved,
        # are read only from the matching protected context.
        rust-audit = pkgs.runCommand "d2b-rust-audit" {
          nativeBuildInputs = [ pkgs.cargo-audit pkgs.jq ];
        } ''
          export HOME="$TMPDIR"
          policy_root=${rustPackagesSrc}/packages/policy-inputs
          advisory_policy=$policy_root/advisory-policy.json
          run_audit() {
            local lock=$1 context_key=$2 advisory_id
            shift 2
            local -a ignores=()
            if [ -n "$context_key" ]; then
              while IFS= read -r advisory_id; do
                [ -n "$advisory_id" ] && ignores+=(--ignore "$advisory_id")
              done < <(
                jq -r \
                  --arg context_key "$context_key" \
                  '.contexts[$context_key].advisories[]?.id' \
                  "$advisory_policy"
              )
            fi
            echo "==> cargo audit ($context_key)"
            cargo-audit audit --file "$lock" \
              --db ${advisoryDbGit} --no-fetch \
              "''${ignores[@]}" "$@"
          }
          while IFS= read -r lock; do
            relative="''${lock#"$policy_root"/}"
            IFS=/ read -r system target context _projection _lock <<< "$relative"
            run_audit "$lock" "$system/$target/$context"
          done < <(
            find "$policy_root" -type f -path '*/policy/Cargo.lock' | LC_ALL=C sort
          )
          run_audit ${rustPackagesSrc}/packages/Cargo.guest.lock ""
          echo ok > $out
        '';

        guest-static-dependency-policy =
          pkgs.runCommand "d2b-guest-static-dependency-policy" { } ''
            lock=${./packages/Cargo.guest.lock}
            if grep -E 'name = "(cc|cmake|pkg-config|openssl|openssl-sys|native-tls|libsystemd|systemd)"' "$lock"; then
              echo "guest static lock contains a native-link/build-script dependency" >&2
              exit 1
            fi
            echo ok > "$out"
          '';

        guest-shell-runner-static-dependency-policy =
          pkgs.runCommand "d2b-guest-shell-runner-static-dependency-policy" { } ''
            lock=${./Cargo.lock}
            if grep -E 'name = "(openssl|openssl-sys|native-tls|libsystemd|systemd|pam-sys|dlopen2)"' "$lock"; then
              echo "guest shell runner lock contains a forbidden dynamic/PAM/systemd dependency" >&2
              exit 1
            fi
            if ! grep -A6 'name = "motd"' "$lock" | grep -F 'version = "0.2.2"' >/dev/null; then
              echo "guest shell runner lock must pin the expected PAM-free motd dependency posture" >&2
              exit 1
            fi
            echo ok > "$out"
          '';

        harness-ubuntu-skeleton = (import ./harness/ubuntu/default.nix) {
          pkgs = nixpkgsFor.${system};
        };

      });

      lib = nixpkgs.lib.makeExtensible (_: {
        evalFixture = system: self.checks.${system}.eval-fixture-contracts.fixtureData;
        buildProviderElfShim = providerElfShim;
        providerMatrix =
          (import ./nixos-modules/generated/provider-catalog-shape.nix)
            .providerMatrix;
        providerIds =
          (import ./nixos-modules/generated/provider-catalog-shape.nix)
            .providerIds;
        providerArtifactLayout =
          (import ./nixos-modules/generated/provider-catalog-shape.nix)
            .artifactLayout;
        mkProviderArtifact = args:
          let
            system = args.system or builtins.currentSystem;
            providerPkgs = args.pkgs or nixpkgsFor.${system};
            helperArgs = builtins.removeAttrs args [ "pkgs" "system" ];
          in
          (import ./nix/provider-artifact.nix {
            pkgs = providerPkgs;
          }) helperArgs;
        buildProviderArtifact = args: self.lib.mkProviderArtifact args;
        providerRuntimeCloudHypervisor = system:
          let
            package = self.packages.${system}.d2b-provider-runtime-cloud-hypervisor;
            metadata = package.passthru.providerArtifact;
          in {
            inherit package;
            inherit (metadata) catalog trustedPublisher;
            descriptor = {
              package = package;
              type = "provider";
              inherit (metadata) catalog;
            };
          };
        evalGuest = {
          system ? builtins.currentSystem,
          d2bHostToolOverrides ? null,
          extraSpecialArgs ? { },
          nixpkgsConfig ? { },
          nixpkgsOverlays ? [ ],
          ...
        }@args:
          let
            guestInputs = inputs // { inherit self; };
            guestPkgs = nixpkgsFor.${system};
            guestTools = {
              broker = self.packages.${system}.d2b-broker-guest-static;
              d2bd = self.packages.${system}.d2bd-guest-static;
              d2b-guest-shell-runner-static =
                self.packages.${system}.d2b-guest-shell-runner-static;
            };
            evaluator = (import ./nixos-modules/vm-evaluator.nix {
              inputs = guestInputs;
            }) {
              config = {
                d2b.site = {
                  inherit extraSpecialArgs;
                  usePrebuiltHostTools = false;
                };
                nixpkgs = {
                  config = nixpkgsConfig;
                  overlays = nixpkgsOverlays;
                };
              };
              lib = guestPkgs.lib;
              pkgs = guestPkgs;
              d2bHostTools = guestTools;
              inherit d2bHostToolOverrides;
            };
          in
          evaluator._evalGuest (builtins.removeAttrs args [
            "system"
            "d2bHostToolOverrides"
            "extraSpecialArgs"
            "nixpkgsConfig"
            "nixpkgsOverlays"
          ]);
      });

    };
}
