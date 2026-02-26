{
  description = "Kilo is a multi-cloud network overlay built on WireGuard and designed for Kubernetes (k8s + wg = kg)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    git-hooks-nix = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, ... }@inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.git-hooks-nix.flakeModule
      ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      perSystem =
        {
          pkgs,
          system,
          config,
          ...
        }:
        {
          packages =
            let
              _version = builtins.getEnv "VERSION";
              homepage = "https://github.com/squat/kilo";
              base = pkgs.buildGoModule (finallAttrs: {
                pname = "kilo";
                version = if _version != "" then _version else toString (self.rev or self.dirtyRev or "unknown");
                src = ./.;
                vendorHash = null;
                env.CGO_ENABLED = 0;
                ldflags = [
                  "-X github.com/squat/kilo/pkg/version.Version=${finallAttrs.version}"
                ];
                nativeBuildInputs = [ pkgs.installShellFiles ];
                meta = {
                  inherit homepage;
                };
              });
              kg = base.overrideAttrs {
                pname = "kg";
                subPackages = [
                  "cmd/kg"
                ];
                postInstall = ''
                  installShellCompletion --cmd kg \
                    --bash <($out/bin/kg completion bash) \
                    --fish <($out/bin/kg completion fish) \
                    --zsh <($out/bin/kg completion zsh)
                '';
                meta.mainProgram = "kg";
                meta.description = "kg is the Kilo agent that runs on every Kubernetes node in a Kilo mesh";
              };

              kgctl = base.overrideAttrs {
                pname = "kgctl";
                subPackages = [
                  "cmd/kgctl"
                ];
                postInstall = ''
                  installShellCompletion --cmd kgctl \
                    --bash <($out/bin/kgctl completion bash) \
                    --fish <($out/bin/kgctl completion fish) \
                    --zsh <($out/bin/kgctl completion zsh)
                '';
                meta.mainProgram = "kgctl";
                meta.description = "kgctl is Kilo's command line tool for inspecting and interacting with clusters: kgctl. It can be used to understand a mesh's topology, get the WireGuard configuration for a peer, or graph a cluster";

              };

              kilo = pkgs.symlinkJoin {
                name = "kilo";
                paths = [
                  kg
                  kgctl
                ];
                meta = {
                  inherit homepage;
                  description = "Kilo is a multi-cloud network overlay built on WireGuard and designed for Kubernetes (k8s + wg = kg)";
                };
              };

            in
            {
              inherit kg kgctl kilo;
              default = kilo;
            }
            // (builtins.listToAttrs (
              map
                (target: {
                  name = "kg-cross-${target.os}-${target.arch}";
                  value = kg.overrideAttrs (
                    _: oldAttrs: {
                      env = oldAttrs.env // {
                        GOOS = target.os;
                        GOARCH = target.arch;
                        CGO_ENABLED = 0;
                      };
                      checkPhase = false;
                      postInstall = "";
                    }
                  );
                })
                [
                  {
                    os = "linux";
                    arch = "amd64";
                  }
                  {
                    os = "linux";
                    arch = "arm64";
                  }
                  {
                    os = "linux";
                    arch = "arm";
                  }
                ]
            ))
            // (builtins.listToAttrs (
              map
                (target: {
                  name = "kgctl-cross-${target.os}-${target.arch}";
                  value = kgctl.overrideAttrs (
                    _: oldAttrs: {
                      env = oldAttrs.env // {
                        GOOS = target.os;
                        GOARCH = target.arch;
                        CGO_ENABLED = 0;
                      };
                      checkPhase = false;
                      postInstall = "";
                    }
                  );
                })
                [
                  {
                    os = "linux";
                    arch = "amd64";
                  }
                  {
                    os = "linux";
                    arch = "arm64";
                  }
                  {
                    os = "linux";
                    arch = "arm";
                  }
                  {
                    os = "darwin";
                    arch = "amd64";
                  }
                  {
                    os = "darwin";
                    arch = "arm64";
                  }
                  {
                    os = "windows";
                    arch = "amd64";
                  }
                ]
            ))
            // (builtins.listToAttrs (
              map
                (target: {
                  name = "kilo-cross-${target.os}-${target.arch}";
                  value = kilo.overrideAttrs {
                    paths = [
                      config.packages."kg-cross-${target.os}-${target.arch}"
                      config.packages."kgctl-cross-${target.os}-${target.arch}"
                    ];
                  };
                })
                [
                  {
                    os = "linux";
                    arch = "amd64";
                  }
                  {
                    os = "linux";
                    arch = "arm64";
                  }
                  {
                    os = "linux";
                    arch = "arm";
                  }
                ]
            ));

          pre-commit = {
            check.enable = true;
            settings = {
              src = ./.;
              hooks = {
                actionlint.enable = true;
                nixfmt.enable = true;
                nixfmt.excludes = [ "vendor" ];
                gofmt.enable = true;
                gofmt.excludes = [ "vendor" ];
                golangci-lint.enable = true;
                golangci-lint.excludes = [ "vendor" ];
                golangci-lint.extraPackages = [ pkgs.go ];
                govet.enable = true;
                govet.excludes = [ "vendor" ];
                shellcheck.enable = true;
                shellcheck.excludes = [
                  ".envrc"
                  "vendor"
                ];
                yamlfmt.enable = true;
                yamlfmt.args = [
                  "--formatter"
                  "indentless_arrays=true"
                ];
                yamlfmt.excludes = [
                  ".github"
                  "vendor"
                ];
                header = {
                  enable = true;
                  name = "Header";
                  entry =
                    let
                      headerCheck = pkgs.writeShellApplication {
                        name = "header-check";
                        text = ''
                          HEADER=$(cat ${./.header})
                          HEADER_LEN=$(wc -l ${./.header} | awk '{print $1}')
                          FILES=
                          for f in "$@"; do 
                              for i in 0 1 2 3 4 5; do 
                                  FILE=$(tail -n +$i "$f" | ( head -n "$HEADER_LEN"; cat > /dev/null ) | sed "s/[0-9]\{4\}/YEAR/")
                                  [ "$FILE" = "$HEADER" ] && continue 2
                              done
                              FILES="$FILES$f "
                          done
                          if [ -n "$FILES" ]; then \
                              printf 'the following files are missing the license header: %s\n' "$FILES"; \
                              exit 1
                          fi
                        '';
                      };
                    in
                    pkgs.lib.getExe headerCheck;
                  files = "\\.(go)$";
                  excludes = [ "vendor" ];
                };
                kgMDGen = {
                  enable = true;
                  name = "kg.md";
                  entry =
                    let
                      kgMDGen = pkgs.writeShellApplication {
                        name = "kgmdgen";
                        text = ''
                          go run ./cmd/kg/... --help | head -n -2 > help.txt
                          go tool embedmd -d docs/kg.md
                        '';
                      };
                    in
                    pkgs.lib.getExe kgMDGen;
                  files = "^README\\.md$";
                  extraPackages = [ pkgs.go ];
                };
              };
            };
          };

          devShells = {
            default = pkgs.mkShell {
              inherit (config.pre-commit.devShell) shellHook;
              packages =
                with pkgs;
                [
                  bash_unit
                  (config.packages.kgctl.overrideAttrs (finallAttrs: {
                    version = "dev";
                    __intentionallyOverridingVersion = true;
                    ldflags = [
                      "-X github.com/squat/kilo/pkg/version.Version=${finallAttrs.version}"
                    ];
                  }))
                  gettext # provides envsubst
                  go
                  kind
                  kubectl
                  yarn
                ]
                ++ config.pre-commit.settings.enabledPackages;
            };
          };
        };
    };
}
