{
  description = "chat-store - keypackage and account registry for Logos Chat";

  # Repeated from the logos-delivery flake: only the top-level flake's nixConfig
  # is honoured, so an input's substituters do nothing for us.
  nixConfig = {
    extra-substituters = [ "https://nix-cache.status.im/" ];
    extra-trusted-public-keys = [
      "nix-cache.status.im-1:x/93lOfLU+duPplwMSBR+OlY4+mo+dCN7n0mr4oPwgY="
    ];
  };

  inputs = {
    # Both revs are exactly what libchat's flake.lock pins, and they only work
    # as a pair: logos-delivery's derivation wants `nim-2_2`, which newer
    # nixos-unstable-small no longer has. Bump the two together.
    nixpkgs.url = "github:NixOS/nixpkgs/6f5e2d2ea55618c5197ce40e346f205c35d2213e";
    # `follows` keeps the library and the toolchain that links it on a single
    # glibc — the Docker build depends on that.
    logos-delivery = {
      url = "github:logos-messaging/logos-delivery/74057c66224f43b4aa27b42033d4ed52eed5c7a7";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, logos-delivery }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        inherit system;
        pkgs = import nixpkgs { inherit system; };
      });
    in
    {
      # The one thing this flake exists for: the native library the
      # `logos-delivery` crate links. Same override as libchat's flake — no
      # postgres archive driver, no Nim dlopen debug hooks, quiet logs.
      packages = forAllSystems ({ system, ... }: {
        logos-delivery = logos-delivery.packages.${system}.liblogosdelivery.override {
          enablePostgres = false;
          enableNimDebugDlOpen = false;
          chroniclesLogLevel = "FATAL";
        };
        default = self.packages.${system}.logos-delivery;
      });

      devShells = forAllSystems ({ pkgs, system, ... }:
        let logosDeliveryLib = self.packages.${system}.logos-delivery;
        in {
          default = pkgs.mkShell {
            nativeBuildInputs = [ pkgs.cargo pkgs.rustc pkgs.pkg-config ]
              # logos-delivery's build.rs rewrites the shipped library's soname
              # with patchelf in its default (absolute-path) linking mode.
              ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.patchelf ];
            buildInputs = [ logosDeliveryLib ];
            shellHook = ''
              export LOGOS_DELIVERY_LIB_DIR="${logosDeliveryLib}/lib"
            '';
          };
        });
    };
}
