{
    inputs = {
        nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
        flake-utils.url = "github:numtide/flake-utils";

        rust-overlay = {
            url = "github:oxalica/rust-overlay";
            inputs.nixpkgs.follows = "nixpkgs";
        };
    };

    outputs = { self, nixpkgs, flake-utils, rust-overlay }:
        flake-utils.lib.eachDefaultSystem (system:
            let
                pkgs = import nixpkgs {
                    inherit system;

                    overlays = [ rust-overlay.overlays.default ];
                };

                config = pkgs.lib.importTOML ./Cargo.toml;

            in {
                packages.default = pkgs.rustPlatform.buildRustPackage {
                    pname = config.package.name;
                    version = config.package.version;

                    src = ./.;
                    cargoLock.lockFile = ./Cargo.lock;

                    meta = with pkgs.lib; {
                        description = config.package.description;
                        homepage = config.package.homepage;
                        license = licenses.gpl3Only;

                        maintainers = [
                            {
                                name = "Nikita Podvirnyi";
                                email = "krypt0nn@vk.com";
                                matrix = "@krypt0nn:mozilla.org";
                                github = "krypt0nn";
                                githubId = 29639507;
                            }
                        ];
                    };

                    nativeBuildInputs = with pkgs; [
                        rust-bin.stable.latest.minimal
                        gcc
                        pkg-config
                    ];
                };

                devShells.default = pkgs.mkShell {
                    nativeBuildInputs = with pkgs; [
                        (rust-bin.stable.latest.default.override {
                            extensions = [ "rust-src" ];
                        })

                        gcc
                        pkg-config
                    ];
                };
            });
}
