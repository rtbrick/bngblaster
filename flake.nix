{
  description = "BNG Blaster - network tester for access and routing protocols";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }: let
    # BNG Blaster supports Linux only.
    linuxSystems = ["x86_64-linux" "aarch64-linux"];
  in
    flake-utils.lib.eachSystem linuxSystems (system: let
      inherit (nixpkgs) lib;
      pkgs = nixpkgs.legacyPackages.${system};
      buildTools = [pkgs.cmake pkgs.ninja];
      dependencies = [pkgs.ncurses pkgs.openssl pkgs.jansson];
      testDependencies = [pkgs.cmocka pkgs.libpcap];
      # Interpreter for bngblaster-cli, bgpupdate and ldpupdate.
      python = pkgs.python3.withPackages (ps: [ps.scapy]);
      gitRef = self.shortRev or self.dirtyShortRev or "dirty";
      gitSha = self.rev or self.dirtyRev or "dirty";
    in rec {
      formatter = pkgs.alejandra;

      packages = {
        libdict = pkgs.stdenv.mkDerivation {
          pname = "libdict";
          version = "1.0.6";

          src = pkgs.fetchFromGitHub {
            owner = "rtbrick";
            repo = "libdict";
            rev = "1.0.6";
            hash = "sha256-JO8gIZwSZ1vOigiM2IoGRYW2m2zoAa1af/eMBP3ZRjY=";
          };

          cmakeFlags = [
            "-DCMAKE_BUILD_TYPE=Release"
            "-DLIBDICT_STATIC=YES"
            "-DLIBDICT_SHARED=YES"
            "-DLIBDICT_TOOLS=NO"
            "-DLIBDICT_TESTS=NO"
          ];

          nativeBuildInputs = buildTools;
        };

        # Unit tests can be disabled with
        # bngblaster.overrideAttrs { doCheck = false; }
        bngblaster = pkgs.stdenv.mkDerivation (finalAttrs: {
          pname = "bngblaster";
          version = gitRef;
          src = lib.cleanSource ./.;

          doCheck = true;
          cmakeFlags =
            [
              "-DCMAKE_BUILD_TYPE=Release"
              "-DGIT_REF=${gitRef}"
              "-DGIT_SHA=${gitSha}"
            ]
            ++ lib.optional finalAttrs.doCheck "-DBNGBLASTER_TESTS=ON";

          nativeBuildInputs = buildTools;
          buildInputs = dependencies ++ [packages.libdict python];
          checkInputs = testDependencies;
        });

        default = packages.bngblaster;
      };

      devShells.default = pkgs.mkShell {
        packages = buildTools ++ dependencies ++ testDependencies ++ [packages.libdict python];
      };

      apps = {
        bngblaster =
          flake-utils.lib.mkApp {drv = packages.bngblaster;}
          // {meta.description = "BNG Blaster network tester";};
        lspgen =
          flake-utils.lib.mkApp {
            drv = packages.bngblaster;
            name = "lspgen";
          }
          // {meta.description = "Link state packet generator for ISIS and OSPF";};
        default = apps.bngblaster;
      };
    });
}
