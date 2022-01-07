{
  inputs.nixpgks.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.flake-utils = {
    url = "github:numtide/flake-utils";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        inherit (nixpkgs) lib;
        pkgs = nixpkgs.legacyPackages.${system};
        buildTools = [ pkgs.cmake pkgs.ninja pkgs.gcc ];
        dependencies = [ pkgs.ncurses pkgs.openssl pkgs.jansson ];
        runTests = false;
      in rec {
        packages = {
          libdict = pkgs.stdenv.mkDerivation {
            pname = "libdict";
            version = "1.0.1";

            src = pkgs.fetchFromGitHub {
              owner = "rtbrick";
              repo = "libdict";
              rev = "fea9fb240cfa08dc3bbfe425fb78466dbbf1aa56";
              sha256 = "rnAvurPnmILMAB3Ingjw0lRJB6lcjdmUtPO6R3ek6e4=";
            };

            cmakeFlags = [
              "-DCMAKE_BUILD_TYPE=Release"
              "-DLIBDICT_STATIC=YES"
              "-DLIBDICT_TOOLS=NO"
              "-DLIBDICT_TESTS=NO"
              "-DLIBDICT_SHARED=YES"
            ];

            doCheck = false;

            checkInputs = [ pkgs.cunit ];
            nativeBuildInputs = buildTools;

          };
          bngblaster = pkgs.stdenv.mkDerivation rec {
            pname = "bngblaster";
            version = "0.52";
            src = lib.cleanSource ./.;

            doCheck = true;
            cmakeFlags = [ "-DCMAKE_BUILD_TYPE=Release" ]
              ++ (if doCheck then [ "-DBNGBLASTER_TESTS=ON" ] else [ ]);

            checkInputs = [ pkgs.cmocka pkgs.libpcap ];
            nativeBuildInputs = buildTools;
            buildInputs = dependencies ++ [ packages.libdict ];
          };
        };
        devShell = pkgs.mkShell {
          nativeBuildInputs = buildTools;
          buildInputs = dependencies
            ++ [ packages.libdict pkgs.bashInteractive ];

          shellHook = ''
            cmake -DEXPORT_COMPILE_COMMANDS=ON ./build
            ln -s ./build/compile_commands.json ./compile_commands.json &1>/dev/null
          '';
        };
        defaultPackage = packages.bngblaster;
        apps.bngblaster = flake-utils.lib.mkApp { drv = packages.bngblaster; };
        defaultApp = apps.bngblaster;
      });
}
