{

  description = "Development environment for raaz, a fast and type safe cryptographic library in haskell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system};
          hpkgs = pkgs.haskell.packages.ghc942;
       in
        {
          devShell = pkgs.mkShell {
            buildInputs = [ pkgs.editorconfig-checker
                            hpkgs.ghc
                            ( hpkgs.ghcWithPackages  ( p: with p; [
                              cabal-install

                            ]))

                          ];
          };
        }
    );
}
