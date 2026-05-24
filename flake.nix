{

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    {
      self,
      nixpkgs,
      ...
    }:
    let
      inherit (nixpkgs) lib;
      forEachSystem = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsForEach = nixpkgs.legacyPackages;
    in
    {
      nixosModules = {
        custos = ./nix/module.nix;
        default = self.nixosModules.custos;
      };

      packages = forEachSystem (
        system:
        let
          pkgs = pkgsForEach.${system};
          custos = pkgs.callPackage ./nix/package.nix { };
        in
        {
          inherit custos;
          default = custos;
        }
      );

      apps = forEachSystem (system: {
        custos = {
          type = "app";
          program = "${self.packages.${system}.custos}/bin/custos";
          meta.description = "Run the custos USB authorization CLI";
        };
        default = self.apps.${system}.custos;
      });

      devShells = forEachSystem (system: {
        default = pkgsForEach.${system}.callPackage ./nix/shell.nix { };
      });
    };
}
