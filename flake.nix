{
  description = "Sphinx CLI for proclamation-signed Git tombs";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      systems = [ "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
      sphinxFor =
        system:
        let
          pkgs = pkgsFor system;
        in
        pkgs.buildGoModule {
          pname = "sphinx";
          version = "0.1.0";
          src = ./.;
          subPackages = [ "cmd/sphinx" ];
          vendorHash = "sha256-Pq1ePAmVbV6BUJDjsVl7zTXkC+aeUpLcAfKx7gH/F0o=";
          nativeBuildInputs = [
            pkgs.git
            pkgs.makeWrapper
          ];
          postInstall = ''
            wrapProgram "$out/bin/sphinx" \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.git ]}
          '';
          meta = {
            description = "Local CLI for signed Git tombs and identity-aware artifact reveal";
            homepage = "https://github.com/marksisson/sphinx";
            mainProgram = "sphinx";
            platforms = [ "aarch64-darwin" ];
          };
        };
    in
    {
      packages = forAllSystems (system: {
        default = sphinxFor system;
        sphinx = sphinxFor system;
      });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${sphinxFor system}/bin/sphinx";
        };
        sphinx = {
          type = "app";
          program = "${sphinxFor system}/bin/sphinx";
        };
      });

      checks = forAllSystems (system: {
        sphinx = sphinxFor system;
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              git
              go
              gopls
            ];
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
