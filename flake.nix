{
  description = "sphinx identity-aware secret guardian";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
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
          vendorHash = "sha256-xwkkLn5Ss4A86PukLHIYmX5loGsuNtSs+lMh+lyH8XU=";
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postInstall = ''
            wrapProgram "$out/bin/sphinx" \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.git ]}
          '';
          meta = {
            description = "Identity-aware guardian controlling access to relics";
            homepage = "https://github.com/marksisson/sphinx";
            mainProgram = "sphinx";
            platforms = nixpkgs.lib.platforms.unix;
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
