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
          buildGo126Module = pkgs.buildGoModule.override { go = pkgs.go_1_26; };
        in
        buildGo126Module {
          pname = "sphinx";
          version = "0.1.0";
          src = ./.;
          subPackages = [ "cmd/sphinx" ];
          vendorHash = "sha256-vGSc35RLCH98ragZcKxb72Q3v11LacoUVZoyuXprTB0=";
          nativeCheckInputs = [ pkgs.git ];
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
            SPHINX_CODESIGN_IDENTITY = "Developer ID Application: Razorrock LLC (3ZFD84NJ64)";
            SPHINX_NOTARY_PROFILE = "RazorrockNotary";
            packages = with pkgs; [
              git
              go_1_26
              gopls
            ];
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
