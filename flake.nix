{
  description = "LocalWebAuthn passkey-only authentication packages";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            bash
            bash-completion
            cacert
            git
            gnumake
            nodejs_22
            sqlite
          ];

          shellHook = ''
            echo "LocalWebAuthn Development Environment"
            echo ""
            printf "  %-12s %s\n" "node" "$(node --version 2>/dev/null)"
            printf "  %-12s %s\n" "npm" "$(npm --version 2>/dev/null)"
            printf "  %-12s %s\n" "sqlite" "$(sqlite3 --version 2>/dev/null | cut -d' ' -f1)"

            if [ ! -d node_modules ] && [ -f package-lock.json ]; then
              echo ""
              echo "[flake] installing npm dependencies ..."
              npm ci --no-audit --no-fund --loglevel=error
            fi

            echo ""
            echo "Commands: make build | make test | make check"
          '';
        };
      });
}
