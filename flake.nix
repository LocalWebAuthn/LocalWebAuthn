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

        # Throwaway PostgreSQL for the store conformance tests. Listens on
        # 127.0.0.1 only, with Unix sockets disabled: the absolute socket path
        # in a deep checkout can exceed the 103-byte limit on macOS.
        pgPort = "55432";
        pgData = ".pgdata";
        pgUrl = "postgres://postgres@127.0.0.1:${pgPort}/localwebauthn_test";

        pg-start = pkgs.writeShellScriptBin "pg-start" ''
          set -euo pipefail
          if [ -d "${pgData}" ] && ${pkgs.postgresql_17}/bin/pg_ctl -D "${pgData}" status >/dev/null 2>&1; then
            echo "PostgreSQL already running on port ${pgPort}"
            exit 0
          fi
          if [ ! -d "${pgData}" ]; then
            echo "Initializing ${pgData} ..."
            ${pkgs.postgresql_17}/bin/initdb -D "${pgData}" -U postgres --auth=trust -E UTF8 >/dev/null
          fi
          ${pkgs.postgresql_17}/bin/pg_ctl -D "${pgData}" -l "${pgData}/server.log" \
            -o "-p ${pgPort} -c listen_addresses=127.0.0.1 -c unix_socket_directories=" start
          until ${pkgs.postgresql_17}/bin/pg_isready -h 127.0.0.1 -p ${pgPort} -q; do sleep 0.2; done
          ${pkgs.postgresql_17}/bin/psql -h 127.0.0.1 -p ${pgPort} -U postgres -tAc \
            "SELECT 1 FROM pg_database WHERE datname='localwebauthn_test'" \
            | grep -q 1 || ${pkgs.postgresql_17}/bin/createdb -h 127.0.0.1 -p ${pgPort} -U postgres localwebauthn_test
          echo "PostgreSQL ready: ${pgUrl}"
        '';

        pg-stop = pkgs.writeShellScriptBin "pg-stop" ''
          set -euo pipefail
          if [ -d "${pgData}" ]; then
            ${pkgs.postgresql_17}/bin/pg_ctl -D "${pgData}" stop -m fast || true
          fi
        '';
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            bash
            bash-completion
            cacert
            git
            gnumake
            nodejs_22
            postgresql_17
            sqlite
            pg-start
            pg-stop
          ];

          # Consumed by tests/server/store-conformance.test.ts. When the server
          # is not running the PostgreSQL suite skips instead of failing, so a
          # plain `make test` still works without `pg-start`.
          LOCALWEBAUTHN_TEST_POSTGRES_URL = pgUrl;

          shellHook = ''
            echo "LocalWebAuthn Development Environment"
            echo ""
            printf "  %-12s %s\n" "node" "$(node --version 2>/dev/null)"
            printf "  %-12s %s\n" "npm" "$(npm --version 2>/dev/null)"
            printf "  %-12s %s\n" "sqlite" "$(sqlite3 --version 2>/dev/null | cut -d' ' -f1)"
            printf "  %-12s %s\n" "postgres" "$(pg_ctl --version 2>/dev/null | awk '{print $NF}')"

            if [ ! -d node_modules ] && [ -f package-lock.json ]; then
              echo ""
              echo "[flake] installing npm dependencies ..."
              npm ci --no-audit --no-fund --loglevel=error
            fi

            echo ""
            echo "Commands: make demo | make build | make test | make check"
            echo "PostgreSQL tests: pg-start (then make test) | pg-stop"
          '';
        };
      });
}
