{
  description = "mcp-oauth-proxy — development shell";

  # Pinned by flake.lock. `nix flake update` moves it; the lock is what makes the shell reproducible.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        # `nix develop` puts node and pnpm on PATH at the versions this package targets:
        # nodejs_22 matches the `engines.node` floor and the Dockerfile's base image, and pkgs.pnpm
        # matches the pinned `packageManager`. Corepack is deliberately not used here — it needs a
        # writable home and a network fetch, and it cannot switch versions once `packageManager` is set.
        default = pkgs.mkShell {
          packages = [
            pkgs.nodejs_22
            pkgs.pnpm
          ];

          # Only greet on an interactive shell; `nix develop --command ...` must not have its
          # output polluted by the banner.
          shellHook = ''
            if [ -t 1 ]; then
              echo "mcp-oauth-proxy dev shell — node $(node --version), pnpm $(pnpm --version)"
              echo "  pnpm install --frozen-lockfile && pnpm check && pnpm test"
            fi
          '';
        };
      });
    };
}
