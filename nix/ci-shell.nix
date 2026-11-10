# Copied from nikstur/bombon (MIT).
{ pkgs }:
pkgs.mkShell {
  packages = [
    pkgs.lixPackageSets.latest.nix-eval-jobs
  ];

  shellHook = ''
    eval-checks() {
      nix-eval-jobs ./nix/release.nix --check-cache-status | jq -s 'map({attr, isCached})'
    }
  '';
}
