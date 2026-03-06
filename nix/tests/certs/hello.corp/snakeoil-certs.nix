# This script generates self-signed certificates (referred to as "snakeoil" certificates) 
# for testing or development purposes only. These certificates are NOT TRUSTED by 
# browsers or clients and should NEVER be used in production environments. Use them 
# solely for local testing. For internal services, generate YOUR OWN certificates.

# To generate snakeoil cert files:
# cp $(nix-build '<nixpkgs/nixos/tests/common/acme/server/generate-certs.nix>' --arg domain '(import ./snakeoil-certs.nix).workloadDomain' --no-out-link)/* .
# WARNING: if the nix-build invocation fails, you may have `cp /* .` which will copy your rootfs in the cwd.
# Exercise caution while executing.

let
  workloadDomain = "hello.corp.example.com";
in
{
  inherit workloadDomain;
  ca = {
    cert = ./ca.cert.pem;
    key = ./ca.key.pem;
  };
  ${workloadDomain} = {
    cert = ./${workloadDomain}.cert.pem;
    key = ./${workloadDomain}.key.pem;
  };
}
