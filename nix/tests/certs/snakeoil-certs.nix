# This directory aggregates snakeoil certificates.

# This script generates self-signed certificates (referred to as "snakeoil" certificates) 
# for testing or development purposes only. These certificates are NOT TRUSTED by 
# browsers or clients and should NEVER be used in production environments. Use them 
# solely for local testing. For internal services, generate YOUR OWN certificates.

let
  proxyCerts = import ./portail.corp/snakeoil-certs.nix;
  workloadCerts = import ./hello.corp/snakeoil-certs.nix;
in
{
  inherit proxyCerts workloadCerts;
}
