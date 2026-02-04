# Portail: an access proxy for terminals

> **Warning**: This project is under ongoing development. Features and functionality may change. Do not use in production.

## Why a new access proxy?

The landscape of open-source access proxies has stagnated in recent years. 

Tools like [Squid](https://megamansec.github.io/Squid-Security-Audit/) and [tinyproxy](https://github.com/tinyproxy/tinyproxy/issues?q=sort%3Aupdated-desc+is%3Aissue+is%3Aopen) have become inadequate for the terminal usage we do in Sécurix. We thank all the contributors and maintainers behind these projects for providing solutions for decades.

Instead of being a generic access proxy, Portail draws inspiration from [BeyondCorp research papers](https://research.google/pubs/beyondcorp-the-access-proxy/), aiming to build a more secure and flexible access proxy that works well alongside [Sécurix](https://github.com/cloud-gouv/securix).

## Design goals

### Proxy and protocol support

Portail plan to support usual proxy protocols, including SOCKS5 (TCP CONNECT, UDP ASSOCIATE) and HTTP CONNECT (1.1/2/3). 

There's optional mTLS support for secure communication between local and remote proxies. 
For proxied protocols, we focus on the most commonly used protocols on a terminal system: SSH, HTTPS, IMAP, SMTP, WebSocket, and WebRTC driven UDP.

### Access control and security

Portail includes an sophisticated ACL language that allows rules based on metadata such as device inventories, geo-fencing, risk assessments or the request itself. 
The system is designed for enabling redirects, logging, blocking, and more in future releases such as step up requests or challenges.

The proxy is meant to be **identity-aware**, supporting device and user attestation workflows for secure authentication. mTLS certificates and OIDC are meant to be combined for authentication and authorization. 

Additionally, structured audit logs are offered, with the ability to redirect users to error pages while preventing sensitive information leaks based on a second level of ACLs which access the same context as the filter ACL rules.

Finally, we want to build the ACL language with disaster recovery in mind, this is an open topic we did not address yet.

### Performance and deployment flexibility

We do not want Portail to be a bottleneck for terminal users, with a target of supporting **1Gbps** throughput while maintaining minimal impact on desktop usage and battery life.

Portail is designed to run on **systemd** targets, using [FDStore](https://systemd.io/FILE_DESCRIPTOR_STORE/) for hot reloads without disconnecting users. 
In Kubernetes environments, the use of an L4 load balancer is advised for persistent connections.

### Monitoring and observability

For monitoring, Portail plan to offer Prometheus metrics both locally and remotely, tracking performance indicators like ACL evaluation times, latency, throughput, errors, and active connections.

## What's implemented

* A SOCKS5 proxy server that can connect to other SOCKS5 proxies, optionally behind mTLS.
* A basic ACL language for experimentation with allow/deny/log rules, backend recommendations, metadata conditions, and hostname regexes.
* Socket activation for RPC and SOCKS5 sockets.

## Next steps

* Add support for running the SOCKS5 proxy behind mTLS itself.
* Implement client certificate resolution via the PKCS#11 API for TPM2 or security key usecases.
* Extend support for HTTP CONNECT and extended HTTP CONNECT using **Hyper**.
* Integrate trust inference backends (e.g., Grist API, OIDC) to enrich HTTP/SOCKS5 contexts (e.g., request URI, verb, headers).
* Enable connections to backends behind **SSH** for compatibility with the usual Sécurix deployment architecture.
