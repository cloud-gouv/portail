# Roadmap

## Implemented

- [x] SOCKS5 proxy (TCP CONNECT): local and chained, optional mTLS between hops
- [x] mTLS listeners
- [x] HTTP CONNECT (1.1, 2)
- [x] ACL language: `when`/`require`/`action`, regex host matching, set membership, logical operators
- [x] Backend routing: static, dynamic (RPC-updatable), multi-backend failover, default backend
- [x] NixOS module: `services.portail`, systemd socket activation, FDStore, ACL generation
- [x] RPC control API: Varlink interface
- [x] Structured logging: JSON and systemd via `tracing`
- [x] Socket activation: systemd integration
- [x] Documentation: bilingual mdbook (FR/EN)

## In progress

- [ ] Prometheus metrics
- [ ] PKCS#11 client certificate resolution
- [ ] UDP ASSOCIATE
- [ ] HTTP/3

## Planned

- [ ] Trust inference backends: Grist API, OIDC
- [ ] SSH backend transport
- [ ] Audit log redaction
- [ ] Step-up authentication challenges
- [ ] Disaster recovery: degraded mode when backends unavailable
- [ ] Configuration reload without restart (FDStore ready)
- [ ] Helm chart

## Future considerations

- [ ] Extended CONNECT
- [ ] ACL language stabilization: EBNF grammar, formal semantics
- [ ] Performance: 1 Gbps throughput target
