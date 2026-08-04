# Feuille de route

## Implémenté

- [x] Proxy SOCKS5 (TCP CONNECT) : local et chaîné, mTLS optionnel entre les sauts
- [x] Listeners mTLS
- [x] HTTP CONNECT (1.1, 2)
- [x] Langage ACL : `when`/`require`/`action`, regex, appartenance, opérateurs logiques
- [x] Routage : backends statiques, dynamiques (mise à jour RPC), failover, backend par défaut
- [x] Module NixOS : `services.portail`, activation socket systemd, FDStore, génération ACL
- [x] API de contrôle RPC : interface Varlink
- [x] Journalisation structurée : JSON et systemd via `tracing`
- [x] Activation par socket : intégration systemd
- [x] Documentation : mdbook bilingue (FR/EN)

## En cours

- [ ] Métriques Prometheus
- [ ] Résolution certificats clients PKCS#11
- [ ] UDP ASSOCIATE
- [ ] HTTP/3

## Prévu

- [ ] Backends d'inférence de confiance : Grist API, OIDC
- [ ] Transport backend SSH
- [ ] Masquage des journaux d'audit
- [ ] Demandes d'élévation d'authentification
- [ ] Reprise après sinistre : mode dégradé si backends indisponibles
- [ ] Rechargement de configuration sans redémarrage (FDStore prêt)
- [ ] Chart Helm

## Considérations futures

- [ ] CONNECT étendu
- [ ] Stabilisation du langage ACL : grammaire EBNF, sémantique formelle
- [ ] Performance : objectif 1 Gbps
