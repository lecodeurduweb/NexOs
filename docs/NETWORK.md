# NexOS — Pile Réseau & TLS 1.3 (`docs/NETWORK.md`)

NexOS implémente une pile réseau **100 % indépendante** en Rust `no_std` (`network/`), sans dépendance Linux, `smoltcp`, `OpenSSL` ou `mbedTLS`.

## 1. Pilotes Réseau
- **QEMU `virt` (`[TESTÉ (QEMU)]`)** : `drivers/virtio/net.rs` (VirtIO-Net v1 MMIO, anneaux RX/TX DMA, MAC détectée dynamiquement).
- **Raspberry Pi 4 (`[MOCK MMIO sous QEMU]` / `[COMPILÉ / NON TESTÉ SUR MATÉRIEL]`)** : `drivers/net/genet.rs` (BCM2711 GENET v5 UniMAC/RDMA/TDMA validé par simulation MMIO déterministe au démarrage ; non testé sur Ethernet physique Pi 4).

## 2. Protocoles Implémentés & Testés
- **Liaison & ARP** : Ethernet II (`0x0800`, `0x0806`, `0x86DD`), ARP avec validation MAC unicast, filtrage anti-spoofing hors sous-réseau et file d'attente de paquets en attente de résolution.
- **IPv4 & Configuration** : DHCPv4 complet (`Discover → Offer → Request → Ack`, IP `10.0.2.15` sous QEMU SLIRP) avec bascule statique (`10.77.0.2/24`, testée sur TAP `nexostap0`).
- **IPv6 & ICMPv6 (`network/ipv6.rs`)** : Adresse Link-Local `fe80::/64` dérivée EUI-64 (`fe80:0:0:0:5054:ff:fe12:3456`), Neighbor Discovery (NS/NA) et Echo ICMPv6 auto-testés.
- **ICMPv4, UDP, DNS** : Echo Request/Reply (ping bidirectionnel mesuré), résolveur DNS RFC 1035 (`UDP/53`, vérifié contre serveur UDP hôte).
- **TCP (`network/tcp.rs`)** : Automate complet `Listen`/`SynReceived`/`Established`/`FinWait`/`CloseWait`/`Closed`, gestion fenêtre/ACK/retransmission et `RST` immédiat sur ports fermés (`:9999`).
- **TLS 1.3 (`network/tls.rs`)** : RFC 8446 pur Rust :
  - Suite négociée et vérifiée par client OpenSSL Python `ssl` (`TLSv1.3`): **`TLS_CHACHA20_POLY1305_SHA256`**.
  - Échange de clés éphémères **X25519** (RFC 7748).
  - Signature serveur **Ed25519** (RFC 8032) + certificat X.509 DER auto-généré par démarrage.
  - Dérivation de clés **HKDF-SHA256** (vecteur RFC 5869 vérifié au boot).
  - Vecteurs cryptographiques (`SHA-512`, `HKDF`, `ChaCha20-Poly1305`, `X25519`, `Ed25519`) auto-testés à chaque démarrage.

## 3. Services Réseau Exposés
- `TCP :7070` : Démon Echo diagnostic (`[TESTÉ (QEMU)]` sur TAP).
- `TCP :80` : Serveur d'administration Web HTTP/1.1 authentifié (`[TESTÉ (QEMU)]`).
- `TCP :443` : Serveur d'administration Web HTTPS **TLS 1.3** (`/api/v1/*`, `[TESTÉ (QEMU)]`).
