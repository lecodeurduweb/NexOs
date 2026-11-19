# NexOS — Sécurité, RBAC & Isolation Matérielle (`docs/SECURITY.md`)

## 1. Primitives Cryptographiques (`security/sha256.rs` & `network/tls.rs`)
- **Hachage des mots de passe** : `PBKDF2-HMAC-SHA256` (**4 096 itérations**, sels 128 bits par compte), vecteurs FIPS 180-4, RFC 4231 (`HMAC`) et RFC 6070 (`PBKDF2 c=1, c=2`) auto-testés à chaque boot.
- **Comparaison temps constant** : `constant_time_eq` / `constant_time_slice_eq` + dérivation factice sur identifiant inconnu (anti-énumération).
- **Jetons de session Bearer** : 256 bits (`64` hex chars) signés via `HMAC-SHA256` avec secret éphémère par démarrage (`CNTPCT_EL0`) et expiration.
- **Transport chiffré (`:443`)** : TLS 1.3 RFC 8446 (`X25519` + `ChaCha20-Poly1305` + `Ed25519`), sans clé statique partagée entre redémarrages.

## 2. Contrôle d'Accès (RBAC) & Protection Anti-Brute-Force
- **4 Rôles** (`security/mod.rs`) :
  - `admin` : toutes permissions (`PERM_READ_METRICS | PERM_MANAGE_SERVICES | PERM_WRITE_VFS | PERM_NET_ADMIN | PERM_AI_ADMIN`)
  - `operator` : métriques + contrôle des services (`PERM_READ_METRICS | PERM_MANAGE_SERVICES`)
  - `viewer` : lecture seule (`PERM_READ_METRICS`)
  - `ai-agent` : lecture seule + inférence bornée (`PERM_READ_METRICS`, aucune écriture VFS ni gestion services/utilisateurs)
- **Gestion CRUD dynamique (`POST/GET/DELETE /api/v1/users`)** : création et suppression de comptes (compte `admin` protégé contre la suppression).
- **Verrouillage anti-brute-force (`429 Too Many Requests`)** : blocage avec backoff exponentiel après **5 échecs** (`LOCKOUT`, `Retry-After: 2`).
- **Journal d'audit (`GET /api/v1/audit`)** : trace `AUTH_OK`, `AUTH_FAIL`, `AUTH_LOCKED`, `LOCKOUT`, `PERM_DENIED`, `USER_CREATE`, `USER_DELETE`, `HTTP_AUTH_FAIL`.
- *(Note : les identifiants initiaux de test `admin` / `operator` / `viewer` / `ai-core` doivent être renouvelés avant mise en production.)*

## 3. Durcissement Mémoire & Privilege Separation (ARM64 EL0/EL1)
- **Noyau `W^X` strict** : `.text` RX (`EL1`), `.rodata` RO+NX, `.data`/`.bss`/Heap RW+NX ; page physique `0x0` non mappée (garde `NULL`).
- **Userspace `EL0` isolé (`TTBR0_EL1`)** :
  - Vérification statique de l'ELF (`init.elf` vérifié `0` segment `RWE`).
  - `SYS_MMAP` rejette toute demande `W+X` (`EINVAL`).
  - Tout accès EL0 vers le noyau (`0x40080000`) lève un `Data Abort` (`EC=0x24`), contenu sans panique et suivi de `reap_exited()`.
  - Validation matérielle `AT S1E0R` / `AT S1E0W` sur chaque pointeur passé aux syscalls (`EFAULT = -14`).
  - Défense HTTP/VFS : rejet traversée `..` (`InvalidPath`), limite en-têtes `2048 B` (`413`), échappement JSON/HTML strict.
