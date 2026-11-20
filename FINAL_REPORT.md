# NexOS — Rapport de validation

> Ce document distingue les résultats reproductibles des éléments qui nécessitent un environnement ou du matériel externe. Une compilation réussie ne prouve pas le fonctionnement sur une carte physique.

## Périmètre

NexOS est un système bare-metal AArch64 indépendant, écrit principalement en Rust `no_std`, assembleur AArch64 et C freestanding pour l'espace utilisateur.

## Validation automatisable

La CI GitHub (`.github/workflows/ci.yml`) exécute :
- Vérification TypeScript du dashboard.
- Build de production du dashboard React.
- Compilation des cibles QEMU et Raspberry Pi 4.
- Vérification des segments ELF W^X et de l'image SD.
- Tests de démarrage, noyau, userspace, stockage, réseau et AI Core sous QEMU.
- Tests de l'administration HTTP/HTTPS, TLS 1.3, RBAC et persistance.

Le statut réel est celui du dernier workflow exécuté sur GitHub Actions. La présence de ce workflow ne signifie pas que ses étapes ont déjà réussi.

## Limites non masquées

| Domaine | Statut honnête |
|---|---|
| Build ARM64/QEMU | À confirmer par CI |
| Dashboard TypeScript/production | À confirmer par CI |
| Tests QEMU | À confirmer par CI |
| Réseau TAP hôte ↔ QEMU | Peut être ignoré si le runner interdit la création d'interfaces TAP ; un SKIP n'est pas un PASS |
| Raspberry Pi 4 physique | Non validé tant qu'un démarrage et des tests sur carte réelle n'ont pas été réalisés |
| Fournisseur LLM externe | Non validé sans identifiants réels et appel de bout en bout |

## Procédure de validation matérielle

Suivre [docs/HARDWARE_TEST.md](docs/HARDWARE_TEST.md) et consigner le modèle de carte, le firmware, les branchements UART, les logs de démarrage et les tests réellement effectués.

## Rapport de tests détaillé

Voir [TEST_REPORT.md](TEST_REPORT.md), [STATUS.md](STATUS.md), [PROJECT_STATUS.md](PROJECT_STATUS.md) et [TESTING.md](TESTING.md).
