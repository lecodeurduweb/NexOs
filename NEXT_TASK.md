# NEXT_TASK.md — reprise immédiate

Dernière mise à jour : 2026-11-20 (session 2)

## État CI (branche `fix/ci-diagnostics`, PR #2)

| Run | Événement | Résultat | Durée | Observation |
|---|---|---|---|---|
| 44691848637 | push f45fb6b8 | PASS | — | ancienne suite (sans diagnostics) |
| 44691864911 | pull_request f45fb6b8 | FAIL | — | même commit → non déterministe, cause illisible |
| 44735816524 | push 71882ce | FAIL | 2 min 56 s | échec à « Run complete build and QEMU test suite », **durée trop courte pour un build Rust + QEMU complet → échec précoce probable dans `./build.sh all`** |

Les logs détaillés ne sont pas lisibles via l'API dans la session actuelle. Les artefacts
`nexos-test-logs-44735816524` (report.json + logs par étape) existent et doivent être lus en premier.

## Tâche n°1 (bloquante) — lire le vrai log de build
1. Ouvrir le run 44735816524 → artefact `nexos-test-logs-*` → `build/test-logs/1__Build_*.log` et `report.json`.
2. Hypothèses à vérifier dans l'ordre :
   - `cargo build --target aarch64-unknown-none` : erreur de compilation avec le `stable` courant
     (features instables, `asm!`, lints promus en erreur) ;
   - `aarch64-linux-gnu-gcc -B/usr/bin/aarch64-linux-gnu-` : `ld` croisé absent (`binutils-aarch64-linux-gnu` est installé mais vérifier `aarch64-linux-gnu-ld`) ;
   - `llvm-objcopy` : paquet `llvm` sur ubuntu-24.04 fournit `llvm-objcopy-18` sans alias → fallback vers `aarch64-linux-gnu-objcopy` attendu ; vérifier.
3. Corriger, pousser sur `fix/ci-diagnostics`, relancer 3× (`workflow_dispatch`) pour mesurer la flakiness.

## Tâche n°2 — valider les correctifs de la session 2 (NOT TESTED localement)
- `scripts/mk_rpi4_sd.py` : image 272 MiB sparse, ≥ 65 525 clusters, FSInfo + secteurs de secours. L'étape 1d de
  `tests/run_all.py` doit toujours passer ; ajouter une assertion `clusters >= 65525` et une vérification FSInfo à 1d.
  Vérifier que `fsck.fat -n build/rpi4/nexos-rpi4-sd.img` (avec offset) n'émet aucune erreur.
- `scripts/test_stage11_net.py` : exit 77 → doit apparaître en `SKIP` dans `report.json` sur le runner GitHub.

## Ensuite (ordre de priorité)
3. Phase 1 : audit MMU/W^X/SMP par lecture de `arch/arm64/mmu.rs`, `smp.rs`, `kernel/sync.rs`.
4. Phase 2 : EMMC2 (`drivers/block/sd_emmc2.rs`) et GENET (`drivers/net/genet.rs`) — remplacer les mocks MMIO par les vrais chemins BCM2711 en gardant les tests mock pour QEMU.
5. Créer `CHANGELOG.md`, `AI_CORE.md` (absents sur `main`).

## Toujours non validé
- Raspberry Pi 4 physique : aucun test effectué.
- TAP : SKIP sur runner sans CAP_NET_ADMIN.
