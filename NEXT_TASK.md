# NEXT_TASK.md — reprise immédiate

Date : 2026-11-20

## Contexte vérifié (dépôt réel)
- Branches : `main` (f822525, dépôt complet), `ci/quality-gates` (f45fb6b8, PR #1 ouverte, non fusionnée), `fix/ci-diagnostics` (cette branche).
- CI du commit f45fb6b8 : run `push` 44691848637 = succès, run `pull_request` 44691864911 = échec à l'étape « Run complete build and QEMU test suite » (exit 1). Même code, résultats différents => test non déterministe. La cause exacte n'était PAS récupérable : l'ancien `tests/run_all.py` n'affichait pas le transcript UART à l'échec. Rien ne prouve une cause IPv6.

## Ce que fait cette branche
- `tests/run_all.py` : statuts PASS/FAIL/SKIP(exit 77)/BLOCKED par étape, journaux dans `build/test-logs/`, transcript UART affiché et sauvegardé à l'échec, liste exacte des marqueurs manquants, attente du prompt pilotée par événement (timeout `NEXOS_BOOT_TIMEOUT`, défaut 90 s) au lieu de 30 s fixes + sleeps, rapport `report.json`. Les lignes « SKIPPED » codées en dur ont été supprimées.
- `.github/workflows/ci.yml` : diagnostics d'environnement, affichage du rapport et du transcript, artefact `nexos-test-logs-*`.

## Tâche suivante (ordre)
1. Faire tourner la CI sur `fix/ci-diagnostics` (push déclenche le workflow) et lire `report.json` / transcript pour identifier le marqueur réellement manquant dans le run flaky. Relancer 3 fois (`workflow_dispatch`) pour mesurer la flakiness.
2. Adapter `scripts/test_stage11_net.py` pour sortir avec le code 77 quand TAP est indisponible (actuellement il faut vérifier son code de sortie : un SKIP ne doit jamais être un PASS).
3. Corriger la cause racine identifiée (probable : timing boot QEMU sur runner 2 vCPU, ou course sur ports 18080/18443).
4. Ensuite seulement : Phase 1 noyau (audit MMU/W^X/SMP), Phase 2 pilotes BCM2711 (EMMC2 réel, GENET), etc. Voir ROADMAP.md.

## Non fait / non prouvé
- Aucune compilation ni exécution QEMU n'a été réalisée dans cette session (pas d'environnement d'exécution disponible) : la nouvelle suite doit être validée par la CI GitHub.
- Aucune validation Raspberry Pi 4 physique.
