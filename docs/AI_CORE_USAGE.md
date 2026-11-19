# NexOS AI Core — Guide d'Utilisation (`docs/AI_CORE_USAGE.md`)

## 1. Générer & Embarquer un Modèle `.nxm` v1

Le générateur hors-ligne `scripts/mk_test_model.py` produit un modèle Transformer `.nxm` v1 quantifié `Q8_0` (sans aucune dépendance Python à l'intérieur de NexOS) :

```bash
python3 scripts/mk_test_model.py build/MODEL.NXM
python3 scripts/mk_test_disk.py build/test_disk.img
```
`mk_test_disk.py` écrit automatiquement sur la partition FAT32 :
- `MODEL.NXM` (`103 262 B`) : chargé automatiquement au démarrage sur `/disk/MODEL.NXM`.
- `BAD.GGF` (`64 B`) : en-tête GGUF v3 permettant de vérifier le rejet diagnostique des modèles non convertis.

## 2. Utilisation depuis le Shell EL0 (`nexos#`, via `SYS_AI_CMD = 29`)

```text
nexos# ai status
nexos# ai ask nexos status
nexos# ai bench
nexos# ai unload
nexos# ai load /disk/MODEL.NXM
```
Exemple de sortie réelle mesurée sous QEMU `virt` :
```text
  AI>  arm64 neon q8 inference engine active [cortex-a72 smp tls1.3 ready].
  [stats: prompt_toks=4 gen_toks=13 elapsed_us=26620 speed=488.35 tok/s aborted=false]
```

## 3. API HTTP/HTTPS TLS 1.3 (`/api/v1/ai/*`)

Tous les appels nécessitent une authentification valide (`Basic` ou `Bearer <token>`). Les opérations de chargement/déchargement exigent le rôle `admin` (`PERM_AI_ADMIN`) :

- **État du moteur et budget RAM (`GET`)** :
  ```bash
  curl -k -H "Authorization: Bearer $TOKEN" https://127.0.0.1:18443/api/v1/ai
  ```
- **Inférence (`POST`)** :
  ```bash
  curl -k -X POST -H "Authorization: Bearer $TOKEN" \
    "https://127.0.0.1:18443/api/v1/ai/infer?prompt=nexos%20status&max_tokens=24"
  ```
- **Benchmark NEON Q8_0 (`POST`)** :
  ```bash
  curl -k -X POST -H "Authorization: Bearer $TOKEN" https://127.0.0.1:18443/api/v1/ai/bench
  ```
- **Décharger / Charger un modèle depuis `/disk` (`POST`, `PERM_AI_ADMIN`)** :
  ```bash
  curl -k -X POST -H "Authorization: Bearer $TOKEN" https://127.0.0.1:18443/api/v1/ai/unload
  curl -k -X POST -H "Authorization: Bearer $TOKEN" "https://127.0.0.1:18443/api/v1/ai/load?path=/disk/MODEL.NXM"
  ```
