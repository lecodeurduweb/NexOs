# NexOS AI Core — Architecture & Conception (`docs/AI_CORE_DESIGN.md`)

> **État d'implémentation** : **`TESTÉ (QEMU)`** *(Cible Raspberry Pi 4 : `COMPILÉ / NON TESTÉ SUR MATÉRIEL`)*
>
> **Architecture retenue** : Moteur d'inférence **100 % natif ARM64 en Rust `no_std` + assembleur AArch64 NEON SIMD** (`ai_core/` + `arch/arm64/neon_gemv.S`), sans aucune dépendance à Linux, Python, POSIX `libc`, ou `llama.cpp` à l'exécution.

---

## 1. Noyaux Assembleur AArch64 NEON SIMD (`arch/arm64/neon_gemv.S`)

- **`nexos_neon_dot_f32(a, b, n)`** : produit scalaire vectoriel 4×`f32` par cycle (`ld1 {v1.4s}`, `fmla v0.4s`, réduction `faddp`) avec reliquat scalaire.
- **`nexos_neon_gemv_q8_0(out, mat_q8, x, rows, cols)`** : multiplication matrice-vecteur quantifiée **Q8_0** (blocs de 32 poids `i8` + facteur d'échelle `f32` = `36 octets/bloc`), élargissement vectoriel `sxtl`/`sxtl2` (`i8→i16→i32→f32` via `scvtf`), accumulation `fmla`/`fmadd`.
- **Sécurité sous préemption SMP** : `neon_gemv.S` n'utilise que les registres `v0..v7`, `v16..v18` et `TrapFrame` (`arch/arm64/vectors.S`) sauvegarde/restaure intégralement `Q0..Q31`, `FPCR`, `FPSR` à chaque interruption timer.
- **Auto-test au démarrage (`tensor::self_test()`)** : compare les résultats NEON aux boucles scalaires IEEE-754 (`tolérance < 1e-3`).

## 2. Pipeline Transformer Causal (`ai_core/model.rs`)

1. **Format binaire `.nxm` v1 (`ai_core/format.rs`)** : en-tête 64 octets (`NXM1`), hyperparamètres (`vocab_size`, `dim`, `hidden_dim`, `n_layers`, `n_heads`, `n_kv_heads`, `max_seq`, `quant_type=Q8_0`, `rope_theta`, `flags`).
2. **Détection GGUF diagnostique (`inspect_gguf`)** : si un fichier externe `.gguf` est soumis, NexOS détecte sa version et son nombre de tenseurs et retourne une erreur explicite sans dépendance C++ tierce.
3. **Tokenizer (`ai_core/tokenizer.rs`)** : table de vocabulaire UTF-8 intégrée dans `.nxm`, encodage greedy longest-match avec fallback octet.
4. **Blocs Transformer (`forward_token`)** :
   - Déquantification de plongement (`tok_emb`).
   - Par couche : `RMSNorm` (`fsqrt` matériel AArch64), projections `Wq/Wk/Wv` via NEON Q8_0 GEMV, encodage positionnel rotatif (**RoPE** précalculé), cache **KV** par couche, attention causale GQA/MHA (`dot_f32` + `softmax`), projection `Wo` + résiduel, puis FFN **SwiGLU** (`w2(silu(w1(norm(x))) * w3(norm(x)))`).
   - Projection classificateur finale (`w_cls` ou poids liés) + échantillonnage glouton / Top-K température + indicateur `ABORT_FLAG`.

## 3. Gouvernance Mémoire & Supervision (`ai_core/mod.rs`)

- **Plafond configurable** : **`DEFAULT_CONFIG_CEILING_BYTES = 5 GiB`** sur Raspberry Pi 4 (8 Go RAM), dynamiquement borné par `effective_budget_bytes()` selon la RAM physique disponible (`phys::stats()` moins `MIN_SYSTEM_RESERVE_BYTES = 128 MiB`) et le plafond du tas noyau (`HEAP_MAX_BYTES = 64 MiB`).
- **Zéro swap sur carte SD** : vérification stricte `required_bytes <= active_budget_bytes` avant toute allocation de tenseurs.
- **Démon supervisé** : enregistré sous le nom `ai-core` dans `kernel/services.rs` (priorité `135`, politique `RestartPolicy::Always`).

## 4. Mesures Vérifiées (QEMU `virt`, Cortex-A72)

- Modèle vérifié `/disk/MODEL.NXM` (`103 262 B`, `dim=64`, `hidden=128`, `2` couches, `4` têtes, `vocab=64`, `Q8_0`) :
  - Empreinte RAM d'exécution : **`168 KiB`** (pour un budget actif sous QEMU de `61 025 KiB`).
  - Débit mesuré par `CNTPCT_EL0` sous émulation TCG : **`429.05 – 488.35 tok/s`** (`13` tokens générés en `~26.6 – 30.3 ms`).
