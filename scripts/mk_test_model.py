#!/usr/bin/env python3
"""Generate a deterministic native NexOS .nxm v1 Q8_0 Transformer model.

Also writes a minimal GGUF header stub for verifying external format rejection.
No runtime dependency inside NexOS: this offline script packs weights into FAT32.
"""

import math
import os
import struct
import sys
import zlib

NXM_MAGIC = b"NXM1"
NXM_VERSION = 1
QUANT_Q8_0 = 1
Q8_BLOCK_ELEMS = 32
FLAG_CRC32_INTEGRITY = 1 << 1


def quantize_q8_0_matrix(rows: list[list[float]]) -> bytes:
    out = bytearray()
    for row in rows:
        assert len(row) % Q8_BLOCK_ELEMS == 0
        for off in range(0, len(row), Q8_BLOCK_ELEMS):
            blk = row[off : off + Q8_BLOCK_ELEMS]
            max_abs = max(abs(x) for x in blk)
            scale = (max_abs / 127.0) if max_abs > 1e-12 else 0.0
            qs = [
                max(-127, min(127, int(round(x / scale)))) if scale > 0.0 else 0
                for x in blk
            ]
            out.extend(struct.pack("<f32b", scale, *qs))
    return bytes(out)


def build_vocab() -> list[tuple[str, float]]:
    # 64 tokens matching vocab_size = dim = 64
    base = [
        ("<pad>", -10.0),      # 0
        ("<bos>", -10.0),      # 1
        ("<eos>", -10.0),      # 2
        ("nexos", 10.0),       # 3
        ("status", 10.0),      # 4
        (" ", 5.0),            # 5
        (" arm64", 8.0),       # 6
        (" neon", 8.0),        # 7
        (" q8", 8.0),          # 8
        (" inference", 8.0),   # 9
        (" engine", 8.0),      # 10
        (" active", 8.0),      # 11
        (" [", 8.0),           # 12
        ("cortex-a72", 8.0),   # 13
        (" smp", 8.0),         # 14
        (" tls1.3", 8.0),      # 15
        (" ready", 8.0),       # 16
        ("]", 8.0),            # 17
        (".", 8.0),            # 18
        ("hello", 6.0),        # 19
        (" help", 6.0),        # 20
        (" rpi4", 6.0),        # 21
        (" ram", 6.0),         # 22
        (" ok", 6.0),          # 23
    ]
    # Add printable ASCII byte-fallback / single-char tokens to fill 64 entries
    chars = list("abcdefghijklmnopqrstuvwxyz0123456789:-_/!?\n")
    idx = 0
    while len(base) < 64 and idx < len(chars):
        ch = chars[idx]
        idx += 1
        if all(tok != ch for tok, _ in base):
            base.append((ch, 1.0))
    while len(base) < 64:
        base.append((f"<t{len(base)}>", 0.0))
    return base[:64]


def build_nxm_bytes() -> bytes:
    vocab = build_vocab()
    vocab_size = 64
    dim = 64
    hidden_dim = 128
    n_layers = 2
    n_heads = 4
    n_kv_heads = 4
    max_seq = 64
    rope_theta = 10000.0
    flags = FLAG_CRC32_INTEGRITY  # untied w_cls + IEEE CRC-32 payload integrity

    payload = bytearray()

    buf = payload
    # Vocab table
    for text, score in vocab:
        raw = text.encode("utf-8")
        buf.extend(struct.pack("<fH", score, len(raw)))
        buf.extend(raw)

    # Token embeddings: strong unit-basis identity + subtle deterministic harmonic features
    tok_emb = []
    for t in range(vocab_size):
        row = [0.02 * math.sin((t + 1) * (c + 1) * 0.37) for c in range(dim)]
        row[t] = 1.0
        tok_emb.append(row)
    buf.extend(quantize_q8_0_matrix(tok_emb))

    # 2 Transformer layers with genuine non-zero attention + SwiGLU FFN projections
    # Scaled gently so residual direction remains separable after RMSNorm
    ones_norm = struct.pack(f"<{dim}f", *([1.0] * dim))
    for layer in range(n_layers):
        # rms_att
        buf.extend(ones_norm)
        # wq, wk, wv, wo (64x64)
        wq = [[0.25 if r == c else 0.01 * math.cos((r + layer) * (c + 1) * 0.21) for c in range(dim)] for r in range(dim)]
        wk = [[0.25 if r == c else 0.01 * math.sin((r + layer) * (c + 1) * 0.19) for c in range(dim)] for r in range(dim)]
        wv = [[0.10 if r == c else 0.0 for c in range(dim)] for r in range(dim)]
        wo = [[0.08 if r == c else 0.0 for c in range(dim)] for r in range(dim)]
        for m in (wq, wk, wv, wo):
            buf.extend(quantize_q8_0_matrix(m))

        # rms_ffn
        buf.extend(ones_norm)
        # w1 (128x64), w2 (64x128), w3 (128x64)
        w1 = [[0.15 if (r % dim) == c else 0.0 for c in range(dim)] for r in range(hidden_dim)]
        w3 = [[0.15 if (r % dim) == c else 0.0 for c in range(dim)] for r in range(hidden_dim)]
        w2 = [[0.06 if r == (c % dim) else 0.0 for c in range(hidden_dim)] for r in range(dim)]
        buf.extend(quantize_q8_0_matrix(w1))
        buf.extend(quantize_q8_0_matrix(w2))
        buf.extend(quantize_q8_0_matrix(w3))

    # rms_final
    buf.extend(ones_norm)

    # Output classifier weights: deterministic next-token transition chain
    # (Synthetic validation weights - NOT a trained conversational LLM)
    transitions = {
        4: 6,
        6: 7,
        7: 8,
        8: 9,
        9: 10,
        10: 11,
        11: 12,
        12: 13,
        13: 14,
        14: 15,
        15: 16,
        16: 17,
        17: 18,
        18: 2,
    }
    w_cls = [[0.0 for _ in range(dim)] for _ in range(vocab_size)]
    for cur_tok in range(vocab_size):
        nxt = transitions.get(cur_tok, 6 if cur_tok != 2 else 2)
        w_cls[nxt][cur_tok] = 2.0
    buf.extend(quantize_q8_0_matrix(w_cls))

    payload_bytes = bytes(buf)
    payload_crc = zlib.crc32(payload_bytes) & 0xFFFFFFFF
    hdr = struct.pack(
        "<4sIIIIIIIIIfIIQ4s",
        NXM_MAGIC,
        NXM_VERSION,
        vocab_size,
        dim,
        hidden_dim,
        n_layers,
        n_heads,
        n_kv_heads,
        max_seq,
        QUANT_Q8_0,
        rope_theta,
        flags,
        payload_crc,
        len(payload_bytes),
        b"\x00" * 4,
    )
    assert len(hdr) == 64
    return hdr + payload_bytes


def build_corrupt_nxm_bytes() -> bytes:
    corrupt = bytearray(build_nxm_bytes())
    corrupt[-17] ^= 0x01
    return bytes(corrupt)


def build_bad_gguf_stub() -> bytes:
    # Minimal GGUF v3 diagnostic test file (magic "GGUF", version=3, tensors=12, kv=4)
    return struct.pack("<4sIQQ", b"GGUF", 3, 12, 4) + (b"\x00" * 40)


def main() -> None:
    out_path = sys.argv[1] if len(sys.argv) > 1 else "build/MODEL.NXM"
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    data = build_nxm_bytes()
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"Generated {out_path}: {len(data)} bytes ({len(data) / 1024:.1f} KiB) NXM1 Q8_0 model")


if __name__ == "__main__":
    main()
