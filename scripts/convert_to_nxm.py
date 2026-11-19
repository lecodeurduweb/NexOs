#!/usr/bin/env python3
"""Offline Converter to NexOS Native .nxm v1 Q8_0 Model Format.

Host-only offline tool (Python stdlib only; zero runtime dependency in NexOS).
Supports:
  - GGUF v2 / v3 (F32, F16, Q8_0 tensors) -> .nxm v1 (Q8_0 + CRC-32)
  - llama2.c raw FP32 .bin -> .nxm v1 (Q8_0 + CRC-32)
  - JSON float32 weight spec -> .nxm v1 (Q8_0 + CRC-32)
  - --verify <model.nxm> integrity & geometry verification
"""

from __future__ import annotations

import argparse
import json
import math
import os
import struct
import sys
import zlib
from typing import Any, BinaryIO

NXM_MAGIC = b"NXM1"
NXM_VERSION = 1
NXM_HEADER_SIZE = 64
QUANT_Q8_0 = 1
Q8_BLOCK_ELEMS = 32
Q8_BLOCK_BYTES = 36
FLAG_TIED_CLS = 1 << 0
FLAG_CRC32_INTEGRITY = 1 << 1

GGUF_MAGIC = b"GGUF"
GGML_TYPE_F32 = 0
GGML_TYPE_F16 = 1
GGML_TYPE_Q8_0 = 8


def quantize_f32_to_nxm_q8_0(values: list[float], rows: int, cols: int) -> bytes:
    if len(values) != rows * cols:
        raise ValueError(f"Matrix size mismatch: got {len(values)}, expected {rows}x{cols}")
    if cols % Q8_BLOCK_ELEMS != 0:
        raise ValueError(f"cols={cols} must be a multiple of {Q8_BLOCK_ELEMS}")
    out = bytearray()
    for r in range(rows):
        base = r * cols
        for off in range(0, cols, Q8_BLOCK_ELEMS):
            blk = values[base + off : base + off + Q8_BLOCK_ELEMS]
            max_abs = max(abs(x) for x in blk)
            scale = (max_abs / 127.0) if max_abs > 1e-12 else 0.0
            qs = [
                max(-127, min(127, int(round(x / scale)))) if scale > 0.0 else 0
                for x in blk
            ]
            out.extend(struct.pack("<f32b", scale, *qs))
    return bytes(out)


def pack_nxm_v1(
    vocab: list[tuple[str, float]],
    dim: int,
    hidden_dim: int,
    n_layers: int,
    n_heads: int,
    n_kv_heads: int,
    max_seq: int,
    rope_theta: float,
    tok_emb: list[float],
    layers: list[dict[str, list[float]]],
    rms_final: list[float],
    w_cls: list[float] | None,
) -> bytes:
    vocab_size = len(vocab)
    head_dim = dim // n_heads
    kv_dim = n_kv_heads * head_dim
    flags = FLAG_CRC32_INTEGRITY | (FLAG_TIED_CLS if w_cls is None else 0)

    payload = bytearray()
    for text, score in vocab:
        raw = text.encode("utf-8")
        payload.extend(struct.pack("<fH", float(score), len(raw)))
        payload.extend(raw)

    payload.extend(quantize_f32_to_nxm_q8_0(tok_emb, vocab_size, dim))
    for lw in layers:
        if len(lw["rms_att"]) != dim or len(lw["rms_ffn"]) != dim:
            raise ValueError("RMSNorm weight length mismatch")
        payload.extend(struct.pack(f"<{dim}f", *lw["rms_att"]))
        payload.extend(quantize_f32_to_nxm_q8_0(lw["wq"], dim, dim))
        payload.extend(quantize_f32_to_nxm_q8_0(lw["wk"], kv_dim, dim))
        payload.extend(quantize_f32_to_nxm_q8_0(lw["wv"], kv_dim, dim))
        payload.extend(quantize_f32_to_nxm_q8_0(lw["wo"], dim, dim))
        payload.extend(struct.pack(f"<{dim}f", *lw["rms_ffn"]))
        payload.extend(quantize_f32_to_nxm_q8_0(lw["w1"], hidden_dim, dim))
        payload.extend(quantize_f32_to_nxm_q8_0(lw["w2"], dim, hidden_dim))
        payload.extend(quantize_f32_to_nxm_q8_0(lw["w3"], hidden_dim, dim))

    if len(rms_final) != dim:
        raise ValueError("rms_final length mismatch")
    payload.extend(struct.pack(f"<{dim}f", *rms_final))
    if w_cls is not None:
        payload.extend(quantize_f32_to_nxm_q8_0(w_cls, vocab_size, dim))

    payload_bytes = bytes(payload)
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
        float(rope_theta),
        flags,
        payload_crc,
        len(payload_bytes),
        b"\x00" * 4,
    )
    assert len(hdr) == NXM_HEADER_SIZE
    return hdr + payload_bytes


def verify_nxm_file(path: str) -> dict[str, Any]:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < NXM_HEADER_SIZE:
        raise ValueError("File smaller than 64-byte NXM1 header")
    (
        magic,
        ver,
        vocab_size,
        dim,
        hidden_dim,
        n_layers,
        n_heads,
        n_kv_heads,
        max_seq,
        quant_type,
        rope_theta,
        flags,
        payload_crc,
        payload_len,
        _res,
    ) = struct.unpack("<4sIIIIIIIIIfIIQ4s", data[:64])

    if magic != NXM_MAGIC:
        raise ValueError(f"Bad magic: {magic!r}")
    if ver != NXM_VERSION:
        raise ValueError(f"Unsupported version: {ver}")
    if quant_type != QUANT_Q8_0:
        raise ValueError(f"Unsupported quant: {quant_type}")
    if dim % 32 != 0 or hidden_dim % 32 != 0 or n_heads == 0 or dim % n_heads != 0:
        raise ValueError("Invalid dim/hidden_dim/n_heads geometry")

    actual_payload = data[NXM_HEADER_SIZE:]
    if (flags & FLAG_CRC32_INTEGRITY) != 0:
        if len(actual_payload) != payload_len:
            raise ValueError(f"Payload length mismatch: got {len(actual_payload)}, header={payload_len}")
        actual_crc = zlib.crc32(actual_payload) & 0xFFFFFFFF
        if actual_crc != payload_crc:
            raise ValueError(f"CRC-32 mismatch: got {actual_crc:#010x}, expected {payload_crc:#010x}")

    # Walk tokenizer and weight section lengths
    off = 64
    for _ in range(vocab_size):
        _score, tlen = struct.unpack_from("<fH", data, off)
        off += 6 + tlen

    def q8_sz(r: int, c: int) -> int:
        return r * (c // Q8_BLOCK_ELEMS) * Q8_BLOCK_BYTES

    kv_dim = n_kv_heads * (dim // n_heads)
    off += q8_sz(vocab_size, dim)
    for _ in range(n_layers):
        off += dim * 4
        off += q8_sz(dim, dim) + q8_sz(kv_dim, dim) * 2 + q8_sz(dim, dim)
        off += dim * 4
        off += q8_sz(hidden_dim, dim) * 2 + q8_sz(dim, hidden_dim)
    off += dim * 4
    if (flags & FLAG_TIED_CLS) == 0:
        off += q8_sz(vocab_size, dim)
    if off != len(data):
        raise ValueError(f"Exact payload parse size mismatch: walked {off}, file {len(data)}")

    return {
        "vocab_size": vocab_size,
        "dim": dim,
        "hidden_dim": hidden_dim,
        "n_layers": n_layers,
        "n_heads": n_heads,
        "n_kv_heads": n_kv_heads,
        "max_seq": max_seq,
        "rope_theta": rope_theta,
        "crc32_verified": bool(flags & FLAG_CRC32_INTEGRITY),
        "bytes": len(data),
    }


def _gguf_read_str(f: BinaryIO) -> str:
    n = struct.unpack("<Q", f.read(8))[0]
    return f.read(n).decode("utf-8", errors="replace")


def _gguf_read_val(f: BinaryIO, vtype: int) -> Any:
    if vtype == 0:
        return struct.unpack("<B", f.read(1))[0]
    if vtype == 1:
        return struct.unpack("<b", f.read(1))[0]
    if vtype == 2:
        return struct.unpack("<H", f.read(2))[0]
    if vtype == 3:
        return struct.unpack("<h", f.read(2))[0]
    if vtype == 4:
        return struct.unpack("<I", f.read(4))[0]
    if vtype == 5:
        return struct.unpack("<i", f.read(4))[0]
    if vtype == 6:
        return struct.unpack("<f", f.read(4))[0]
    if vtype == 7:
        return bool(struct.unpack("<B", f.read(1))[0])
    if vtype == 8:
        return _gguf_read_str(f)
    if vtype == 9:
        elem_type, count = struct.unpack("<IQ", f.read(12))
        return [_gguf_read_val(f, elem_type) for _ in range(count)]
    if vtype == 10:
        return struct.unpack("<Q", f.read(8))[0]
    if vtype == 11:
        return struct.unpack("<q", f.read(8))[0]
    if vtype == 12:
        return struct.unpack("<d", f.read(8))[0]
    raise ValueError(f"Unsupported GGUF metadata type {vtype}")


def _dequant_ggml_tensor(raw: bytes, ttype: int, n_elems: int) -> list[float]:
    if ttype == GGML_TYPE_F32:
        return list(struct.unpack(f"<{n_elems}f", raw[: n_elems * 4]))
    if ttype == GGML_TYPE_F16:
        return list(struct.unpack(f"<{n_elems}e", raw[: n_elems * 2]))
    if ttype == GGML_TYPE_Q8_0:
        n_blocks = n_elems // 32
        out: list[float] = []
        for b in range(n_blocks):
            off = b * 34
            (scale,) = struct.unpack_from("<e", raw, off)
            qs = struct.unpack_from("<32b", raw, off + 2)
            out.extend(float(scale) * q for q in qs)
        return out
    raise ValueError(f"Unsupported GGML tensor type {ttype} (supported: F32=0, F16=1, Q8_0=8)")


def convert_from_gguf(path: str) -> bytes:
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != GGUF_MAGIC:
            raise ValueError(f"Not a GGUF file: {magic!r}")
        version, tensor_count, kv_count = struct.unpack("<IQQ", f.read(20))
        if version not in (2, 3):
            raise ValueError(f"Unsupported GGUF version {version}")

        kv: dict[str, Any] = {}
        for _ in range(kv_count):
            k = _gguf_read_str(f)
            vtype = struct.unpack("<I", f.read(4))[0]
            kv[k] = _gguf_read_val(f, vtype)

        arch = kv.get("general.architecture", "llama")
        dim = int(kv[f"{arch}.embedding_length"])
        hidden_dim = int(kv[f"{arch}.feed_forward_length"])
        n_layers = int(kv[f"{arch}.block_count"])
        n_heads = int(kv[f"{arch}.attention.head_count"])
        n_kv_heads = int(kv.get(f"{arch}.attention.head_count_kv", n_heads))
        max_seq = int(kv.get(f"{arch}.context_length", 512))
        rope_theta = float(kv.get(f"{arch}.rope.freq_base", 10000.0))

        tokens = kv["tokenizer.ggml.tokens"]
        scores = kv.get("tokenizer.ggml.scores", [0.0] * len(tokens))
        vocab = [(str(tokens[i]), float(scores[i])) for i in range(len(tokens))]

        tensors = {}
        for _ in range(tensor_count):
            tname = _gguf_read_str(f)
            ndims = struct.unpack("<I", f.read(4))[0]
            dims = struct.unpack(f"<{ndims}Q", f.read(8 * ndims))
            ttype, toff = struct.unpack("<IQ", f.read(12))
            tensors[tname] = (dims, ttype, toff)

        align = int(kv.get("general.alignment", 32))
        cur = f.tell()
        data_start = ((cur + align - 1) // align) * align

        def load_t(name: str) -> list[float]:
            dims, ttype, toff = tensors[name]
            n_elems = 1
            for d in dims:
                n_elems *= d
            f.seek(data_start + toff)
            if ttype == GGML_TYPE_F32:
                raw = f.read(n_elems * 4)
            elif ttype == GGML_TYPE_F16:
                raw = f.read(n_elems * 2)
            elif ttype == GGML_TYPE_Q8_0:
                raw = f.read((n_elems // 32) * 34)
            else:
                raise ValueError(f"Unsupported tensor {name} type {ttype}")
            return _dequant_ggml_tensor(raw, ttype, n_elems)

        tok_emb = load_t("token_embd.weight")
        layers = []
        for l in range(n_layers):
            layers.append(
                {
                    "rms_att": load_t(f"blk.{l}.attn_norm.weight"),
                    "wq": load_t(f"blk.{l}.attn_q.weight"),
                    "wk": load_t(f"blk.{l}.attn_k.weight"),
                    "wv": load_t(f"blk.{l}.attn_v.weight"),
                    "wo": load_t(f"blk.{l}.attn_output.weight"),
                    "rms_ffn": load_t(f"blk.{l}.ffn_norm.weight"),
                    "w1": load_t(f"blk.{l}.ffn_gate.weight"),
                    "w2": load_t(f"blk.{l}.ffn_down.weight"),
                    "w3": load_t(f"blk.{l}.ffn_up.weight"),
                }
            )
        rms_final = load_t("output_norm.weight")
        w_cls = load_t("output.weight") if "output.weight" in tensors else None
        return pack_nxm_v1(
            vocab,
            dim,
            hidden_dim,
            n_layers,
            n_heads,
            n_kv_heads,
            max_seq,
            rope_theta,
            tok_emb,
            layers,
            rms_final,
            w_cls,
        )


def convert_from_llama2c(bin_path: str, tok_json: str | None) -> bytes:
    with open(bin_path, "rb") as f:
        dim, hidden_dim, n_layers, n_heads, n_kv_heads, raw_vocab, seq_len = struct.unpack(
            "<7i", f.read(28)
        )
        shared = raw_vocab > 0
        vocab_size = abs(raw_vocab)
        kv_dim = n_kv_heads * (dim // n_heads)

        def rd_f32(count: int) -> list[float]:
            return list(struct.unpack(f"<{count}f", f.read(count * 4)))

        tok_emb = rd_f32(vocab_size * dim)
        rms_att_all = [rd_f32(dim) for _ in range(n_layers)]
        wq_all = [rd_f32(dim * dim) for _ in range(n_layers)]
        wk_all = [rd_f32(kv_dim * dim) for _ in range(n_layers)]
        wv_all = [rd_f32(kv_dim * dim) for _ in range(n_layers)]
        wo_all = [rd_f32(dim * dim) for _ in range(n_layers)]
        rms_ffn_all = [rd_f32(dim) for _ in range(n_layers)]
        w1_all = [rd_f32(hidden_dim * dim) for _ in range(n_layers)]
        w2_all = [rd_f32(dim * hidden_dim) for _ in range(n_layers)]
        w3_all = [rd_f32(hidden_dim * dim) for _ in range(n_layers)]
        rms_final = rd_f32(dim)
        # Skip legacy RoPE tables if present before wcls
        rem = os.path.getsize(bin_path) - f.tell()
        rope_bytes = seq_len * (dim // n_heads) * 4
        if not shared and rem >= rope_bytes + vocab_size * dim * 4:
            f.read(rope_bytes)
        w_cls = None if shared else rd_f32(vocab_size * dim)

    if tok_json:
        with open(tok_json, "r", encoding="utf-8") as tf:
            tdata = json.load(tf)
        vocab = [(str(item[0]), float(item[1])) for item in tdata[:vocab_size]]
    else:
        vocab = [("<pad>", -10.0), ("<bos>", -10.0), ("<eos>", -10.0)]
        for i in range(3, vocab_size):
            vocab.append((chr(i) if 32 <= i < 127 else f"<t{i}>", 0.0))

    layers = [
        {
            "rms_att": rms_att_all[l],
            "wq": wq_all[l],
            "wk": wk_all[l],
            "wv": wv_all[l],
            "wo": wo_all[l],
            "rms_ffn": rms_ffn_all[l],
            "w1": w1_all[l],
            "w2": w2_all[l],
            "w3": w3_all[l],
        }
        for l in range(n_layers)
    ]
    return pack_nxm_v1(
        vocab, dim, hidden_dim, n_layers, n_heads, n_kv_heads, seq_len, 10000.0, tok_emb, layers, rms_final, w_cls
    )


def convert_from_json(json_path: str) -> bytes:
    with open(json_path, "r", encoding="utf-8") as f:
        spec = json.load(f)
    cfg = spec["config"]
    vocab = [(str(t[0]), float(t[1])) for t in spec["vocab"]]
    return pack_nxm_v1(
        vocab=vocab,
        dim=int(cfg["dim"]),
        hidden_dim=int(cfg["hidden_dim"]),
        n_layers=int(cfg["n_layers"]),
        n_heads=int(cfg["n_heads"]),
        n_kv_heads=int(cfg.get("n_kv_heads", cfg["n_heads"])),
        max_seq=int(cfg.get("max_seq", 64)),
        rope_theta=float(cfg.get("rope_theta", 10000.0)),
        tok_emb=[float(x) for x in spec["tok_emb"]],
        layers=[
            {k: [float(x) for x in v] for k, v in lw.items()}
            for lw in spec["layers"]
        ],
        rms_final=[float(x) for x in spec["rms_final"]],
        w_cls=[float(x) for x in spec["w_cls"]] if spec.get("w_cls") is not None else None,
    )


def main() -> None:
    p = argparse.ArgumentParser(description="Convert GGUF / llama2.c / JSON weights to NexOS .nxm v1")
    p.add_argument("--input", "-i", help="Input model path (.gguf, .bin, or .json)")
    p.add_argument("--output", "-o", help="Output .nxm path")
    p.add_argument(
        "--format",
        choices=["auto", "gguf", "llama2c", "json"],
        default="auto",
        help="Input format (default: auto-detect)",
    )
    p.add_argument("--tokenizer", help="Optional tokenizer JSON [[text, score], ...] for llama2.c")
    p.add_argument("--verify", metavar="NXM_FILE", help="Verify an existing .nxm file and print summary")
    args = p.parse_args()

    if args.verify:
        info = verify_nxm_file(args.verify)
        print(json.dumps(info, indent=2))
        return

    if not args.input or not args.output:
        p.error("--input and --output are required unless --verify is used")

    fmt = args.format
    if fmt == "auto":
        with open(args.input, "rb") as f:
            head = f.read(4)
        if head == GGUF_MAGIC:
            fmt = "gguf"
        elif args.input.endswith(".json"):
            fmt = "json"
        else:
            fmt = "llama2c"

    if fmt == "gguf":
        nxm = convert_from_gguf(args.input)
    elif fmt == "json":
        nxm = convert_from_json(args.input)
    else:
        nxm = convert_from_llama2c(args.input, args.tokenizer)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(nxm)
    info = verify_nxm_file(args.output)
    print(f"Converted {args.input} ({fmt}) -> {args.output}: {info}")


if __name__ == "__main__":
    main()
