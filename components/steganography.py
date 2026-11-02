"""Mesin stenografi LSB untuk citra medis (grayscale / RGB, lossless PNG/BMP).

Tata letak data pada citra (aliran nilai piksel hasil ``reshape(-1)``):
  * 64 LSB pertama  -> header utama: MAGIC "SMW1" (4 B) + panjang payload utama (4 B, big-endian)
  * [opsional] 64 LSB berikutnya -> header PHI: MAGIC "PHI1" (4 B) + panjang PHI (4 B, big-endian) + data PHI
  * LSB berikutnya  -> payload utama; berurutan (tanpa key) atau tersebar acak berkunci (dengan key)

Posisi acak dibangun dari permutasi pseudo-acak berkunci (jaringan Feistel + cycle-walking),
murni aritmetika integer sehingga hasilnya identik di semua versi NumPy.
Kerahasiaan isi pesan TIDAK bergantung pada penyebaran posisi: payload sudah terenkripsi AES-GCM.
"""
from __future__ import annotations

import hashlib
import io
import os

import cv2
import numpy as np
from PIL import Image

MAGIC = b"SMW1"
MAGIC_PHI = b"PHI1"
HEADER_BITS = 64
PHI_HEADER_BITS = 64


class StegoError(Exception):
    """Kesalahan yang aman ditampilkan ke pengguna."""


# --------------------------------------------------------------------------- I/O
def load_image(data: bytes, max_pixels: int | None = None) -> np.ndarray:
    """Baca byte gambar -> array uint8 (H,W) untuk grayscale atau (H,W,3) untuk RGB."""
    try:
        img = Image.open(io.BytesIO(data))
        if max_pixels and img.width * img.height > max_pixels:
            raise StegoError(
                f"Citra terlalu besar ({img.width}x{img.height}). Batas {max_pixels:,} piksel."
            )
        img.load()
    except StegoError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise StegoError("File bukan gambar yang valid (gunakan PNG, BMP, atau JPG).") from exc

    if img.mode in ("I;16", "I;16L", "I;16B", "I", "F"):  # citra medis 16-bit -> 8-bit
        a = np.asarray(img, dtype=np.float64)
        lo, hi = float(a.min()), float(a.max())
        return ((a - lo) / ((hi - lo) or 1.0) * 255.0).astype(np.uint8)
    if img.mode == "L":
        return np.asarray(img, dtype=np.uint8).copy()
    if img.mode in ("1", "LA", "La"):
        return np.asarray(img.convert("L"), dtype=np.uint8).copy()
    return np.asarray(img.convert("RGB"), dtype=np.uint8).copy()


def to_png_bytes(arr: np.ndarray) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    return buf.getvalue()


def to_bmp_bytes(arr: np.ndarray) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="BMP")
    return buf.getvalue()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- posisi acak
def _round(r: np.ndarray, rk: int, mask: np.uint64) -> np.ndarray:
    x = (r ^ np.uint64(rk)) * np.uint64(0x9E3779B97F4A7C15)
    x ^= x >> np.uint64(31)
    x *= np.uint64(0xBF58476D1CE4E5B9)
    x ^= x >> np.uint64(29)
    return x & mask


def _prp(idx: np.ndarray, domain: int, key: bytes, rounds: int = 6) -> np.ndarray:
    """Permutasi pseudo-acak berkunci atas [0, domain) (Feistel + cycle-walking)."""
    bits = max(2, (domain - 1).bit_length())
    if bits % 2:
        bits += 1
    half = bits // 2
    mask = np.uint64((1 << half) - 1)
    sh = np.uint64(half)
    rks = [int.from_bytes(hashlib.sha256(key + bytes([i])).digest()[:8], "big") for i in range(rounds)]

    def enc(x: np.ndarray) -> np.ndarray:
        left, right = (x >> sh) & mask, x & mask
        for rk in rks:
            left, right = right, left ^ _round(right, rk, mask)
        return (left << sh) | right

    out = enc(idx)
    limit = np.uint64(domain)
    bad = out >= limit
    while bad.any():
        out[bad] = enc(out[bad])
        bad = out >= limit
    return out


def _positions(total: int, n_bits: int, key: bytes | None, offset: int = HEADER_BITS) -> np.ndarray:
    domain = total - offset
    if key is None:
        return np.arange(offset, offset + n_bits, dtype=np.int64)
    perm = _prp(np.arange(n_bits, dtype=np.uint64), domain, key)
    return perm.astype(np.int64) + offset


# Magics untuk ekstensi (seperti PHI, DIA, SIG, dll.)
MAGIC_PHI = b"PHI1"
MAGIC_DIAG = b"DIA1"
MAGIC_SIG = b"SIG1"

HEADER_BITS = 64
PHI_HEADER_BITS = 64
DIAG_HEADER_BITS = 64
SIG_HEADER_BITS = 64  # Jika kita ingin menyembunyikan signature secara terpisah


def capacity_bytes(arr: np.ndarray, phi_len: int = 0, diag_len: int = 0) -> int:
    offset = HEADER_BITS
    if phi_len > 0:
        offset += PHI_HEADER_BITS + (phi_len * 8)
    if diag_len > 0:
        offset += DIAG_HEADER_BITS + (diag_len * 8)
    return max(0, (int(arr.size) - offset) // 8)


def embed(cover: np.ndarray, payload: bytes, key: bytes | None = None, phi_payload: bytes | None = None, diag_payload: bytes | None = None, sig_payload: bytes | None = None) -> np.ndarray:
    phi_len = len(phi_payload) if phi_payload else 0
    diag_len = len(diag_payload) if diag_payload else 0
    sig_len = len(sig_payload) if sig_payload else 0
    cap = capacity_bytes(cover, phi_len, diag_len)
    if len(payload) > cap:
        raise StegoError(
            f"Payload {len(payload):,} B melebihi kapasitas citra {cap:,} B. "
            "Gunakan citra lebih besar atau perkecil payload."
        )
    flat = np.ascontiguousarray(cover).reshape(-1).copy()

    # 1. Header utama
    header = MAGIC + len(payload).to_bytes(4, "big")
    hbits = np.unpackbits(np.frombuffer(header, dtype=np.uint8))
    flat[:HEADER_BITS] = (flat[:HEADER_BITS] & 0xFE) | hbits

    offset = HEADER_BITS

    # 2. PHI (opsional)
    if phi_payload:
        phi_header = MAGIC_PHI + len(phi_payload).to_bytes(4, "big")
        ph_bits = np.unpackbits(np.frombuffer(phi_header, dtype=np.uint8))
        flat[offset : offset + PHI_HEADER_BITS] = (flat[offset : offset + PHI_HEADER_BITS] & 0xFE) | ph_bits
        offset += PHI_HEADER_BITS
        p_bits = np.unpackbits(np.frombuffer(phi_payload, dtype=np.uint8))
        flat[offset : offset + p_bits.size] = (flat[offset : offset + p_bits.size] & 0xFE) | p_bits
        offset += p_bits.size

    # 3. Diagnosis (opsional)
    if diag_payload:
        diag_header = MAGIC_DIAG + len(diag_payload).to_bytes(4, "big")
        dh_bits = np.unpackbits(np.frombuffer(diag_header, dtype=np.uint8))
        flat[offset : offset + DIAG_HEADER_BITS] = (flat[offset : offset + DIAG_HEADER_BITS] & 0xFE) | dh_bits
        offset += DIAG_HEADER_BITS
        d_bits = np.unpackbits(np.frombuffer(diag_payload, dtype=np.uint8))
        flat[offset : offset + d_bits.size] = (flat[offset : offset + d_bits.size] & 0xFE) | d_bits
        offset += d_bits.size

    # 4. Signature (opsional) - disembunyikan setelah diagnosis (secara berurutan)
    if sig_payload:
        sig_header = MAGIC_SIG + len(sig_payload).to_bytes(4, "big")
        sh_bits = np.unpackbits(np.frombuffer(sig_header, dtype=np.uint8))
        flat[offset : offset + SIG_HEADER_BITS] = (flat[offset : offset + SIG_HEADER_BITS] & 0xFE) | sh_bits
        offset += SIG_HEADER_BITS
        s_bits = np.unpackbits(np.frombuffer(sig_payload, dtype=np.uint8))
        flat[offset : offset + s_bits.size] = (flat[offset : offset + s_bits.size] & 0xFE) | s_bits
        offset += s_bits.size

    # 5. Payload utama (acak berkunci dari offset sisa)
    if payload:
        bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
        pos = _positions(flat.size, bits.size, key, offset=offset)
        flat[pos] = (flat[pos] & 0xFE) | bits

    return flat.reshape(cover.shape)


def extract(stego: np.ndarray, key: bytes | None = None) -> tuple[bytes, bytes | None, bytes | None, bytes | None]:
    """Ekstrak payload. Return (payload_utama, phi_payload_jika_ada, diag_payload_jika_ada, sig_payload_jika_ada)"""
    flat = np.ascontiguousarray(stego).reshape(-1)
    if flat.size < HEADER_BITS:
        raise StegoError("Citra terlalu kecil untuk memuat data stego.")

    header = np.packbits(flat[:HEADER_BITS] & 1).tobytes()
    if header[:4] != MAGIC:
        raise StegoError("Tidak ditemukan data stego pada citra ini (header tidak dikenali).")
    n = int.from_bytes(header[4:8], "big")

    offset = HEADER_BITS
    phi_payload = None
    diag_payload = None
    sig_payload = None

    # Coba ekstrak PHI
    if flat.size >= offset + PHI_HEADER_BITS:
        phi_header = np.packbits(flat[offset : offset + PHI_HEADER_BITS] & 1).tobytes()
        if phi_header[:4] == MAGIC_PHI:
            n_phi = int.from_bytes(phi_header[4:8], "big")
            offset += PHI_HEADER_BITS
            if offset + (n_phi * 8) <= flat.size:
                phi_payload = np.packbits(flat[offset : offset + (n_phi * 8)] & 1).tobytes()
                offset += n_phi * 8

    # Coba ekstrak Diagnosis
    if flat.size >= offset + DIAG_HEADER_BITS:
        diag_header = np.packbits(flat[offset : offset + DIAG_HEADER_BITS] & 1).tobytes()
        if diag_header[:4] == MAGIC_DIAG:
            n_diag = int.from_bytes(diag_header[4:8], "big")
            offset += DIAG_HEADER_BITS
            if offset + (n_diag * 8) <= flat.size:
                diag_payload = np.packbits(flat[offset : offset + (n_diag * 8)] & 1).tobytes()
                offset += n_diag * 8

    # Coba ekstrak Signature (opsional)
    if flat.size >= offset + SIG_HEADER_BITS:
        sig_header = np.packbits(flat[offset : offset + SIG_HEADER_BITS] & 1).tobytes()
        if sig_header[:4] == MAGIC_SIG:
            n_sig = int.from_bytes(sig_header[4:8], "big")
            offset += SIG_HEADER_BITS
            if offset + (n_sig * 8) <= flat.size:
                sig_payload = np.packbits(flat[offset : offset + (n_sig * 8)] & 1).tobytes()
                offset += n_sig * 8

    if n > capacity_bytes(stego, len(phi_payload) if phi_payload else 0, len(diag_payload) if diag_payload else 0):
        raise StegoError("Header stego rusak: panjang payload melebihi kapasitas citra.")

    if n == 0:
        return b"", phi_payload, diag_payload, sig_payload

    pos = _positions(flat.size, n * 8, key, offset=offset)
    return np.packbits(flat[pos] & 1).tobytes(), phi_payload, diag_payload, sig_payload


def scrub(stego: np.ndarray, key: bytes | None, keep_bytes: int, old_bytes: int) -> np.ndarray:
    """Timpa sisa bit payload lama (setelah payload baru yang lebih pendek) dengan bit acak.

    Tanpa ini, bit payload lama (mis. daftar penerima yang sudah dicabut) tetap bisa dibaca dari citra.
    """
    if old_bytes <= keep_bytes:
        return stego
    flat = np.ascontiguousarray(stego).reshape(-1).copy()
    pos = _positions(flat.size, old_bytes * 8, key)[keep_bytes * 8:]
    noise = np.frombuffer(os.urandom(len(pos)), dtype=np.uint8) & 1
    flat[pos] = (flat[pos] & 0xFE) | noise
    return flat.reshape(stego.shape)


# --------------------------------------------------------------------------- metrik & visual
def psnr(a: np.ndarray, b: np.ndarray) -> float:
    mse = float(np.mean((a.astype(np.float64) - b.astype(np.float64)) ** 2))
    return float("inf") if mse == 0 else float(10.0 * np.log10(255.0**2 / mse))


def ssim(a: np.ndarray, b: np.ndarray) -> float:
    from skimage.metrics import structural_similarity

    return float(structural_similarity(a, b, data_range=255, channel_axis=2 if a.ndim == 3 else None))


def changed_values(a: np.ndarray, b: np.ndarray) -> int:
    return int(np.count_nonzero(a != b))


def diff_heatmap(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Peta selisih (nilai 0/1 diperkuat x255) berwarna, RGB."""
    d = np.abs(a.astype(np.int16) - b.astype(np.int16))
    if d.ndim == 3:
        d = d.max(axis=2)
    d = np.clip(d * 255, 0, 255).astype(np.uint8)
    return cv2.cvtColor(cv2.applyColorMap(d, cv2.COLORMAP_INFERNO), cv2.COLOR_BGR2RGB)


# --------------------------------------------------------------------------- hex (setara HxD)
def hex_dump(data: bytes, offset: int = 0, length: int = 256, width: int = 16) -> str:
    offset = max(0, min(offset, max(len(data) - 1, 0)))
    chunk = data[offset : offset + length]
    lines = []
    for i in range(0, len(chunk), width):
        row = chunk[i : i + width]
        hexs = " ".join(f"{b:02X}" for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{offset + i:08X}  {hexs:<{width * 3 - 1}}  {asc}")
    return "\n".join(lines)


def byte_diffs(a: bytes, b: bytes, limit: int = 200) -> dict:
    n = min(len(a), len(b))
    x = np.frombuffer(a[:n], dtype=np.uint8)
    y = np.frombuffer(b[:n], dtype=np.uint8)
    idx = np.flatnonzero(x != y)
    rows = [
        {
            "offset": f"0x{int(i):08X}",
            "covertext": f"{int(x[i]):02X}",
            "stegotext": f"{int(y[i]):02X}",
            "biner covertext": f"{int(x[i]):08b}",
            "biner stegotext": f"{int(y[i]):08b}",
        }
        for i in idx[:limit]
    ]
    return {
        "total": int(idx.size),
        "size_a": len(a),
        "size_b": len(b),
        "first_offset": int(idx[0]) if idx.size else None,
        "rows": rows,
    }


# --------------------------------------------------------------------------- citra contoh
def make_sample_cover(size: int = 512, seed: int = 7) -> np.ndarray:
    """Citra grayscale sintetis mirip rontgen dada (BUKAN citra medis asli) untuk uji coba."""
    rng = np.random.default_rng(seed)
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float64) / size

    def blob(cx, cy, sx, sy, amp):
        return amp * np.exp(-(((xx - cx) / sx) ** 2 + ((yy - cy) / sy) ** 2))

    img = blob(0.5, 0.5, 0.46, 0.55, 95)
    img += blob(0.33, 0.45, 0.13, 0.26, -65) + blob(0.67, 0.45, 0.13, 0.26, -65)
    img += blob(0.5, 0.5, 0.035, 0.46, 70)
    img += blob(0.5, 0.62, 0.10, 0.12, 45)
    for k in range(-4, 5):
        img += blob(0.5, 0.45 + k * 0.05, 0.36, 0.007, 22)
    img += rng.normal(0, 5, img.shape)
    return np.clip(img + 35, 0, 255).astype(np.uint8)
