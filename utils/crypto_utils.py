"""MediCrypt: enkripsi hybrid untuk rekam medis.

Hybrid = kriptografi kunci-publik (X25519 ECDH + HKDF) untuk membungkus kunci data,
         + kriptografi simetris (AES-256-GCM) untuk mengenkripsi isi rekam medis.

Alur enkripsi satu rekam medis (multi-penerima: pasien + dokter pembuat):
  1. DEK acak 256-bit; payload JSON dikompres lalu dienkripsi AES-256-GCM dengan DEK.
  2. Pasangan kunci X25519 efemeral dibuat. Untuk tiap penerima: ECDH(efemeral, pub penerima)
     -> HKDF-SHA256 -> KEK -> AES-256-GCM membungkus DEK (key wrapping).
  3. Seluruh header (daftar penerima) ikut menjadi AAD payload, sehingga manipulasi terdeteksi.
Passphrase opsional ikut diturunkan (scrypt) ke dalam KEK sebagai faktor tambahan.

Kunci privat X25519 tiap pengguna disimpan terbungkus AES-GCM memakai kunci turunan master key
dan hanya dibuka server untuk sesi yang lolos autentikasi dompet (lihat README: model ancaman).
"""
from __future__ import annotations

import hashlib
import json
import os
import zlib

from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

import config

MAGIC = b"MCR2"
VERSION = 1
NONCE_LEN = 12
RID_LEN = 8
WRAP_LEN = 32 + 16  # DEK + tag GCM


class MediCryptError(Exception):
    """Kesalahan kriptografi yang aman ditampilkan ke pengguna."""


# --------------------------------------------------------------------------- util
def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _scrypt(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode("utf-8"))


def recipient_id(address: str) -> bytes:
    return hashlib.sha256(address.lower().encode()).digest()[:RID_LEN]


# --------------------------------------------------------------------------- kunci pengguna
def generate_user_keypair(address: str, master: bytes | None = None) -> tuple[str, str]:
    """Buat pasangan X25519. Return (pub_hex, kunci_privat_terbungkus_hex)."""
    master = master or config.master_key()
    priv = X25519PrivateKey.generate()
    raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce = os.urandom(NONCE_LEN)
    kek = _hkdf(master, b"MediCrypt-v2-userkey", b"userkey|" + address.lower().encode())
    wrapped = nonce + AESGCM(kek).encrypt(nonce, raw, address.lower().encode())
    return pub.hex(), wrapped.hex()


def generate_ed25519_keypair(address: str, master: bytes | None = None) -> tuple[str, str]:
    """Buat pasangan Ed25519 untuk tanda tangan digital diagnosis.

    Return (pub_hex 64 char, kunci_privat_terbungkus_hex). Kunci privat dibungkus
    AES-GCM dengan master key (pola sama seperti X25519).
    """
    master = master or config.master_key()
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce = os.urandom(NONCE_LEN)
    kek = _hkdf(master, b"MediCrypt-v2-ed25519", b"edkey|" + address.lower().encode())
    wrapped = nonce + AESGCM(kek).encrypt(nonce, raw, address.lower().encode())
    return pub.hex(), wrapped.hex()


def load_ed_private(address: str, wrapped_hex: str, master: bytes) -> Ed25519PrivateKey:
    """Buka kunci privat Ed25519 yang dibungkus master key."""
    blob = bytes.fromhex(wrapped_hex)
    kek = _hkdf(master, b"MediCrypt-v2-ed25519", b"edkey|" + address.lower().encode())
    try:
        raw = AESGCM(kek).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], address.lower().encode())
    except InvalidTag as exc:
        raise MediCryptError("Kunci privat Ed25519 tidak dapat dibuka.") from exc
    return Ed25519PrivateKey.from_private_bytes(raw)


def rewrap_private_key(address: str, wrapped_hex: str) -> str:
    """Buka kunci privat dengan kunci apa pun pada cincin kunci, bungkus ulang dengan master key aktif."""
    last: Exception | None = None
    for m in config.master_keys():
        try:
            raw = _load_private(address, wrapped_hex, m).private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            break
        except MediCryptError as exc:
            last = exc
    else:
        raise MediCryptError("Kunci privat tidak dapat dibuka dengan master key mana pun.") from last
    nonce = os.urandom(NONCE_LEN)
    kek = _hkdf(config.master_key(), b"MediCrypt-v2-userkey", b"userkey|" + address.lower().encode())
    return (nonce + AESGCM(kek).encrypt(nonce, raw, address.lower().encode())).hex()


def _load_private(address: str, wrapped_hex: str, master: bytes) -> X25519PrivateKey:
    blob = bytes.fromhex(wrapped_hex)
    kek = _hkdf(master, b"MediCrypt-v2-userkey", b"userkey|" + address.lower().encode())
    try:
        raw = AESGCM(kek).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], address.lower().encode())
    except InvalidTag as exc:
        raise MediCryptError("Kunci privat pengguna tidak dapat dibuka (master key berubah?).") from exc
    return X25519PrivateKey.from_private_bytes(raw)


# --------------------------------------------------------------------------- stego-key
def derive_stego_key(record_id: str, passphrase: str | None = None, master: bytes | None = None) -> bytes:
    """Kunci penyebar posisi LSB: dari master key + id rekam (+ passphrase)."""
    master = master or config.master_key()
    salt = hashlib.sha256(b"MediCrypt-v2-stego|" + record_id.encode()).digest()[:16]
    ikm = master + (_scrypt(passphrase, salt) if passphrase else b"")
    return _hkdf(ikm, salt, b"stego|" + record_id.encode())


def derive_stego_key_v2(record_id: str, passphrase: str | None = None) -> bytes:
    """Kunci penyebar posisi LSB generasi 2: dari id rekam (+ passphrase), TANPA master key.

    Posisi LSB bukan penjaga kerahasiaan (itu tugas AES-GCM); memutus ketergantungan pada master key membuat
    rotasi master key tidak merusak citra stego yang sudah ada.
    """
    salt = hashlib.sha256(b"MediCrypt-v2-stego2|" + record_id.encode()).digest()[:16]
    ikm = record_id.encode() + (_scrypt(passphrase, salt) if passphrase else b"")
    return _hkdf(ikm, salt, b"stego2|" + record_id.encode())


def stego_key_candidates(record_id: str, key_version: int, passphrase: str | None = None) -> list[bytes]:
    """Kunci yang perlu dicoba untuk rekam ini (v1 memakai setiap master pada cincin kunci)."""
    if key_version >= 2:
        return [derive_stego_key_v2(record_id, passphrase)]
    return [derive_stego_key(record_id, passphrase, m) for m in config.master_keys()]


# --------------------------------------------------------------------------- rekam medis
def _kek(shared: bytes, eph_pub: bytes, rid: bytes, pp: bytes) -> bytes:
    return _hkdf(shared + pp, eph_pub, b"MediCrypt-v2|wrap|" + rid)


def encrypt_record(record: dict, recipients: list[tuple[str, str]], passphrase: str | None = None) -> bytes:
    """recipients: daftar (alamat, pub_hex X25519). Return blob MCR2."""
    if not recipients:
        raise MediCryptError("Minimal satu penerima diperlukan.")
    dek = os.urandom(32)
    payload_nonce = os.urandom(NONCE_LEN)
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pp = _scrypt(passphrase, hashlib.sha256(b"MediCrypt-v2-pp|" + eph_pub).digest()[:16]) if passphrase else b""

    entries = b""
    for address, pub_hex in recipients:
        rid = recipient_id(address)
        shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)))
        wrap_nonce = os.urandom(NONCE_LEN)
        wrapped = AESGCM(_kek(shared, eph_pub, rid, pp)).encrypt(wrap_nonce, dek, rid + eph_pub)
        entries += rid + wrap_nonce + wrapped

    header = MAGIC + bytes([VERSION, 1 if passphrase else 0, len(recipients)]) + payload_nonce + eph_pub + entries
    plaintext = zlib.compress(json.dumps(record, ensure_ascii=False, sort_keys=True).encode("utf-8"), 9)
    return header + AESGCM(dek).encrypt(payload_nonce, plaintext, header)


def _parse(blob: bytes) -> dict:
    if len(blob) < 7 or blob[:4] != MAGIC:
        raise MediCryptError("Data bukan blob MediCrypt yang valid.")
    version, flags, n = blob[4], blob[5], blob[6]
    if version != VERSION:
        raise MediCryptError(f"Versi MediCrypt {version} tidak didukung.")
    pos = 7
    payload_nonce = blob[pos : pos + NONCE_LEN]
    pos += NONCE_LEN
    eph_pub = blob[pos : pos + 32]
    pos += 32
    entries = {}
    for _ in range(n):
        rid = blob[pos : pos + RID_LEN]
        wn = blob[pos + RID_LEN : pos + RID_LEN + NONCE_LEN]
        wrapped = blob[pos + RID_LEN + NONCE_LEN : pos + RID_LEN + NONCE_LEN + WRAP_LEN]
        entries[rid] = (wn, wrapped)
        pos += RID_LEN + NONCE_LEN + WRAP_LEN
    if len(blob) <= pos or len(eph_pub) != 32:
        raise MediCryptError("Blob MediCrypt terpotong/rusak.")
    return {
        "header": blob[:pos], "ciphertext": blob[pos:], "flags": flags, "payload_nonce": payload_nonce,
        "eph_pub": eph_pub, "entries": entries,
    }


def blob_info(blob: bytes) -> dict:
    p = _parse(blob)
    return {"penerima": len(p["entries"]), "passphrase": bool(p["flags"] & 1), "ukuran_byte": len(blob)}


def decrypt_record(
    blob: bytes, address: str, wrapped_priv_hex: str, passphrase: str | None = None,
    master: bytes | None = None,
) -> dict:
    masters = [master] if master else config.master_keys()
    p = _parse(blob)
    rid = recipient_id(address)
    if rid not in p["entries"]:
        raise MediCryptError("Alamat dompet Anda bukan penerima sah rekam medis ini.")
    if p["flags"] & 1 and not passphrase:
        raise MediCryptError("Rekam medis ini dilindungi passphrase. Masukkan passphrase.")
    priv = None
    for m in masters:
        try:
            priv = _load_private(address, wrapped_priv_hex, m)
            break
        except MediCryptError:
            continue
    if priv is None:
        raise MediCryptError("Kunci privat pengguna tidak dapat dibuka (master key berubah?).")
    shared = priv.exchange(X25519PublicKey.from_public_bytes(p["eph_pub"]))
    pp = b""
    if p["flags"] & 1:
        pp = _scrypt(passphrase, hashlib.sha256(b"MediCrypt-v2-pp|" + p["eph_pub"]).digest()[:16])
    wn, wrapped = p["entries"][rid]
    try:
        dek = AESGCM(_kek(shared, p["eph_pub"], rid, pp)).decrypt(wn, wrapped, rid + p["eph_pub"])
        plaintext = AESGCM(dek).decrypt(p["payload_nonce"], p["ciphertext"], p["header"])
    except InvalidTag as exc:
        raise MediCryptError(
            "Dekripsi gagal: passphrase salah atau data telah dimodifikasi (tag AES-GCM tidak cocok)."
        ) from exc
    return json.loads(zlib.decompress(plaintext).decode("utf-8"))


# --------------------------------------------------------------------------- PHI (Protected Health Information)
PHI_MAGIC = b"PHI1"


def encrypt_phi(phi_data: dict, recipients: list[tuple[str, str]], passphrase: str | None = None) -> bytes:
    """Enkripsi data identitas pasien (PHI) dengan format multi-penerima.
    
    phi_data: dict berisi {full_name, medical_record_number, national_id, date_of_birth, address}
    recipients: daftar (alamat, pub_hex X25519)
    Return blob PHI1 terenkripsi.
    """
    if not recipients:
        raise MediCryptError("Minimal satu penerima diperlukan untuk PHI.")
    dek = os.urandom(32)
    payload_nonce = os.urandom(NONCE_LEN)
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pp = _scrypt(passphrase, hashlib.sha256(b"MediCrypt-v2-phi-pp|" + eph_pub).digest()[:16]) if passphrase else b""

    entries = b""
    for address, pub_hex in recipients:
        rid = recipient_id(address)
        shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)))
        wrap_nonce = os.urandom(NONCE_LEN)
        wrapped = AESGCM(_kek(shared, eph_pub, rid, pp)).encrypt(wrap_nonce, dek, rid + eph_pub)
        entries += rid + wrap_nonce + wrapped

    header = PHI_MAGIC + bytes([VERSION, 1 if passphrase else 0, len(recipients)]) + payload_nonce + eph_pub + entries
    plaintext = json.dumps(phi_data, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return header + AESGCM(dek).encrypt(payload_nonce, plaintext, header)


def decrypt_phi(
    blob: bytes, address: str, wrapped_priv_hex: str, passphrase: str | None = None,
    master: bytes | None = None,
) -> dict:
    """Dekripsi data PHI. Return dict {full_name, medical_record_number, national_id, date_of_birth, address}."""
    if len(blob) < 7 or blob[:4] != PHI_MAGIC:
        raise MediCryptError("Data bukan blob PHI yang valid.")
    
    masters = [master] if master else config.master_keys()
    version, flags, n = blob[4], blob[5], blob[6]
    if version != VERSION:
        raise MediCryptError(f"Versi PHI {version} tidak didukung.")
    
    pos = 7
    payload_nonce = blob[pos : pos + NONCE_LEN]
    pos += NONCE_LEN
    eph_pub = blob[pos : pos + 32]
    pos += 32
    entries = {}
    for _ in range(n):
        rid = blob[pos : pos + RID_LEN]
        wn = blob[pos + RID_LEN : pos + RID_LEN + NONCE_LEN]
        wrapped = blob[pos + RID_LEN + NONCE_LEN : pos + RID_LEN + NONCE_LEN + WRAP_LEN]
        entries[rid] = (wn, wrapped)
        pos += RID_LEN + NONCE_LEN + WRAP_LEN
    
    if len(blob) <= pos or len(eph_pub) != 32:
        raise MediCryptError("Blob PHI terpotong/rusak.")
    
    rid = recipient_id(address)
    if rid not in entries:
        raise MediCryptError("Alamat dompet Anda bukan penerima sah PHI ini.")
    if flags & 1 and not passphrase:
        raise MediCryptError("PHI ini dilindungi passphrase. Masukkan passphrase.")
    
    priv = None
    for m in masters:
        try:
            priv = _load_private(address, wrapped_priv_hex, m)
            break
        except MediCryptError:
            continue
    if priv is None:
        raise MediCryptError("Kunci privat pengguna tidak dapat dibuka (master key berubah?).")
    
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    pp = b""
    if flags & 1:
        pp = _scrypt(passphrase, hashlib.sha256(b"MediCrypt-v2-phi-pp|" + eph_pub).digest()[:16])
    
    wn, wrapped = entries[rid]
    try:
        dek = AESGCM(_kek(shared, eph_pub, rid, pp)).decrypt(wn, wrapped, rid + eph_pub)
        header = blob[:pos]
        ciphertext = blob[pos:]
        plaintext = AESGCM(dek).decrypt(payload_nonce, ciphertext, header)
    except InvalidTag as exc:
        raise MediCryptError(
            "Dekripsi PHI gagal: passphrase salah atau data telah dimodifikasi (tag AES-GCM tidak cocok)."
        ) from exc
    return json.loads(plaintext.decode("utf-8"))


# --------------------------------------------------------------------------- Diagnosis Dokter (MAGIC "DIA1")
DIAG_MAGIC = b"DIA1"
DIAG_VERSION = 1
DIAG_FLAGS_ENC = 1  # bit 0 = encrypted with passphrase


def encrypt_diagnosis(diag_data: dict, recipients: list[tuple[str, str]], passphrase: str | None = None) -> bytes:
    """Enkripsi data diagnosis dokter (diagnosis akhir, riwayat sensitif, obat dosis tinggi).

    Format DIA1: MAGIC(4) | VERSION(1) | FLAGS(1) | N_RECIP(1) | PAYLOAD_NONCE(12)
               | EPH_PUB(32) | recipient entries... | ciphertext
    """
    if not recipients:
        raise MediCryptError("Minimal satu penerima diperlukan untuk diagnosis.")
    dek = os.urandom(32)
    payload_nonce = os.urandom(NONCE_LEN)
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pp = _scrypt(passphrase, hashlib.sha256(b"MediCrypt-v2-diag-pp|" + eph_pub).digest()[:16]) if passphrase else b""

    entries = b""
    for address, pub_hex in recipients:
        rid = recipient_id(address)
        shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)))
        wrap_nonce = os.urandom(NONCE_LEN)
        wrapped = AESGCM(_kek(shared, eph_pub, rid, pp)).encrypt(wrap_nonce, dek, rid + eph_pub)
        entries += rid + wrap_nonce + wrapped

    header = DIAG_MAGIC + bytes([DIAG_VERSION, DIAG_FLAGS_ENC if passphrase else 0, len(recipients)]) + payload_nonce + eph_pub + entries
    plaintext = json.dumps(diag_data, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return header + AESGCM(dek).encrypt(payload_nonce, plaintext, header)


def decrypt_diagnosis(
    blob: bytes, address: str, wrapped_priv_hex: str, passphrase: str | None = None,
    master: bytes | None = None,
) -> dict:
    """Dekripsi data diagnosis dokter."""
    if len(blob) < 7 or blob[:4] != DIAG_MAGIC:
        raise MediCryptError("Data bukan blob diagnosis yang valid.")
    version, flags, n = blob[4], blob[5], blob[6]
    if version != DIAG_VERSION:
        raise MediCryptError(f"Versi diagnosis {version} tidak didukung.")
    pos = 7
    payload_nonce = blob[pos : pos + NONCE_LEN]; pos += NONCE_LEN
    eph_pub = blob[pos : pos + 32]; pos += 32
    entries = {}
    for _ in range(n):
        rid = blob[pos : pos + RID_LEN]
        wn = blob[pos + RID_LEN : pos + RID_LEN + NONCE_LEN]
        wrapped = blob[pos + RID_LEN + NONCE_LEN : pos + RID_LEN + NONCE_LEN + WRAP_LEN]
        entries[rid] = (wn, wrapped); pos += RID_LEN + NONCE_LEN + WRAP_LEN
    if len(blob) <= pos or len(eph_pub) != 32:
        raise MediCryptError("Blob diagnosis terpotong/rusak.")

    rid = recipient_id(address)
    if rid not in entries:
        raise MediCryptError("alamat dompet Anda bukan penerima sah diagnosis ini.")
    if flags & DIAG_FLAGS_ENC and not passphrase:
        raise MediCryptError("Diagnosis dilindungi passphrase. Masukkan passphrase.")

    priv = None
    for m in [master] if master else config.master_keys():
        try:
            priv = _load_private(address, wrapped_priv_hex, m)
            break
        except MediCryptError:
            continue
    if priv is None:
        raise MediCryptError("Kunci privat pengguna tidak dapat dibuka (master key berubah?).")

    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    pp = b""
    if flags & DIAG_FLAGS_ENC:
        pp = _scrypt(passphrase, hashlib.sha256(b"MediCrypt-v2-diag-pp|" + eph_pub).digest()[:16])
    wn, wrapped = entries[rid]
    try:
        dek = AESGCM(_kek(shared, eph_pub, rid, pp)).decrypt(wn, wrapped, rid + eph_pub)
        plaintext = AESGCM(dek).decrypt(payload_nonce, blob[pos:], blob[:pos])
    except InvalidTag as exc:
        raise MediCryptError(
            "Dekripsi diagnosis gagal: passphrase salah atau diagnosis telah dimodifikasi."
        ) from exc
    return json.loads(plaintext.decode("utf-8"))


# --------------------------------------------------------------------------- Tanda Tangan Digital Ed25519 (MAGIC "SIG1")
SIG_MAGIC = b"SIG1"
SIG_VERSION = 1
SIG_LEN_OFF = 5      # sig_len (2 B big-endian)
SIG_PUB_OFF = 7      # public key (32 B)
SIG_PUB_LEN = 32
SIG_SIG_OFF = 39     # signature (64 B)
SIG_SIG_LEN = 64


def sign_diagnosis(message: bytes, ed_priv_hex: str) -> bytes:
    """Tanda tangan Ed25519 dokter atas payload diagnosis (byte raw).

    Return: SIG1 | VERSION(1) | sig_len(2) | pub_key(32) | signature(64)
    """
    if len(ed_priv_hex) != 64:
        raise MediCryptError("Kunci privat Ed25519 harus 32 byte (hex 64 char).")
    ed_priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ed_priv_hex))
    pub_bytes = ed_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = ed_priv.sign(message)
    return SIG_MAGIC + bytes([SIG_VERSION]) + len(sig).to_bytes(2, "big") + pub_bytes + sig


def verify_diagnosis(sig_blob: bytes, message: bytes) -> bool:
    """Verifikasi tanda tangan Ed25519 dokter."""
    if sig_blob[:4] != SIG_MAGIC or sig_blob[4] != SIG_VERSION:
        raise MediCryptError("Blob tanda tangan diagnosis tidak valid.")
    n = int.from_bytes(sig_blob[SIG_LEN_OFF:SIG_LEN_OFF+2], "big")
    if n != SIG_SIG_LEN:
        raise MediCryptError("Panjang signature Ed25519 tidak valid.")
    pub_bytes = sig_blob[SIG_PUB_OFF:SIG_PUB_OFF+SIG_PUB_LEN]
    sig_bytes = sig_blob[SIG_SIG_OFF:SIG_SIG_OFF+SIG_SIG_LEN]
    ed_pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    try:
        ed_pub.verify(sig_bytes, message)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------- Lab (simetris, passphrase)
LAB_MAGIC = b"LAB1"
LAB_ENC_MAGIC = b"MCP1"


def lab_stego_key(passphrase: str) -> bytes:
    return hashlib.sha256(b"StegoMed-lab-key|" + _scrypt(passphrase, b"StegoMed-lab-salt1")).digest()


def pack_lab_payload(name: str, data: bytes, passphrase: str | None = None) -> bytes:
    """Bungkus payload Lab: LAB1 | enc(1) | len_nama(2) | nama | data (opsional AES-256-GCM)."""
    nm = name.encode("utf-8")[:255]
    enc = 0
    if passphrase:
        salt, nonce = os.urandom(16), os.urandom(NONCE_LEN)
        data = LAB_ENC_MAGIC + salt + nonce + AESGCM(_scrypt(passphrase, salt)).encrypt(nonce, data, LAB_ENC_MAGIC)
        enc = 1
    return LAB_MAGIC + bytes([enc]) + len(nm).to_bytes(2, "big") + nm + data


def unpack_lab_payload(blob: bytes, passphrase: str | None = None) -> tuple[str, bytes, bool]:
    if blob[:4] != LAB_MAGIC:
        raise MediCryptError("Payload bukan format Lab StegoMed (LAB1).")
    enc = blob[4] == 1
    nlen = int.from_bytes(blob[5:7], "big")
    name = blob[7 : 7 + nlen].decode("utf-8", errors="replace")
    data = blob[7 + nlen :]
    if enc:
        if not passphrase:
            raise MediCryptError("Payload terenkripsi. Masukkan passphrase.")
        salt, nonce, ct = data[4:20], data[20 : 20 + NONCE_LEN], data[20 + NONCE_LEN :]
        try:
            data = AESGCM(_scrypt(passphrase, salt)).decrypt(nonce, ct, LAB_ENC_MAGIC)
        except InvalidTag as exc:
            raise MediCryptError("Passphrase salah atau payload rusak.") from exc
    return name, data, enc
