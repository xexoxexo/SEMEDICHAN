import os
import time

import numpy as np
import pytest

from components import steganography as stego
from utils import crypto_utils as mc
from utils import db_helper as db
from utils import web3_utils as w3

ADDR_P = "0x" + "a" * 40
ADDR_D = "0x" + "b" * 40
ADDR_X = "0x" + "c" * 40


# ------------------------------------------------------------------ stenografi
@pytest.mark.parametrize("shape", [(200, 200), (96, 96, 3)])
@pytest.mark.parametrize("key", [None, b"k" * 32])
def test_stego_roundtrip(shape, key):
    cover = np.random.default_rng(3).integers(0, 256, shape, dtype=np.uint8)
    payload = os.urandom(1500)
    out = stego.embed(cover, payload, key)
    assert stego.extract(out, key)[0] == payload
    assert stego.psnr(cover, out) > 50
    assert np.abs(out.astype(int) - cover.astype(int)).max() <= 1  # hanya LSB yang berubah


def test_stego_empty_and_capacity():
    cover = stego.make_sample_cover(128)
    assert stego.extract(stego.embed(cover, b""), None)[0] == b""
    with pytest.raises(stego.StegoError):
        stego.embed(cover, os.urandom(stego.capacity_bytes(cover) + 1))
    assert len(stego.extract(stego.embed(cover, os.urandom(stego.capacity_bytes(cover)), b"x" * 32), b"x" * 32)[0]) == stego.capacity_bytes(cover)


def test_stego_wrong_key_and_clean_image():
    cover = stego.make_sample_cover(128)
    payload = b"rahasia" * 20
    out = stego.embed(cover, payload, b"a" * 32)
    assert stego.extract(out, b"b" * 32)[0] != payload
    with pytest.raises(stego.StegoError):
        stego.extract(cover)


def test_stego_survives_png_and_bmp_files():
    cover = stego.make_sample_cover(128)
    out = stego.embed(cover, b"halo" * 50, b"k" * 32)
    for enc in (stego.to_png_bytes, stego.to_bmp_bytes):
        assert stego.extract(stego.load_image(enc(out)), b"k" * 32)[0] == b"halo" * 50


def test_hex_diff_aligned():
    cover = stego.make_sample_cover(64)
    out = stego.embed(cover, b"x" * 100)
    d = stego.byte_diffs(stego.to_bmp_bytes(cover), stego.to_bmp_bytes(out))
    assert d["size_a"] == d["size_b"] and d["total"] > 0 and d["first_offset"] >= 54


# ------------------------------------------------------------------ kriptografi hybrid
@pytest.fixture(scope="module")
def keys():
    return {a: mc.generate_user_keypair(a) for a in (ADDR_P, ADDR_D, ADDR_X)}


@pytest.mark.parametrize("pp", [None, "rahasia"])
def test_hybrid_roundtrip_multi_recipient(keys, pp):
    rec = {"diagnosis": "Pneumonia", "angka": list(range(30))}
    blob = mc.encrypt_record(rec, [(ADDR_P, keys[ADDR_P][0]), (ADDR_D, keys[ADDR_D][0])], pp)
    assert mc.decrypt_record(blob, ADDR_P, keys[ADDR_P][1], pp) == rec
    assert mc.decrypt_record(blob, ADDR_D, keys[ADDR_D][1], pp) == rec
    with pytest.raises(mc.MediCryptError):  # bukan penerima
        mc.decrypt_record(blob, ADDR_X, keys[ADDR_X][1], pp)


def test_hybrid_rejects_wrong_passphrase_and_tamper(keys):
    blob = mc.encrypt_record({"a": 1}, [(ADDR_P, keys[ADDR_P][0])], "benar")
    with pytest.raises(mc.MediCryptError):
        mc.decrypt_record(blob, ADDR_P, keys[ADDR_P][1], "salah")
    with pytest.raises(mc.MediCryptError):
        mc.decrypt_record(blob, ADDR_P, keys[ADDR_P][1], None)
    for i in (10, 60, len(blob) - 1):  # header, daftar penerima, ciphertext
        bad = bytearray(blob)
        bad[i] ^= 1
        with pytest.raises(mc.MediCryptError):
            mc.decrypt_record(bytes(bad), ADDR_P, keys[ADDR_P][1], "benar")


def test_hybrid_user_key_bound_to_address(keys):
    blob = mc.encrypt_record({"a": 1}, [(ADDR_P, keys[ADDR_P][0])])
    with pytest.raises(mc.MediCryptError):  # kunci privat milik alamat lain tidak bisa dibuka
        mc.decrypt_record(blob, ADDR_P, keys[ADDR_D][1])


def test_lab_payload_roundtrip():
    blob = mc.pack_lab_payload("a.wav", os.urandom(300), "pw")
    name, data, enc = mc.unpack_lab_payload(blob, "pw")
    assert name == "a.wav" and enc and len(data) == 300
    with pytest.raises(mc.MediCryptError):
        mc.unpack_lab_payload(blob, "salah")


# ------------------------------------------------------------------ Web3 + DB
def test_audit_chain_detects_tamper():
    db.init_db()
    for i in range(3):
        db.log_event(ADDR_P, "uji", str(i))
    assert db.verify_audit_chain()[0]
    from models import AuditLog
    with db.session_scope() as s:
        s.query(AuditLog).order_by(AuditLog.id).first().detail = "dimanipulasi"
    ok, bad_id, _ = db.verify_audit_chain()
    assert not ok and bad_id is not None


# ------------------------------------------------------------------ login satu klik (challenge tanpa alamat)
def _signed_challenge(label="satu-klik"):
    db.init_db()
    ch = db.issue_challenge()
    acct = w3.dev_wallet(label)
    message = ch["template"].replace(w3.ADDRESS_TOKEN, acct.address)  # persis yang dilakukan frontend
    address, sig = w3.sign_with_dev_wallet(label, message)
    return ch, address, message, sig


def test_challenge_login_ok_and_replay_rejected():
    ch, address, message, sig = _signed_challenge()
    assert w3.verify_signature(message, sig, address)
    assert db.consume_challenge(address, ch["nonce"], message) is True
    assert db.consume_challenge(address, ch["nonce"], message) is False  # sekali pakai


def test_challenge_rejects_tampered_message_and_wrong_address():
    ch, address, message, sig = _signed_challenge("satu-klik-2")
    assert db.consume_challenge(address, ch["nonce"], message.replace("Nonce:", "Nonce: ")) is False
    assert db.consume_challenge(ADDR_X, ch["nonce"], message) is False  # alamat lain -> pesan rekonstruksi beda
    assert db.consume_challenge(address, "nonce-palsu", message) is False
    assert db.consume_challenge(address, ch["nonce"], message) is True  # percobaan gagal tidak membakar nonce


def test_challenge_expiry():
    from models import AuthNonce
    ch, address, message, _ = _signed_challenge("satu-klik-3")
    with db.session_scope() as s:
        s.query(AuthNonce).filter_by(nonce=ch["nonce"]).one().expires_at = time.time() - 1
    assert db.consume_challenge(address, ch["nonce"], message) is False
