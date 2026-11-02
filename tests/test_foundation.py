"""Fondasi: enkripsi kolom, migrasi dari DB lama, penjaga master key, profil produksi, rotasi cincin kunci."""
import importlib

import pytest
from sqlalchemy import create_engine, text

import config
from utils import auth, crypto_utils as mc, fieldcrypt


def test_seal_roundtrip_and_legacy_plaintext():
    v = fieldcrypt.seal("Budi Santoso")
    assert v.startswith("enc1:") and "Budi" not in v
    assert fieldcrypt.unseal(v) == "Budi Santoso"
    assert fieldcrypt.seal(v) == v                              # idempoten
    assert fieldcrypt.unseal("teks lama") == "teks lama"        # data lama tanpa awalan tetap terbaca
    assert fieldcrypt.seal(None) is None
    assert fieldcrypt.seal("sama") != fieldcrypt.seal("sama")   # nonce acak


def test_seal_detects_tamper():
    v = fieldcrypt.seal("rahasia")
    bad = v[:-3] + ("AAA" if not v.endswith("AAA") else "BBB")
    with pytest.raises(Exception):
        fieldcrypt.unseal(bad)


def test_blind_index_deterministic_and_keyed():
    a, b = fieldcrypt.blind_index("a@gmail.com"), fieldcrypt.blind_index("a@gmail.com")
    assert a == b and len(a) == 64 and "gmail" not in a
    assert fieldcrypt.blind_index("a@gmail.com", master=b"x" * 32) != a


def test_database_holds_no_plaintext_pii():
    from models import Account
    from utils import db_helper as db
    db.init_db()
    acct = db.create_account("rahasia.pii@gmail.com", "Nama Sangat Rahasia", "doctor", auth.hash_password("kunci-rahasia1"), "STR-99887766")
    with db.get_engine().connect() as conn:
        raw = conn.execute(text("SELECT email, email_key, full_name, license_no FROM accounts WHERE id=:i"), {"i": acct.id}).one()
    blob = " ".join(map(str, raw))
    assert "rahasia.pii" not in blob and "Rahasia" not in blob and "99887766" not in blob
    again = db.get_account_by_email("RAHASIA.pii+x@gmail.com")
    assert again.full_name == "Nama Sangat Rahasia" and again.license_no == "STR-99887766"


def test_migration_encrypts_legacy_plaintext_database(tmp_path, monkeypatch):
    """DB versi lama (kolom plaintext, tanpa kolom baru) dimigrasikan tanpa kehilangan data."""
    from utils import migrations
    eng = create_engine(f"sqlite:///{tmp_path/'lama.db'}")
    with eng.begin() as c:
        c.execute(text("CREATE TABLE accounts (id INTEGER PRIMARY KEY, email VARCHAR(254), email_key VARCHAR(254) UNIQUE, "
                       "full_name VARCHAR(120), role VARCHAR(16), password_hash VARCHAR(300), is_approved BOOLEAN, "
                       "license_no VARCHAR(64), wallet_address VARCHAR(42), failed_attempts INTEGER, locked_until FLOAT, created_at DATETIME)"))
        c.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, address VARCHAR(42), name VARCHAR(120), role VARCHAR(16), "
                       "is_approved BOOLEAN, license_no VARCHAR(64), enc_pub VARCHAR(64), enc_priv TEXT, created_at DATETIME)"))
        c.execute(text("CREATE TABLE medical_records (id VARCHAR(32) PRIMARY KEY, patient_address VARCHAR(42), doctor_address VARCHAR(42), "
                       "title VARCHAR(200), stego_file VARCHAR(80), stego_format VARCHAR(8), cover_name VARCHAR(200), sha256 VARCHAR(64), "
                       "payload_bytes INTEGER, capacity_bytes INTEGER, psnr FLOAT, ssim FLOAT, has_passphrase BOOLEAN, created_at DATETIME)"))
        c.execute(text("INSERT INTO accounts VALUES (1,'lama@gmail.com','lama@gmail.com','Pasien Lama','patient','x',1,NULL,NULL,0,0,'2026-01-01')"))
        c.execute(text("INSERT INTO users VALUES (1,'0x"+"a"*40+"','Pasien Lama','patient',1,NULL,'ab','cd','2026-01-01')"))
        c.execute(text("INSERT INTO medical_records VALUES ('r1','0x"+"a"*40+"','0x"+"b"*40+"','Judul Lama','f.png','PNG','cover-lama.png','h',1,2,50.0,0.9,0,'2026-01-01')"))
    applied = migrations.migrate(eng)
    assert applied == [1, 2, 3, 4, 5, 6, 7, 8]
    with eng.connect() as c:
        a = c.execute(text("SELECT email, email_key, full_name, email_verified FROM accounts")).one()
        r = c.execute(text("SELECT title, cover_name, key_version FROM medical_records")).one()
        rec = c.execute(text("SELECT address, role FROM record_recipients ORDER BY role")).all()
    assert a.email.startswith("enc1:") and a.full_name.startswith("enc1:") and len(a.email_key) == 64
    assert fieldcrypt.unseal(a.email) == "lama@gmail.com" and a.email_verified in (1, True)   # akun lama tetap bisa masuk
    assert r.title.startswith("enc1:") and fieldcrypt.unseal(r.cover_name) == "cover-lama.png" and r.key_version == 1
    assert sorted(x.role for x in rec) == ["author", "patient"]                              # penerima lama diisi otomatis
    assert migrations.migrate(eng) == []                                                      # idempoten


def test_master_key_guard(monkeypatch):
    from utils import db_helper as db
    db.init_db()
    monkeypatch.setenv("MEDICRYPT_MASTER_KEY", "kunci-yang-salah-sama-sekali-0123456789")
    with pytest.raises(RuntimeError, match="tidak cocok"):
        db.check_master_key()
    # selama rotasi: kunci lama ada di cincin -> boleh start
    monkeypatch.setenv("MEDICRYPT_MASTER_KEY_OLD", "")
    monkeypatch.delenv("MEDICRYPT_MASTER_KEY")


def test_keyring_reads_data_sealed_with_old_key(monkeypatch):
    monkeypatch.setenv("MEDICRYPT_MASTER_KEY", "kunci-lama-0123456789-0123456789-abcdef")
    sealed = fieldcrypt.seal("data lama")
    pub, priv = mc.generate_user_keypair("0x" + "d" * 40)
    blob = mc.encrypt_record({"a": 1}, [("0x" + "d" * 40, pub)])
    monkeypatch.setenv("MEDICRYPT_MASTER_KEY", "kunci-baru-0123456789-0123456789-abcdef")
    with pytest.raises(Exception):
        fieldcrypt.unseal(sealed)                                  # tanpa kunci lama: gagal
    monkeypatch.setenv("MEDICRYPT_MASTER_KEY_OLD", "kunci-lama-0123456789-0123456789-abcdef")
    assert fieldcrypt.unseal(sealed) == "data lama"                # dengan cincin kunci: terbaca
    assert mc.decrypt_record(blob, "0x" + "d" * 40, priv) == {"a": 1}


def test_stego_key_v2_independent_of_master(monkeypatch):
    k1 = mc.derive_stego_key_v2("rec1", "pw")
    monkeypatch.setenv("MEDICRYPT_MASTER_KEY", "master-lain-0123456789-0123456789-abcdef")
    assert mc.derive_stego_key_v2("rec1", "pw") == k1
    assert mc.derive_stego_key_v2("rec2", "pw") != k1 and mc.derive_stego_key_v2("rec1", None) != k1


def test_production_profile_rejects_insecure_settings(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("ALLOW_DEV_WALLET", "0")
    monkeypatch.setenv("AUTO_APPROVE_DOCTORS", "0")
    monkeypatch.setenv("MEDICRYPT_MASTER_KEY", "x" * 40)
    monkeypatch.setenv("ADMIN_EMAILS", "a@gmail.com")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("APP_URI", "https://rme.example.com")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg2://u:p@db/x")
    mod = importlib.reload(config)
    try:
        assert mod.production_problems() == []
        assert mod.ALLOW_DEV_WALLET is False
        assert mod.AUTO_APPROVE_DOCTORS is False
        assert mod.REQUIRE_EMAIL_VERIFICATION
        assert {"admin", "doctor"} <= mod.REQUIRE_MFA_ROLES
        assert not mod.ENABLE_LAB
    finally:
        importlib.reload(config)
