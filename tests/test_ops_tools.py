"""Alat operasional: admin CLI, backup/verify/restore, rotasi master key, checkpoint audit."""
import io
import json
import tarfile
from typing import Any, cast

import pytest

import config
from tests.test_clinical_sharing import _make_record, _person
from tools import manage
from utils import auth, totp
from utils import db_helper as db
from utils import record_service as rs

PW = "kunci-rahasia1"


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    """Database + folder stego + master key terpisah per tes."""
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "STEGO_DIR", tmp_path / "stego")
    monkeypatch.setattr(config, "DATABASE_URL", f"sqlite:///{(tmp_path / 'uji.db').as_posix()}")
    monkeypatch.setenv("MEDICRYPT_MASTER_KEY", "kunci-A-0123456789-0123456789-abcdefgh")
    db.get_engine.cache_clear()
    db.init_db()
    yield tmp_path
    monkeypatch.undo()
    db.get_engine.cache_clear()


def _populate():
    patient, doctor = _person("pasien-ops", "patient"), _person("dokter-ops", "doctor")
    patient = cast(Any, patient)
    rec, _ = _make_record(patient, doctor, "rahasia-ops")
    acct = db.get_account_by_wallet(patient.address)
    if acct is None:
        raise RuntimeError("Account not found for patient wallet")
    secret, codes = totp.new_secret(), totp.new_recovery_codes()
    db.enable_mfa(acct.id, secret, codes)
    return patient, doctor, rec, acct, secret, codes


# ------------------------------------------------------------------ admin CLI
@pytest.mark.usefixtures("isolated")
def test_cli_admin_mfa_unlock():
    assert manage.main(["create-admin", "--email", "cli.admin@gmail.com", "--name", "Admin CLI", "--password", PW]) == 0
    acct = db.get_account_by_email("cli.admin@gmail.com")
    assert acct is not None
    assert acct.role == "admin" and acct.is_approved and acct.email_verified
    assert manage.main(["create-admin", "--email", "cli.admin@gmail.com", "--name", "X", "--password", PW]) == 1   # duplikat
    assert manage.main(["create-admin", "--email", "lemah@gmail.com", "--name", "X", "--password", "password123"]) == 1
    db.enable_mfa(acct.id, totp.new_secret(), totp.new_recovery_codes())
    for _ in range(auth.MAX_FAILED):
        db.record_login_failure(acct.id)
    assert db.get_account(acct.id).locked_until > 0
    assert manage.main(["unlock", "--email", "cli.admin@gmail.com"]) == 0 and db.get_account(acct.id).locked_until == 0
    assert manage.main(["reset-mfa", "--email", "cli.admin@gmail.com"]) == 0 and not db.get_account(acct.id).mfa_enabled
    assert manage.main(["reset-mfa", "--email", "tidak.ada@gmail.com"]) == 1
    actions = [l.action for l in db.list_logs(50)]
    assert {"admin_dibuat_cli", "mfa_direset_cli", "akun_dibuka_cli"} <= set(actions)


@pytest.mark.usefixtures("isolated")
def test_cli_check_config_and_audit_checkpoint(tmp_path):
    assert manage.main(["check-config"]) == 0
    db.log_event("0x" + "a" * 40, "uji_cli")
    cp = tmp_path / "cp.json"
    assert manage.main(["checkpoint", "--out", str(cp)]) == 0
    assert manage.main(["verify-audit", "--checkpoint", str(cp)]) == 0
    db.log_event("0x" + "a" * 40, "uji_cli_2")
    assert manage.main(["verify-audit", "--checkpoint", str(cp)]) == 0           # penambahan normal tetap valid
    data = json.loads(cp.read_text())
    data["count"] += 3
    cp.write_text(json.dumps(data))
    assert manage.main(["verify-audit", "--checkpoint", str(cp)]) == 1           # checkpoint dipalsukan


# ------------------------------------------------------------------ backup & restore (skenario bencana)
@pytest.mark.usefixtures("isolated")
def test_backup_verify_tamper_and_disaster_restore(tmp_path):
    patient, _, rec, _, _, _ = _populate()
    backup = tmp_path / "out" / "cadangan.tar.gz"
    assert manage.main(["backup", "--out", str(backup)]) == 0
    assert manage.main(["verify-backup", "--file", str(backup)]) == 0

    # backup yang dimodifikasi ditolak (hash berkas)
    tampered = tmp_path / "rusak.tar.gz"
    with tarfile.open(backup) as src, tarfile.open(tampered, "w:gz") as dst:
        for m in src.getmembers():
            extracted = src.extractfile(m)
            assert extracted is not None
            blob = extracted.read()
            if m.name.startswith("stego/"):
                blob = blob[:-1] + bytes([blob[-1] ^ 1])
            info = tarfile.TarInfo(m.name)
            info.size = len(blob)
            dst.addfile(info, io.BytesIO(blob))
    assert manage.main(["verify-backup", "--file", str(tampered)]) == 1
    # manifest yang dipalsukan ditolak (tanda tangan)
    forged = tmp_path / "palsu.tar.gz"
    with tarfile.open(backup) as src, tarfile.open(forged, "w:gz") as dst:
        for m in src.getmembers():
            extracted = src.extractfile(m)
            assert extracted is not None
            blob = extracted.read()
            if m.name == "manifest.json":
                blob = blob.replace(b'"versi": 1', b'"versi": 2')
            info = tarfile.TarInfo(m.name)
            info.size = len(blob)
            dst.addfile(info, io.BytesIO(blob))
    assert manage.main(["verify-backup", "--file", str(forged)]) == 1

    # bencana: database dan semua file stego hilang
    db.get_engine().dispose()
    db.get_engine.cache_clear()
    (tmp_path / "uji.db").unlink()
    for f in (tmp_path / "stego").glob("*"):
        f.unlink()
    assert manage.main(["restore", "--file", str(backup)]) == 0
    assert manage.main(["restore", "--file", str(backup)]) == 1                  # menolak menimpa tanpa --force
    assert manage.main(["restore", "--file", str(backup), "--force"]) == 0

    db.get_engine.cache_clear()
    db.init_db()
    restored = db.get_record(rec.id)
    assert restored is not None
    assert restored.title == "Uji" and rs.open_record(restored, patient, "rahasia-ops")["diagnosis"] == "Bronkitis"
    restored_account = db.get_account_by_email("pasien-ops.berbagi@gmail.com")
    assert restored_account is not None and restored_account.mfa_enabled
    assert db.verify_audit_chain()[0]


# ------------------------------------------------------------------ rotasi master key
@pytest.mark.usefixtures("isolated")
def test_rotate_master_key_end_to_end(monkeypatch):
    patient, _, rec, acct, secret, codes = _populate()
    from models import SystemMeta
    from utils import fieldcrypt

    monkeypatch.setenv("MEDICRYPT_MASTER_KEY_OLD", "kunci-A-0123456789-0123456789-abcdefgh")
    monkeypatch.setenv("MEDICRYPT_MASTER_KEY", "kunci-B-9876543210-9876543210-hgfedcba")
    # selama transisi (cincin kunci) semuanya tetap terbaca tanpa rotasi
    transition_account = db.get_account_by_email("pasien-ops.berbagi@gmail.com")
    assert transition_account is not None and transition_account.full_name == "Pasien-Ops"
    assert rs.open_record(db.get_record(rec.id), patient, "rahasia-ops")["diagnosis"] == "Bronkitis"
    db.check_master_key()                                                        # kunci lama di cincin: boleh start

    assert manage.main(["rotate-master", "--dry-run"]) == 0
    with db.session_scope() as s:
        meta = s.get(SystemMeta, "master_fingerprint")
        assert meta is not None
        assert meta.value == fieldcrypt.fingerprint(config.master_keys()[1])   # belum berubah
    assert manage.main(["rotate-master"]) == 0
    with db.session_scope() as s:
        meta = s.get(SystemMeta, "master_fingerprint")
        assert meta is not None
        assert meta.value == fieldcrypt.fingerprint(config.master_key())

    # kunci lama dibuang: semua tetap berfungsi
    monkeypatch.delenv("MEDICRYPT_MASTER_KEY_OLD")
    db.check_master_key()
    again = db.get_account_by_email("PASIEN-OPS.berbagi+x@gmail.com")
    assert again is not None and again.totp_secret == secret                     # blind index + kolom terenkripsi dirotasi
    rotated_record = db.get_record(rec.id)
    rotated_user = db.get_user(patient.address)
    assert rotated_record is not None and rotated_user is not None
    assert rotated_record.cover_name == "c.png" and rotated_user.name == "Pasien-Ops"
    fresh = db.get_user(patient.address)
    assert fresh is not None
    patient.enc_priv = fresh.enc_priv                                            # kunci privat sudah dibungkus ulang
    assert rs.open_record(db.get_record(rec.id), patient, "rahasia-ops")["diagnosis"] == "Bronkitis"
    assert db.use_recovery_code(acct.id, codes[0]) is True                       # kode pemulihan tetap berlaku
    assert db.verify_checkpoint(db.audit_checkpoint())[0]

    # kunci lama saja sudah tidak cocok lagi dengan data
    monkeypatch.setenv("MEDICRYPT_MASTER_KEY", "kunci-A-0123456789-0123456789-abcdefgh")
    with pytest.raises(RuntimeError, match="tidak cocok"):
        db.check_master_key()


@pytest.mark.usefixtures("isolated")
def test_rotate_requires_old_key():
    assert manage.main(["rotate-master"]) == 1
