import time

import pytest

import config
from utils import auth
from utils import db_helper as db
from utils import web3_utils as w3


@pytest.fixture(autouse=True)
def isolate_state(monkeypatch):
    """Pastikan setiap test dimulai dari basis data bersih dan konfigurasi default."""
    db.init_db()
    monkeypatch.setattr(config, "ADMIN_EMAILS", set())
    monkeypatch.setattr(config, "AUTO_APPROVE_DOCTORS", True)
    yield
    db.init_db()


# ------------------------------------------------------------------ email & password
def test_email_validation_and_canonical():
    assert auth.validate_email("budi.s@gmail.com") is None
    assert auth.validate_email("budi@yahoo.com")  # bukan Gmail -> ditolak
    assert auth.validate_email("bukan-email")
    assert auth.validate_email("a@gmail")
    assert auth.canonical_email("B.u.d.i+tugas@GMail.com") == auth.canonical_email("budi@gmail.com") == "budi@gmail.com"
    assert auth.canonical_email("budi@googlemail.com") == "budi@gmail.com"


def test_password_policy_and_hashing():
    assert auth.validate_password("pendek1")
    assert auth.validate_password("hanyahuruf")
    assert auth.validate_password("12345678")
    assert auth.validate_password("kunci-rahasia1") is None

    h = auth.hash_password("kunci-rahasia1")
    assert h != auth.hash_password("kunci-rahasia1")
    assert auth.verify_password("kunci-rahasia1", h)
    assert not auth.verify_password("kunci-rahasia2", h)
    assert not auth.verify_password("x", "rusak$format")


# ------------------------------------------------------------------ akun
def _mk(email, role="patient", pw="kunci-rahasia1"):
    return db.create_account(
        email,
        "Nama Uji",
        role,
        auth.hash_password(pw),
        "STR-1" if role == "doctor" else None,
    )


def test_duplicate_email_including_gmail_aliases():
    _mk("dupe.test@gmail.com")
    for alias in ("dupe.test@gmail.com", "dupetest@gmail.com", "d.u.p.e.test+x@googlemail.com"):
        with pytest.raises(ValueError):
            _mk(alias)


def test_admin_email_gets_admin_role_and_doctor_approval_rules(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_EMAILS", {"admin.unit@gmail.com"})

    admin = _mk("admin.unit@gmail.com")
    assert admin is not None and admin.role == "admin"

    doctor = _mk("dokter.satu@gmail.com", "doctor")
    assert doctor is not None and doctor.is_approved is True

    monkeypatch.setattr(config, "AUTO_APPROVE_DOCTORS", False)
    pending = _mk("dokter.dua@gmail.com", "doctor")
    assert pending is not None and pending.is_approved is False
    assert db.approve_account(pending.id)

    approved = db.get_account(pending.id)
    assert approved is not None and approved.is_approved


def test_lockout_after_repeated_failures():
    acct = _mk("lock.test@gmail.com")
    assert acct is not None

    for _ in range(auth.MAX_FAILED):
        db.record_login_failure(acct.id)

    locked = db.get_account(acct.id)
    assert locked is not None and locked.locked_until > time.time()

    db.reset_login_failures(acct.id)
    reset = db.get_account(acct.id)
    assert reset is not None and reset.locked_until == 0


# ------------------------------------------------------------------ penautan dompet
def test_link_wallet_rules():
    a1, a2 = _mk("wallet.satu@gmail.com"), _mk("wallet.dua@gmail.com", "doctor")
    addr1 = w3.dev_wallet("tautan-1").address.lower()
    addr2 = w3.dev_wallet("tautan-2").address.lower()

    db.link_wallet(a1.id, addr1)
    ident = db.get_user(addr1)
    assert ident and ident.enc_pub and ident.role == "patient"

    db.link_wallet(a1.id, addr1)  # idempoten
    with pytest.raises(ValueError):
        db.link_wallet(a1.id, addr2)
    with pytest.raises(ValueError):
        db.link_wallet(a2.id, addr1)

    db.link_wallet(a2.id, addr2)
    user = db.get_user(addr2)
    assert user is not None and user.role == "doctor"
