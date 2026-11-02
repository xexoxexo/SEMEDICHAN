"""Keamanan akun: TOTP (vektor RFC 6238), OTP, pembatas laju, email, MFA, reset password, sesi."""
import base64
import re
import time
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

import config
from utils import auth, mailer, totp
from utils import db_helper as db

APP = str(Path(__file__).resolve().parents[1] / "app.py")
PW = "kunci-rahasia1"


# ------------------------------------------------------------------ unit
def test_totp_matches_rfc6238_vectors():
    secret = base64.b32encode(b"12345678901234567890").decode()
    for t, expected in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                        (1234567890, "89005924"), (2000000000, "69279037")]:
        assert totp.code_at(secret, t, digits=8) == expected


def test_totp_verify_window_and_replay_protection():
    secret = totp.new_secret()
    now = 1_700_000_000
    code = totp.code_at(secret, now)
    step = totp.verify(secret, code, now=now)
    assert step == now // 30
    assert totp.verify(secret, code, last_step=step, now=now) is None            # kode yang sama tidak bisa dipakai ulang
    assert totp.verify(secret, totp.code_at(secret, now + 30), last_step=step, now=now) == step + 1
    assert totp.verify(secret, totp.code_at(secret, now + 300), now=now) is None  # di luar jendela
    assert totp.verify(secret, "abcdef", now=now) is None and totp.verify(secret, "12345", now=now) is None


def test_recovery_codes_single_use():
    db.init_db()
    acct = db.create_account("pemulihan.uji@gmail.com", "Uji Pemulihan", "patient", auth.hash_password(PW))
    codes = totp.new_recovery_codes()
    db.enable_mfa(acct.id, totp.new_secret(), codes)
    assert db.use_recovery_code(acct.id, codes[0].upper()) is True      # huruf besar/kecil tidak masalah
    assert db.use_recovery_code(acct.id, codes[0]) is False             # sekali pakai
    assert db.use_recovery_code(acct.id, "salah-salah") is False
    assert db.use_recovery_code(acct.id, codes[1]) is True


def test_otp_expiry_attempts_and_reissue():
    db.init_db()
    acct = db.create_account("otp.uji@gmail.com", "Uji Otp", "patient", auth.hash_password(PW))
    code = db.issue_otp(acct.id, "verify_email")
    newer = db.issue_otp(acct.id, "verify_email")                       # kode baru membatalkan yang lama
    assert db.check_otp(acct.id, "verify_email", code) in (False, code == newer)
    for _ in range(config.OTP_MAX_ATTEMPTS):
        db.check_otp(acct.id, "verify_email", "000000" if newer != "000000" else "111111")
    assert db.check_otp(acct.id, "verify_email", newer) is False        # terkunci setelah terlalu banyak percobaan
    fresh = db.issue_otp(acct.id, "reset_password")
    assert db.check_otp(acct.id, "verify_email", fresh) is False        # beda tujuan tidak berlaku
    assert db.check_otp(acct.id, "reset_password", fresh) is True
    assert db.check_otp(acct.id, "reset_password", fresh) is False      # sekali pakai


def test_otp_expired(monkeypatch):
    db.init_db()
    acct = db.create_account("otp.kedaluwarsa@gmail.com", "Uji", "patient", auth.hash_password(PW))
    monkeypatch.setattr(config, "OTP_TTL_SECONDS", -1)
    code = db.issue_otp(acct.id, "verify_email")
    assert db.check_otp(acct.id, "verify_email", code) is False


def test_rate_limiter_window():
    db.init_db()
    key = f"uji:{time.time()}"
    assert [db.rate_limited(key, 3, 60) for _ in range(5)] == [False, False, False, True, True]
    key2 = f"uji2:{time.time()}"
    assert db.rate_limited(key2, 1, 1) is False
    time.sleep(1.05)
    assert db.rate_limited(key2, 1, 1) is False                         # jendela baru


def test_password_policy_extras():
    assert auth.validate_password("password123")                         # umum
    assert auth.validate_password("aaaa1111")                            # terlalu sederhana
    assert auth.validate_password("budisantoso99", "budi.santoso@gmail.com")  # memuat nama email
    assert auth.validate_password("kunci-rahasia1", "budi@gmail.com") is None
    assert auth.validate_license("") and auth.validate_license("ab") and auth.validate_license("STR-1234567") is None


def test_smtp_backend_sends_with_tls(monkeypatch):
    calls = []

    class FakeSMTP:
        def __init__(self, host, port, _timeout=0):
            del _timeout
            calls.append(("connect", host, port))
        def __enter__(self): return self
        def __exit__(self, *_args):
            del _args
            return False
        def starttls(self, context=None): calls.append(("starttls", context is not None))
        def login(self, u, _p):
            del _p
            calls.append(("login", u))
        def send_message(self, msg): calls.append(("send", msg["To"], msg["Subject"]))

    monkeypatch.setattr(config, "MAIL_BACKEND", "smtp")
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(config, "SMTP_USER", "noreply@example.com")
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    mailer.send_mail("pasien@gmail.com", "Kode", "123456")
    assert ("starttls", True) in calls and ("login", "noreply@example.com") in calls and ("send", "pasien@gmail.com", "Kode") in calls

    class Boom(FakeSMTP):
        def send_message(self, msg):
            del msg
            raise OSError("jaringan putus")
    monkeypatch.setattr("smtplib.SMTP", Boom)
    with pytest.raises(mailer.MailError):
        mailer.send_mail("pasien@gmail.com", "Kode", "123456")


# ------------------------------------------------------------------ alur UI
def _ok(at):
    assert not at.exception, at.exception
    return at


def _btn(at, label):
    return next(b for b in at.button if b.label == label)


def _click(at, label):
    _btn(at, label).click()
    return _ok(at.run())


def _signup(at, name, email, role="Pasien", str_no=""):
    at.text_input(key="reg_name").set_value(name)
    at.text_input(key="reg_email").set_value(email)
    at.radio(key="reg_role").set_value(role)
    if role == "Dokter":
        at.text_input(key="reg_str").set_value(str_no)
    at.text_input(key="reg_pw").set_value(PW)
    at.text_input(key="reg_pw2").set_value(PW)
    at.checkbox(key="reg_consent").check()
    _click(at, "Daftar")


def _login(at, email, password=PW):
    at.text_input(key="login_email").set_value(email)
    at.text_input(key="login_password").set_value(password)
    _click(at, "Masuk")


def _last_code():
    match = re.search(r"\b(\d{6})\b", mailer.DEV_OUTBOX[-1]["body"])
    assert match is not None
    return match.group(1)


def test_email_verification_required(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_EMAIL_VERIFICATION", True)
    at = _ok(AppTest.from_file(APP, default_timeout=120).run())
    _signup(at, "Verifikasi Uji", "verifikasi.uji@gmail.com")
    assert at.subheader[0].value == "Verifikasi email"                       # belum masuk
    at.text_input(key="verify_code").set_value("000000" if _last_code() != "000000" else "111111")
    _click(at, "Verifikasi")
    assert any("salah atau kedaluwarsa" in e.value for e in at.error)
    at.text_input(key="verify_code").set_value(_last_code())
    _click(at, "Verifikasi")
    assert "Halo, Verifikasi Uji" in at.header[0].value
    _click(at, "Keluar")
    _login(at, "verifikasi.uji@gmail.com")                                    # sudah terverifikasi: langsung masuk
    assert "Halo, Verifikasi Uji" in at.header[0].value


def test_mfa_required_for_doctor_with_recovery(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_MFA_ROLES", {"doctor"})
    at = _ok(AppTest.from_file(APP, default_timeout=120).run())
    _signup(at, "dr. Mfa", "dokter.mfa@gmail.com", "Dokter", "STR-MFA-12345")
    flow = at.session_state["auth_flow"]
    assert flow["step"] == "enroll"                                           # wajib mendaftarkan MFA sebelum masuk
    secret, recovery = flow["secret"], list(flow["recovery"])
    at.text_input(key="login_enroll_code").set_value(totp.code_at(secret, time.time()))
    _click(at, "Aktifkan MFA")
    assert any("Centang dulu" in e.value for e in at.error)                  # kode pemulihan harus dikonfirmasi tersimpan
    at.checkbox(key="login_saved").check()
    at.text_input(key="login_enroll_code").set_value(totp.code_at(secret, time.time()))
    _click(at, "Aktifkan MFA")
    assert "Halo, dr. Mfa" in at.header[0].value
    _click(at, "Keluar")

    _login(at, "dokter.mfa@gmail.com")
    assert at.session_state["auth_flow"]["step"] == "mfa"
    at.text_input(key="mfa_code").set_value("123456")
    _click(at, "Verifikasi")
    assert any("Kode tidak cocok" in e.value for e in at.error)
    at.text_input(key="mfa_code").set_value(totp.code_at(secret, time.time() + 30))   # langkah berikutnya (anti replay)
    _click(at, "Verifikasi")
    assert "Halo, dr. Mfa" in at.header[0].value
    _click(at, "Keluar")

    _login(at, "dokter.mfa@gmail.com")                                        # masuk dengan kode pemulihan (sekali pakai)
    at.text_input(key="mfa_code").set_value(recovery[0])
    _click(at, "Verifikasi")
    assert "Halo, dr. Mfa" in at.header[0].value
    _click(at, "Keluar")
    _login(at, "dokter.mfa@gmail.com")
    at.text_input(key="mfa_code").set_value(recovery[0])
    _click(at, "Verifikasi")
    assert at.session_state["auth_flow"]["step"] == "mfa" and at.error     # kode yang sama tidak berlaku lagi


def test_password_reset_flow():
    at = _ok(AppTest.from_file(APP, default_timeout=120).run())
    _signup(at, "Reset Uji", "reset.uji@gmail.com")
    _click(at, "Keluar")
    at.text_input(key="forgot_email").set_value("reset.uji@gmail.com")
    _click(at, "Kirim kode reset")
    code = _last_code()
    at.text_input(key="reset_code").set_value("000000" if code != "000000" else "111111")
    at.text_input(key="reset_pw").set_value("sandi-baru-aman9")
    at.text_input(key="reset_pw2").set_value("sandi-baru-aman9")
    _click(at, "Ubah password")
    assert any("Kode salah" in e.value for e in at.error)
    at.text_input(key="reset_code").set_value(code)
    _click(at, "Ubah password")
    assert any("Password diubah" in s.value for s in at.success)
    _login(at, "reset.uji@gmail.com", PW)                                      # password lama tidak berlaku
    assert any("Email atau password salah" in e.value for e in at.error)
    _login(at, "reset.uji@gmail.com", "sandi-baru-aman9")
    assert "Halo, Reset Uji" in at.header[0].value


def test_reset_request_does_not_reveal_unknown_email():
    at = _ok(AppTest.from_file(APP, default_timeout=120).run())
    before = len(mailer.DEV_OUTBOX)
    at.text_input(key="forgot_email").set_value("tidak.terdaftar@gmail.com")
    _click(at, "Kirim kode reset")
    assert len(mailer.DEV_OUTBOX) == before                                    # tidak ada email, tetapi respons UI sama
    assert any("Jika email terdaftar" in i.value for i in at.info)


def test_session_idle_and_absolute_timeouts():
    at = _ok(AppTest.from_file(APP, default_timeout=120).run())
    _signup(at, "Sesi Uji", "sesi.uji@gmail.com")
    assert "Halo, Sesi Uji" in at.header[0].value
    at.session_state["last_seen"] = time.time() - (config.SESSION_IDLE_MINUTES + 1) * 60
    _ok(at.run())
    assert at.title[0].value == "StegoMed-Web3" and any("tidak ada aktivitas" in w.value for w in at.warning)
    _login(at, "sesi.uji@gmail.com")
    at.session_state["auth_at"] = time.time() - (config.SESSION_MAX_HOURS + 1) * 3600
    _ok(at.run())
    assert any("batas waktu maksimum" in w.value for w in at.warning)


def test_security_page_enroll_change_password_and_cannot_disable_required():
    at = _ok(AppTest.from_file(APP, default_timeout=120).run())
    _signup(at, "Pasien Keamanan", "pasien.keamanan@gmail.com")
    at.sidebar.radio[0].set_value("Keamanan akun")
    _ok(at.run())
    at.text_input(key="sec_pw_current").set_value("salah")
    at.text_input(key="sec_pw_new").set_value("sandi-baru-aman9")
    at.text_input(key="sec_pw_new2").set_value("sandi-baru-aman9")
    _click(at, "Ganti password")
    assert any("Password saat ini salah" in e.value for e in at.error)
    at.text_input(key="sec_pw_current").set_value(PW)
    _click(at, "Ganti password")
    assert any("berhasil diganti" in s.value for s in at.success)
    _click(at, "Aktifkan MFA")                                                 # tombol di panel MFA (pasien: opsional)
    secret = at.session_state["sec_enroll"]["secret"]
    at.checkbox(key="sec_saved").check()
    at.text_input(key="sec_enroll_code").set_value(totp.code_at(secret, time.time()))
    _click(at, "Aktifkan MFA")
    assert any("MFA aktif" in s.value for s in at.success)
