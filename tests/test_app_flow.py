"""Alur end-to-end lewat AppTest: daftar -> tautkan dompet -> persetujuan pasien -> buat rekam -> dekripsi -> admin."""
from pathlib import Path

from streamlit.testing.v1 import AppTest

import config
from utils import auth
from utils import db_helper as db

APP = str(Path(__file__).resolve().parents[1] / "app.py")
PW = "kunci-rahasia1"
ADMIN = "admin.utama@gmail.com"


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


def _menu(at, label):
    at.sidebar.radio[0].set_value(label)
    return _ok(at.run())


def _use_demo_wallet(at, scope, label):
    at.selectbox(key=f"dev_preset_{scope}").select(label)
    _ok(at.run())
    at.button(key=f"dev_btn_{scope}").click()
    _ok(at.run())


def _header(at):
    return at.header[0].value


def _fresh():
    app_test = AppTest.from_file(APP, default_timeout=30)
    app_test.script_path = APP
    return _ok(app_test.run())


def test_full_flow():
    at = _fresh()

    # --- pasien mendaftar; fitur steganografi terkunci karena belum ada dompet
    _signup(at, "Budi Santoso", "budi.santoso@gmail.com")
    assert "Halo, Budi Santoso" in _header(at)
    _menu(at, "Rekam medis saya")
    assert _header(at) == "Fitur steganografi terkunci"
    assert any("mewajibkan alamat dompet" in n.value for n in at.markdown)
    assert not [b for b in at.button if b.label == "Ekstrak dan dekripsi"]
    for locked_page in ("Verifikasi file", "Lab stenografi", "Akses dokter"):
        _menu(at, locked_page)
        assert _header(at) == "Fitur steganografi terkunci"
    _menu(at, "Rekam medis saya")
    _use_demo_wallet(at, "link", "pasien-demo")
    assert _header(at) == "Rekam medis saya"
    _click(at, "Keluar")

    # --- dokter: daftar, tautkan dompet, minta akses pasien
    _signup(at, "dr. Sari", "sari.dokter@gmail.com", "Dokter", "STR-123456")
    _menu(at, "Pasien saya")
    assert _header(at) == "Fitur steganografi terkunci"
    _use_demo_wallet(at, "link", "dokter-demo")
    assert _header(at) == "Pasien saya"
    at.text_input(key="req_patient_email").set_value("tidak.ada@gmail.com")          # respons sama untuk email tak dikenal
    _click(at, "Minta akses")
    assert any("Jika pasien terdaftar" in i.value for i in at.info)
    at.text_input(key="req_patient_email").set_value("budi.santoso@gmail.com")
    _click(at, "Minta akses")
    _menu(at, "Rekam medis baru")
    assert any("Belum ada pasien yang memberi akses" in i.value for i in at.info)   # belum disetujui pasien
    _click(at, "Keluar")

    # --- pasien menyetujui permintaan akses
    _login(at, "Budi.Santoso+tugas@gmail.com")
    _menu(at, "Akses dokter")
    _use_demo_wallet(at, "unlock", "dokter-demo")                                     # dompet salah ditolak
    assert any("berbeda dari dompet tertaut" in e.value for e in at.error)
    _use_demo_wallet(at, "unlock", "pasien-demo")
    assert _header(at) == "Akses dokter"
    _click(at, "Setujui")
    assert any("sejak" in m.value for m in at.markdown)
    _click(at, "Keluar")

    # --- dokter membuat rekam (data terstruktur + passphrase) lalu mendekripsinya
    _login(at, "sari.dokter@gmail.com")
    _menu(at, "Rekam medis baru")
    _use_demo_wallet(at, "unlock", "dokter-demo")
    assert _header(at) == "Rekam medis baru"
    next(t for t in at.text_area if t.label == "Keluhan utama").set_value("Batuk 2 minggu")
    next(t for t in at.text_area if t.label == "Diagnosis").set_value("Bronkitis akut")
    next(t for t in at.text_input if t.label.startswith("Kode ICD-10")).set_value("XYZ")
    next(t for t in at.text_input if t.label.startswith("Passphrase")).set_value("kunci-rahasia")
    _click(at, "Enkripsi dan sisipkan")
    assert any("ICD-10 tidak valid" in e.value for e in at.error)                      # validasi kode klinis
    next(t for t in at.text_input if t.label.startswith("Kode ICD-10")).set_value("J20.9")
    next(t for t in at.text_area if t.label.startswith("Alergi")).set_value("Penisilin")
    _click(at, "Enkripsi dan sisipkan")
    assert any("Rekam medis tersimpan" in s.value for s in at.success), [e.value for e in at.error]
    _menu(at, "Riwayat rekam medis")
    next(t for t in at.text_input if t.label == "Passphrase rekam ini").set_value("kunci-rahasia")
    _click(at, "Ekstrak dan dekripsi")
    assert any("Dekripsi berhasil" in s.value for s in at.success)
    assert any("Bronkitis akut" in m.value for m in at.markdown)
    assert any("J20.9" in m.value for m in at.markdown) and any("Penisilin" in m.value for m in at.markdown)
    _click(at, "Keluar")

    # --- pasien: kunci terkunci per sesi; passphrase salah ditolak, benar berhasil; panel akses tersedia
    _login(at, "budi.santoso@gmail.com")
    _menu(at, "Rekam medis saya")
    assert _header(at) == "Fitur steganografi terkunci"
    _use_demo_wallet(at, "unlock", "pasien-demo")
    next(t for t in at.text_input if t.label == "Passphrase rekam ini").set_value("salah")
    _click(at, "Ekstrak dan dekripsi")
    assert any("Dekripsi gagal" in e.value for e in at.error)
    assert not any("Dekripsi berhasil" in s.value for s in at.success)
    next(t for t in at.text_input if t.label == "Passphrase rekam ini").set_value("kunci-rahasia")
    _click(at, "Ekstrak dan dekripsi")
    assert any("Dekripsi berhasil" in s.value for s in at.success)
    assert any(e.label == "Kelola akses rekam ini" for e in at.expander)
    _click(at, "Keluar")

    # --- admin: hanya metadata, audit utuh, Lab tetap butuh dompet
    if db.get_account_by_email(ADMIN) is None:
        db.create_account(ADMIN, "Admin Utama", "patient", auth.hash_password(PW))
    _login(at, ADMIN)
    _menu(at, "Metadata rekam medis")
    assert not [b for b in at.button if b.label == "Ekstrak dan dekripsi"]
    _menu(at, "Lab stenografi")
    assert _header(at) == "Fitur steganografi terkunci"
    _menu(at, "Audit trail")
    _click(at, "Verifikasi rantai audit")
    assert any("Rantai audit utuh" in s.value for s in at.success)
    _click(at, "Keluar")


def test_doctor_approval_ui(monkeypatch):
    monkeypatch.setattr(config, "AUTO_APPROVE_DOCTORS", False)
    at = _fresh()
    _signup(at, "dr. Baru", "dokter.baru@gmail.com", "Dokter", "STR-998877")
    assert _header(at) == "Menunggu persetujuan admin"
    _click(at, "Keluar")
    _signup(at, "dr. Ditolak", "dokter.ditolak@gmail.com", "Dokter", "STR-000111")
    _click(at, "Keluar")

    if db.get_account_by_email(ADMIN) is None:
        db.create_account(ADMIN, "Admin Utama", "patient", auth.hash_password(PW))
    _login(at, ADMIN)
    _menu(at, "Verifikasi dokter")
    ids = {a.full_name: a.id for a in db.list_accounts(role="doctor")}
    at.text_input(key=f"ap_note_{ids['dr. Baru']}").set_value("pendek")
    at.button(key=f"ap_{ids['dr. Baru']}").click()
    _ok(at.run())
    assert any("catatan verifikasi" in e.value.lower() for e in at.error)               # catatan wajib memadai
    at.text_input(key=f"ap_note_{ids['dr. Baru']}").set_value("Diperiksa di sumber resmi KKI, 20 Okt 2026")
    at.button(key=f"ap_{ids['dr. Baru']}").click()
    _ok(at.run())
    at.text_input(key=f"rej_reason_{ids['dr. Ditolak']}").set_value("STR tidak ditemukan")
    at.button(key=f"rej_{ids['dr. Ditolak']}").click()
    _ok(at.run())
    _click(at, "Keluar")

    _login(at, "dokter.baru@gmail.com")
    assert "Halo, dr. Baru" in _header(at)                                              # sudah disetujui
    _click(at, "Keluar")
    _login(at, "dokter.ditolak@gmail.com")
    assert _header(at) == "Pendaftaran dokter ditolak" and any("STR tidak ditemukan" in e.value for e in at.error)


def test_login_errors_and_lockout():
    at = _fresh()
    _signup(at, "Citra Lestari", "citra.lestari@gmail.com")
    _click(at, "Keluar")

    _login(at, "tidak.ada@gmail.com")
    assert any(e.value == "Email atau password salah." for e in at.error)       # tidak membocorkan keberadaan akun
    for _ in range(5):
        _login(at, "citra.lestari@gmail.com", "salah-password1")
    assert any(e.value == "Email atau password salah." for e in at.error)
    _login(at, "citra.lestari@gmail.com")                                       # password benar, tetapi terkunci
    assert any("dikunci sementara" in e.value for e in at.error)
    assert at.title[0].value == "StegoMed-Web3"


def test_login_rate_limit_per_ip(monkeypatch):
    monkeypatch.setattr(config, "RATE_LOGIN_PER_IP", 3)
    monkeypatch.setattr("views.login.client_ip", lambda: "203.0.113.77")
    at = _fresh()
    for _ in range(3):
        _login(at, "siapa.saja@gmail.com", "salah-password1")
    _login(at, "siapa.saja@gmail.com", "salah-password1")
    assert any("Terlalu banyak percobaan dari jaringan" in e.value for e in at.error)


def test_register_validation():
    at = _fresh()
    _signup(at, "Dewi", "dewi@yahoo.com")                                       # bukan Gmail, nama terlalu pendek
    assert at.error
    at.text_input(key="reg_name").set_value("Dewi Anggraini")
    at.text_input(key="reg_email").set_value("dewi.anggraini@yahoo.com")
    at.text_input(key="reg_pw").set_value(PW)
    at.text_input(key="reg_pw2").set_value(PW)
    at.checkbox(key="reg_consent").check()
    _click(at, "Daftar")
    assert any("Gmail" in e.value for e in at.error)
    at.text_input(key="reg_email").set_value("dewi.anggraini@gmail.com")
    at.text_input(key="reg_pw2").set_value("beda-password1")
    _click(at, "Daftar")
    assert any("Konfirmasi password" in e.value for e in at.error)
    at.text_input(key="reg_pw").set_value("password123")
    at.text_input(key="reg_pw2").set_value("password123")
    _click(at, "Daftar")
    assert any("terlalu umum" in e.value for e in at.error)


def test_registration_requires_and_records_privacy_consent():
    at = _fresh()
    at.text_input(key="reg_name").set_value("Pasien Persetujuan")
    at.text_input(key="reg_email").set_value("pasien.persetujuan@gmail.com")
    at.text_input(key="reg_pw").set_value(PW)
    at.text_input(key="reg_pw2").set_value(PW)
    _click(at, "Daftar")                                                          # tanpa mencentang persetujuan
    assert any("menyetujui pemrosesan data" in e.value for e in at.error)
    assert db.get_account_by_email("pasien.persetujuan@gmail.com") is None
    at.checkbox(key="reg_consent").check()
    _click(at, "Daftar")
    acct = db.get_account_by_email("pasien.persetujuan@gmail.com")
    assert acct.consent_version == config.PRIVACY_VERSION and acct.consent_at is not None
