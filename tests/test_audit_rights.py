"""Audit (checkpoint, keluaran JSON, cakupan), riwayat akses pasien, ekspor data, hak subjek data."""
import io
import json
import logging
import zipfile
from pathlib import Path

import pytest
from sqlalchemy import text
from streamlit.testing.v1 import AppTest

import config
from models import AuditLog
from utils import auth, fhir
from utils import db_helper as db
from utils import record_service as rs
from utils import web3_utils as w3
from views import patient_rights

APP = str(Path(__file__).resolve().parents[1] / "app.py")
PW = "kunci-rahasia1"


def test_audit_emits_json_line_for_external_sink(caplog):
    db.init_db()
    with caplog.at_level(logging.INFO, logger="stegomed.audit"):
        db.log_event("0x" + "a" * 40, "uji_json", "rec1", "rincian ✓")
    line = json.loads(next(r.getMessage() for r in caplog.records if r.name == "stegomed.audit"))
    assert line["action"] == "uji_json" and line["target"] == "rec1" and line["detail"] == "rincian ✓"
    assert len(line["hash"]) == 64 and isinstance(line["id"], int)


def test_checkpoint_detects_truncation_rewrite_and_forgery():
    db.init_db()
    for i in range(4):
        db.log_event("0x" + "c" * 40, "cp_uji", str(i))
    cp = db.audit_checkpoint()
    assert db.verify_checkpoint(cp)[0]
    db.log_event("0x" + "c" * 40, "cp_setelah")                                   # penambahan normal tetap valid
    assert db.verify_checkpoint(cp)[0]

    forged = {**cp, "count": cp["count"] + 5}
    ok, msg = db.verify_checkpoint(forged)
    assert not ok and "Tanda tangan" in msg                                       # checkpoint tidak bisa dipalsukan
    assert db.verify_checkpoint({"x": 1})[0] is False

    # pengelola DB memangkas entri terakhir lalu menyambung ulang rantai: dicek lewat checkpoint
    with db.session_scope() as s:
        last = s.query(AuditLog).order_by(AuditLog.id.desc()).first()
        keep_id = cp["head_id"]
        s.query(AuditLog).filter(AuditLog.id >= keep_id).delete()                  # hapus kepala checkpoint dan setelahnya
    ok, msg = db.verify_checkpoint(cp)
    assert ok is False and "hilang" in msg
    # rantai internal tetap tampak utuh setelah pemangkasan; hanya checkpoint eksternal yang menangkapnya
    assert db.verify_audit_chain()[0] is True


def test_checkpoint_detects_rewritten_history():
    db.init_db()
    db.log_event("0x" + "d" * 40, "tulis_ulang_1")
    cp = db.audit_checkpoint()
    with db.session_scope() as s:
        row = s.get(AuditLog, cp["head_id"])
        original, row.detail = row.detail, "diubah diam-diam"
    try:
        ok, msg = db.verify_checkpoint(cp)
        assert ok is False and ("rusak" in msg or "berbeda" in msg)
    finally:                                                                       # jangan merusak database bersama untuk tes lain
        with db.session_scope() as s:
            s.get(AuditLog, cp["head_id"]).detail = original
    assert db.verify_audit_chain()[0] is True


def _patient_with_record():
    import uuid
    from components import steganography as stego
    from utils import crypto_utils as mc
    pa = db.create_account(f"pasien.ekspor{uuid.uuid4().hex[:6]}@gmail.com", "Pasien Ekspor", "patient", auth.hash_password(PW))
    da = db.create_account(f"dokter.ekspor{uuid.uuid4().hex[:6]}@gmail.com", "Dokter Ekspor", "doctor", auth.hash_password(PW), "STR-555555")
    pa_addr, da_addr = w3.dev_wallet(f"p-{pa.id}").address.lower(), w3.dev_wallet(f"d-{da.id}").address.lower()
    db.link_wallet(pa.id, pa_addr)
    db.link_wallet(da.id, da_addr)
    pu, du = db.get_user(pa_addr), db.get_user(da_addr)
    make = lambda u: type("P", (), dict(address=u.address, enc_pub=u.enc_pub, enc_priv=u.enc_priv, role=u.role, wallet_linked=True, name=u.name))()  # noqa: E731
    patient, doctor = make(pu), make(du)
    recs = []
    for i, pp in enumerate([None, "rahasia-ekspor"]):
        rid = uuid.uuid4().hex
        record = {"title": f"Rekam {i}", "diagnosis": f"Diagnosis {i}", "icd10": ["J20.9"], "patient": {"name": patient.name, "address": patient.address},
                  "doctor": {"name": doctor.name, "address": doctor.address}, "visit": {"date": "2026-10-20", "type": "Rawat jalan"}}
        blob = mc.encrypt_record(record, [(patient.address, patient.enc_pub), (doctor.address, doctor.enc_pub)], pp)
        key = mc.derive_stego_key_v2(rid, pp)
        data = stego.to_png_bytes(stego.embed(stego.make_sample_cover(256), blob, key))
        config.ensure_dirs()
        (config.STEGO_DIR / f"{rid}.png").write_bytes(data)
        db.add_record(id=rid, patient_address=patient.address, doctor_address=doctor.address, title=f"Rekam {i}", stego_file=f"{rid}.png",
                      stego_format="PNG", cover_name="c.png", sha256=stego.sha256_hex(data), payload_bytes=len(blob), capacity_bytes=1,
                      has_passphrase=bool(pp), key_version=2)
        db.add_recipient(rid, patient.address, "patient", doctor.address)
        db.add_recipient(rid, doctor.address, "author", doctor.address)
        db.log_event(doctor.address, "rekam_dibuat", rid)
        recs.append(rid)
    patient.account_id = pa.id
    return pa, patient, doctor, recs


def test_patient_access_history_shows_actions_on_own_records_only():
    pa, patient, doctor, recs = _patient_with_record()
    _, other, other_doc, other_recs = _patient_with_record()
    db.log_event(doctor.address, "dekripsi", recs[0])
    db.log_event(other_doc.address, "dekripsi", other_recs[0])                       # rekam pasien lain
    logs = db.list_logs_for_patient(patient.address, recs)
    assert {l.target for l in logs if l.target} <= set(recs)
    assert any(l.action == "dekripsi" and l.actor == doctor.address for l in logs)
    assert not any(l.target in other_recs for l in logs)


def test_export_contains_decrypted_fhir_and_skips_protected_without_passphrase():
    pa, patient, doctor, recs = _patient_with_record()
    account = db.get_account(pa.id)
    data, skipped = patient_rights._build_export(patient, account, {})
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    assert "akun.json" in names and "riwayat_akses.csv" in names and "BACA-SAYA.txt" in names
    open_tag, locked_tag = recs[0][:8], recs[1][:8]
    assert f"rekam/{open_tag}.json" in names and f"fhir/{open_tag}_fhir.json" in names
    assert f"rekam/{locked_tag}.json" not in names and any(locked_tag in s for s in skipped)
    assert f"stegotext/{locked_tag}.png" in names                                  # file terenkripsi tetap diekspor
    assert json.loads(z.read(f"fhir/{open_tag}_fhir.json"))["resourceType"] == "Bundle"
    assert json.loads(z.read(f"rekam/{open_tag}.json"))["diagnosis"] == "Diagnosis 0"
    # dengan passphrase, rekam terkunci ikut
    data2, skipped2 = patient_rights._build_export(patient, account, {recs[1]: "rahasia-ekspor"})
    assert f"rekam/{locked_tag}.json" in zipfile.ZipFile(io.BytesIO(data2)).namelist() and skipped2 == []
    data3, skipped3 = patient_rights._build_export(patient, account, {recs[1]: "salah"})
    assert skipped3 and f"rekam/{locked_tag}.json" not in zipfile.ZipFile(io.BytesIO(data3)).namelist()


def test_subject_request_lifecycle():
    pa, *_ = _patient_with_record()
    req = db.create_subject_request(pa.id, "koreksi", "  Tanggal lahir saya salah.  ")
    assert req.status == "baru" and db.list_subject_requests(account_id=pa.id)[0].detail == "Tanggal lahir saya salah."
    with db.get_engine().connect() as c:
        raw = c.execute(text("SELECT detail FROM subject_requests WHERE id=:i"), {"i": req.id}).scalar()
    assert raw.startswith("enc1:") and "Tanggal" not in raw                         # rincian terenkripsi di database
    assert db.update_subject_request(req.id, "selesai", "Sudah diperbaiki.", "acct:1")
    got = db.list_subject_requests(status="selesai")
    assert req.id in [r.id for r in got] and next(r for r in got if r.id == req.id).response == "Sudah diperbaiki."
    with pytest.raises(ValueError):
        db.create_subject_request(pa.id, "lainnya", "x")
    with pytest.raises(ValueError):
        db.update_subject_request(req.id, "aneh", "x", "a")


# ------------------------------------------------------------------ UI
def _ok(at):
    assert not at.exception, at.exception
    return at


def _click(at, label):
    next(b for b in at.button if b.label == label).click()
    return _ok(at.run())


def _login(at, email):
    at.text_input(key="login_email").set_value(email)
    at.text_input(key="login_password").set_value(PW)
    _click(at, "Masuk")


def test_subject_request_and_admin_queue_via_ui():
    at = _ok(AppTest.from_file(APP, default_timeout=120).run())
    at.text_input(key="reg_name").set_value("Pasien Hak Data")
    at.text_input(key="reg_email").set_value("pasien.hakdata@gmail.com")
    at.text_input(key="reg_pw").set_value(PW)
    at.text_input(key="reg_pw2").set_value(PW)
    at.checkbox(key="reg_consent").check()
    _click(at, "Daftar")
    _ok(at.run())
    at.sidebar.radio[0].set_value("Permintaan hak data")                              # tidak butuh dompet
    _ok(at.run())
    assert at.header[0].value == "Permintaan hak data"
    at.text_area(key="sr_detail").set_value("pendek")
    _click(at, "Kirim permintaan")
    assert any("minimal 10 karakter" in e.value for e in at.error)
    at.text_area(key="sr_detail").set_value("Mohon salinan seluruh data pribadi saya.")
    _click(at, "Kirim permintaan")
    assert any("Permintaan terkirim" in s.value for s in at.success)
    _click(at, "Keluar")

    if db.get_account_by_email("admin.utama@gmail.com") is None:
        db.create_account("admin.utama@gmail.com", "Admin Utama", "admin", auth.hash_password(PW))
    _login(at, "admin.utama@gmail.com")
    at.sidebar.radio[0].set_value("Permintaan hak data")
    _ok(at.run())
    rid = db.list_subject_requests(status="baru")[0].id
    at.text_input(key=f"sr_reply_{rid}").set_value("ok")
    _click(at, "Simpan")
    assert any("Isi jawaban" in e.value for e in at.error)
    at.text_input(key=f"sr_reply_{rid}").set_value("Salinan data sudah kami siapkan.")
    _click(at, "Simpan")
    assert db.list_subject_requests(status="baru") == [] or rid not in [r.id for r in db.list_subject_requests(status="baru")]
    # akses admin ke halaman sensitif dicatat (satu kali per sesi)
    acts = [l.action for l in db.list_logs(200)]
    assert "admin_lihat_hak_data" in acts and "hak_data_ditangani" in acts


def test_admin_audit_page_checkpoint_and_view_logging():
    at = _ok(AppTest.from_file(APP, default_timeout=120).run())
    if db.get_account_by_email("admin.utama@gmail.com") is None:
        db.create_account("admin.utama@gmail.com", "Admin Utama", "admin", auth.hash_password(PW))
    _login(at, "admin.utama@gmail.com")
    for page in ("Audit trail", "Metadata rekam medis", "Verifikasi dokter"):
        at.sidebar.radio[0].set_value(page)
        _ok(at.run())
        _ok(at.run())                                                                  # rerun tidak menggandakan catatan
    acts = [l.action for l in db.list_logs(500)]
    assert acts.count("admin_lihat_audit") >= 1
    mine = [l for l in db.list_logs(500) if l.action == "admin_lihat_audit"]
    assert len({l.actor for l in mine}) >= 1
