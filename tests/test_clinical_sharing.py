"""Berbagi/pencabutan akses (enkripsi ulang + scrub), persetujuan, verifikasi dokter, ICD-10 dan FHIR."""
import json
import os
import uuid
import io

import numpy as np
import pytest
import streamlit as st
from PIL import Image

import config
from components import steganography as stego
from utils import access, auth, clinical, fhir, record_service as rs, crypto_utils as mc, db_helper as db
from utils import web3_utils as w3

pytest.fixture(autouse=True)
def mock_session():
    st.session_state["DEK"] = os.urandom(32)
    yield
    st.session_state.clear()


def get_dummy_png():
    img = Image.new('RGB', (100, 100), color='red')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


def _person(label, role):
    # Keep persistent test databases isolated across repeated test runs.
    unique_label = f"{label}-{uuid.uuid4().hex[:10]}"
    str_number = f"STR-{uuid.uuid4().hex[:12]}" if role == "doctor" else None
    acct = db.create_account(f"{unique_label}.berbagi@gmail.com", unique_label.title(), role,
                             auth.hash_password("kunci-rahasia1"), str_number)
    addr = w3.dev_wallet(unique_label).address.lower()
    db.link_wallet(acct.id, addr)
    ident = db.get_user(addr)
    assert ident is not None
    return type("P", (), dict(address=addr, role=role, enc_pub=ident.enc_pub, enc_priv=ident.enc_priv, wallet_linked=True, name=label))()


def _make_record(patient, author, passphrase=None, fmt="PNG"):
    """Buat rekam persis seperti portal dokter."""
    rid = uuid.uuid4().hex
    record = {"title": "Uji", "diagnosis": "Bronkitis", "patient": {"name": patient.name, "address": patient.address},
              "doctor": {"name": author.name, "address": author.address}}
    blob = mc.encrypt_record(record, [(patient.address, patient.enc_pub), (author.address, author.enc_pub)], passphrase)
    cover = stego.make_sample_cover(256)
    key = mc.derive_stego_key_v2(rid, passphrase)
    arr = stego.embed(cover, blob, key)
    data = stego.to_png_bytes(arr) if fmt == "PNG" else stego.to_bmp_bytes(arr)
    config.ensure_dirs()
    (config.STEGO_DIR / f"{rid}.{fmt.lower()}").write_bytes(data)
    db.add_record(id=rid, patient_address=patient.address, doctor_address=author.address, title="Uji", stego_file=f"{rid}.{fmt.lower()}",
                  stego_format=fmt, cover_name="c.png", sha256=stego.sha256_hex(data), payload_bytes=len(blob),
                  capacity_bytes=stego.capacity_bytes(cover), psnr=60.0, ssim=0.99, has_passphrase=bool(passphrase), key_version=2)
    db.add_recipient(rid, patient.address, "patient", author.address)
    db.add_recipient(rid, author.address, "author", author.address)
    result = db.get_record(rid)
    assert result is not None
    return result, cover


pytest.fixture(scope="module")
def cast():
    db.init_db()
    return {"pasien": _person("pasien-berbagi", "patient"), "dokter1": _person("dokter-satu", "doctor"),
            "dokter2": _person("dokter-dua", "doctor")}


pytest.mark.parametrize("passphrase,fmt", [(None, "PNG"), ("rahasia-pp", "BMP")])
def test_share_then_revoke_cuts_access_and_scrubs_old_bits(cast, passphrase, fmt):
    p, d1, d2 = cast["pasien"], cast["dokter1"], cast["dokter2"]
    rec, _ = _make_record(p, d1, passphrase, fmt)
    assert access.can_decrypt(p, rec) and access.can_decrypt(d1, rec) and not access.can_decrypt(d2, rec)
    with pytest.raises(Exception):
        rs.open_record(rec, d2, passphrase)                                       # belum penerima

    old_file = rs.stego_path(rec).read_bytes()
    rs.reencrypt(rec, p, passphrase, add=(d2.address,))
    rec = db.get_record(rec.id)
    assert rec is not None
    assert access.can_decrypt(d2, rec) and rs.open_record(rec, d2, passphrase)["diagnosis"] == "Bronkitis"
    assert rs.open_record(rec, d1, passphrase)["diagnosis"] == "Bronkitis"       # penulis tetap bisa
    assert rec.sha256 == stego.sha256_hex(rs.stego_path(rec).read_bytes()) != stego.sha256_hex(old_file)

    shared_file = rs.stego_path(rec).read_bytes()
    rs.reencrypt(rec, p, passphrase, remove=(d2.address,))
    rec = db.get_record(rec.id)
    assert rec is not None
    assert not access.can_decrypt(d2, rec) and access.can_decrypt(d1, rec)
    # dokter2 menyimpan salinan file SAAT dibagikan: tetap bisa membuka salinan itu (batas kriptografis yang jujur)
    key = mc.derive_stego_key_v2(rec.id, passphrase)
    saved_blob, _, _, _ = stego.extract(stego.load_image(shared_file), key)
    assert mc.decrypt_record(saved_blob, d2.address, db.get_user(d2.address).enc_priv, passphrase)["diagnosis"] == "Bronkitis"
    # ...tetapi file TERBARU tidak lagi memuat daftar penerima lama: dokter2 gagal membuka
    with pytest.raises(mc.MediCryptError):
        rs.open_record(rec, d2, passphrase)
    new_blob, _, _, _ = stego.extract(stego.load_image(rs.stego_path(rec).read_bytes()), key)
    assert mc.blob_info(new_blob)["penerima"] == 2
    # sisa bit lama di luar payload baru sudah ditimpa: membaca panjang lama tidak memulihkan blob lama
    arr = stego.load_image(rs.stego_path(rec).read_bytes())
    flat = arr.reshape(-1).copy()
    flat[:64] = (flat[:64] & 0xFE) | np.unpackbits(np.frombuffer(stego.MAGIC + len(saved_blob).to_bytes(4, "big"), dtype=np.uint8))
    forged, _, _, _ = stego.extract(flat.reshape(arr.shape), key)
    assert forged != saved_blob and forged[: len(new_blob)] == new_blob


def test_reencrypt_revokes_access_correctly(cast):
    """(a) Dokter A punya akses, (b) Pasien mencabut akses Dokter A, (c) Dokter A gagal akses, (d) Pasien tetap akses."""
    p, d1, d2 = cast["pasien"], cast["dokter1"], cast["dokter2"]
    # (a) Dokter punya akses
    cover_data = get_dummy_png()
    rec_id = rs.save_new_record(p.address, d1.address, "Rekam Uji", cover_data, "c.png", {"data": "test"})
    rec = db.get_record(rec_id)
    assert rec is not None
    rs.reencrypt(rec, p, add=(d2.address,))
    rec = db.get_record(rec_id)
    assert rec is not None
    assert rs.open_record(rec, d2)["data"] == "test"
    
    # (b) Pasien mencabut akses Dokter A (d2)
    rs.reencrypt(rec, p, remove=(d2.address,))
    rec = db.get_record(rec_id)
    assert rec is not None
    
    # (c) Dokter A gagal akses
    with pytest.raises(mc.MediCryptError):
        rs.open_record(rec, d2)
        
    # (d) Pasien tetap akses
    assert rs.open_record(rec, p)["data"] == "test"

    p, d1, d2 = cast["pasien"], cast["dokter1"], cast["dokter2"]
    rec, _ = _make_record(p, d1)
    with pytest.raises(PermissionError):
        rs.reencrypt(rec, d1, None, add=(d2.address,))                            # bukan pemilik
    with pytest.raises(ValueError, match="tidak dapat dicabut"):
        rs.reencrypt(rec, p, None, remove=(d1.address,))                          # penulis tidak bisa dicabut
    with pytest.raises(ValueError, match="dompet tertaut"):
        rs.reencrypt(rec, p, None, add=("0x" + "9" * 40,))                        # tanpa identitas/kunci
    with pytest.raises(mc.MediCryptError):
        rs.reencrypt(rec, p, "passphrase-salah", add=(d2.address,))
    assert [r.role for r in db.list_recipients(rec.id)].count("shared") == 0       # kegagalan tidak mengubah apa pun


def test_access_grant_lifecycle(cast):
    p, d1 = cast["pasien"], cast["dokter1"]
    assert not db.has_active_grant(p.address, d1.address)
    assert db.request_access(d1.address, p.address) == "pending"
    assert db.request_access(d1.address, p.address) == "pending"                   # idempoten
    assert not db.has_active_grant(p.address, d1.address) and db.list_granted_patients(d1.address) == []
    assert db.respond_access(p.address, d1.address, approve=True) and db.has_active_grant(p.address, d1.address)
    assert [u.address for u in db.list_granted_patients(d1.address)] == [p.address]
    assert db.revoke_access(p.address, d1.address) and not db.has_active_grant(p.address, d1.address)
    assert db.revoke_access(p.address, d1.address) is False
    assert db.request_access(d1.address, p.address) == "pending"                   # bisa meminta lagi setelah dicabut
    assert db.respond_access(p.address, d1.address, approve=False)
    assert db.list_grants(patient=p.address, status="denied")
    db.grant_access(p.address, d1.address)                                         # pasien memberi akses langsung
    assert db.has_active_grant(p.address, d1.address)


def test_list_records_by_recipient(cast):
    p, d1, d2 = cast["pasien"], cast["dokter1"], cast["dokter2"]
    rec, _ = _make_record(p, d1)
    assert rec.id in [r.id for r in db.list_records(recipient=d1.address)]
    assert rec.id not in [r.id for r in db.list_records(recipient=d2.address)]
    rs.reencrypt(rec, p, None, add=(d2.address,))
    assert rec.id in [r.id for r in db.list_records(recipient=d2.address)]


def test_doctor_verification_workflow(monkeypatch):
    monkeypatch.setattr(config, "AUTO_APPROVE_DOCTORS", False)
    db.init_db()
    suffix = uuid.uuid4().hex[:10]
    a = db.create_account(f"verifikasi.dokter.{suffix}@gmail.com", "Dr Verifikasi", "doctor",
                          auth.hash_password("kunci-rahasia1"), f"STR-{suffix}")
    assert a.is_approved is False
    assert db.reject_doctor(a.id, "acct:1", "STR tidak ditemukan di sumber resmi")
    got = db.get_account(a.id)
    assert got is not None
    assert got.is_approved is False and got.rejection_reason == "STR tidak ditemukan di sumber resmi" and got.verified_by == "acct:1"
    assert db.approve_doctor(a.id, "acct:1", "Diperiksa di sumber resmi 2026-10-20")
    got = db.get_account(a.id)
    assert got is not None
    assert got.is_approved and got.rejection_reason is None and got.verification_note is not None and "sumber resmi" in got.verification_note and got.verified_at
    pasien = db.create_account(f"bukan.dokter.{suffix}@gmail.com", "Pasien", "patient", auth.hash_password("kunci-rahasia1"))
    assert db.approve_doctor(pasien.id, "acct:1", "x") is False                    # hanya akun dokter


def test_icd10_and_clinical_cleaning():
    assert clinical.parse_icd10("j20.9, E11 ; I10") == (["J20.9", "E11", "I10"], None)
    assert clinical.parse_icd10("")[0] == []
    codes, err = clinical.parse_icd10("J20.9, XYZ, U99999")
    assert codes == [] and err is not None and "XYZ" in err
    meds = clinical.clean_medications([{"nama": " Amoxicillin ", "dosis": "500 mg"}, {"nama": ""}, {"dosis": "x"}])
    assert meds == [{"nama": "Amoxicillin", "dosis": "500 mg", "frekuensi": "", "durasi": ""}]
    assert clinical.parse_lines("Penisilin\n\n  Debu  ") == ["Penisilin", "Debu"]


def test_fhir_bundle_structure_and_references():
    rec = {"title": "Kontrol", "complaint": "Batuk", "diagnosis": "Bronkitis akut", "icd10": ["J20.9"], "allergies": ["Penisilin"],
           "medications": [{"nama": "Amoxicillin", "dosis": "500 mg", "frekuensi": "3x sehari", "durasi": "5 hari"}],
           "visit": {"date": "2026-10-20", "type": "IGD"}, "vitals": {"bp": "120/80", "temp": 37.2, "pulse": 88, "spo2": 98},
           "patient": {"name": "Budi", "address": "0x" + "a" * 40}, "doctor": {"name": "dr. Sari", "address": "0x" + "b" * 40, "str": "STR-1"},
           "created_at": "2026-10-20T08:00:00+00:00"}
    b = fhir.record_to_bundle(rec, "rec123")
    assert b["resourceType"] == "Bundle" and b["type"] == "collection"
    kinds = [e["resource"]["resourceType"] for e in b["entry"]]
    for k in ("Patient", "Practitioner", "Encounter", "Condition", "AllergyIntolerance", "MedicationRequest", "Observation"):
        assert k in kinds
    urls = {e["fullUrl"] for e in b["entry"]}
    for e in b["entry"]:                                                           # semua referensi menunjuk ke entri yang ada
        res = e["resource"]
        for ref in [res.get(x, {}).get("reference") for x in ("subject", "encounter", "patient", "requester")]:
            assert ref is None or ref in urls
        assert len(res["id"]) <= 64
    cond = next(e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "Condition")
    assert cond["code"]["coding"][0] == {"system": "http://hl7.org/fhir/sid/icd-10", "code": "J20.9"}
    bp = next(e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "Observation" and e["resource"]["code"]["coding"][0]["code"] == "85354-9")
    assert {c["code"]["coding"][0]["code"]: c["valueQuantity"]["value"] for c in bp["component"]} == {"8480-6": 120, "8462-4": 80}
    assert next(e["resource"] for e in b["entry"] if e["resource"]["resourceType"] == "Encounter")["class"]["code"] == "EMER"
    assert json.loads(json.dumps(b)) == b                                          # dapat diserialisasi JSON
    assert fhir.record_to_bundle(rec, "rec123") == b                               # deterministik


def test_legacy_v1_record_still_opens_after_upgrade(cast):
    """Rekam yang dibuat versi sebelumnya (stego-key turunan master, key_version=1) tetap terbuka dan bisa dibagikan."""
    p, d1, d2 = cast["pasien"], cast["dokter1"], cast["dokter2"]
    rid, pp = uuid.uuid4().hex, "pp-lama"
    record = {"title": "Lama", "diagnosis": "Rekam lama", "patient": {"name": "p", "address": p.address}, "doctor": {"name": "d", "address": d1.address}}
    blob = mc.encrypt_record(record, [(p.address, p.enc_pub), (d1.address, d1.enc_pub)], pp)
    key_v1 = mc.derive_stego_key(rid, pp)                                           # turunan lama: master + id + passphrase
    data = stego.to_png_bytes(stego.embed(stego.make_sample_cover(256), blob, key_v1))
    config.ensure_dirs()
    (config.STEGO_DIR / f"{rid}.png").write_bytes(data)
    db.add_record(id=rid, patient_address=p.address, doctor_address=d1.address, title="Lama", stego_file=f"{rid}.png", stego_format="PNG",
                  cover_name="c.png", sha256=stego.sha256_hex(data), payload_bytes=len(blob), capacity_bytes=1, has_passphrase=True, key_version=1)
    db.add_recipient(rid, p.address, "patient", d1.address)
    db.add_recipient(rid, d1.address, "author", d1.address)
    rec = db.get_record(rid)
    assert rec is not None
    assert rs.open_record(rec, p, pp)["diagnosis"] == "Rekam lama" and rs.open_record(rec, d1, pp)["diagnosis"] == "Rekam lama"
    with pytest.raises(mc.MediCryptError):
        rs.open_record(rec, p, "salah")
    rs.reencrypt(rec, p, pp, add=(d2.address,))                                      # berbagi tetap bekerja pada rekam lama
    assert rs.open_record(db.get_record(rid), d2, pp)["diagnosis"] == "Rekam lama"
