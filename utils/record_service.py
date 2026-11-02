"""Operasi inti rekam medis: membuka (ekstrak + dekripsi) dan enkripsi-ulang untuk berbagi/mencabut akses."""
from __future__ import annotations

import json
import os
from pathlib import Path

import config
from components import steganography as stego
from models import MedicalRecord
from utils import crypto_utils as mc
from utils import db_helper as db
import streamlit as st

WRONG_KEY = "Dekripsi gagal: passphrase salah, atau file bukan stegotext rekam ini / telah dimodifikasi."


def ensure_session() -> bytes:
    """Buka kunci DEK dari memori sesi dan minimal-ink ; tetap bisa membuka.

    Jika keluar (session habis), kalibrasi error user-friendly bukan traceback.
    """
    dek = st.session_state.get("DEK")
    if not dek:
        raise mc.MediCryptError("Sesi kedaluwarsa, silakan login ulang.")
    return dek


def stego_path(rec) -> Path:
    return Path(config.STEGO_DIR) / rec.stego_file


def _read(rec, data: bytes, passphrase: str | None):
    """Return (array_citra, blob_utama, phi_blob, diag_blob, sig_blob, stego_key)."""
    arr = stego.load_image(data)
    for key in mc.stego_key_candidates(rec.id, rec.key_version, passphrase or None):
        blob, phi_blob, diag_blob, sig_blob = stego.extract(arr, key)
        if blob[:4] == mc.MAGIC:
            return arr, blob, phi_blob, diag_blob, sig_blob, key
    raise mc.MediCryptError(WRONG_KEY)


def open_record(rec, user, passphrase: str | None = None) -> dict:
    ensure_session()                                   # minta DEK otomatis di memori sesi (tidak minta passphrase manual)
    _, blob, phi_blob, diag_blob, sig_blob, _ = _read(rec, stego_path(rec).read_bytes(), passphrase)
    record = mc.decrypt_record(blob, user.address, user.enc_priv, passphrase or None)
    if phi_blob:
        try:
            record["_phi"] = mc.decrypt_phi(phi_blob, user.address, user.enc_priv, passphrase or None)
            db.log_event(user.address, "ekstrak_phi", rec.id)
        except mc.MediCryptError:
            record["_phi"] = None
    if diag_blob:
        try:
            record["_diagnosis"] = mc.decrypt_diagnosis(diag_blob, user.address, user.enc_priv, passphrase or None)
            db.log_event(user.address, "ekstrak_diagnosis", rec.id)
        except mc.MediCryptError:
            record["_diagnosis"] = None
    if sig_blob and record.get("_diagnosis"):
        try:
            if mc.verify_diagnosis(sig_blob, json.dumps(record["_diagnosis"], ensure_ascii=False, sort_keys=True).encode()):
                record["_diagnosis_verified"] = True
                db.log_event(user.address, "verifikasi_signature_diagnosis", rec.id)
        except mc.MediCryptError:
            record["_diagnosis_verified"] = False
    return record


def save_new_record(
    patient_addr: str, doctor_addr: str, title: str,
    cover_data: bytes, cover_name: str, payload: dict,
    phi_data: dict | None = None, diag_data: dict | None = None,
    passphrase: str | None = None
) -> str:
    """Simpan rekam medis baru dengan payload utama, PHI, dan diagnosis opsional."""
    import uuid
    rec_id = uuid.uuid4().hex
    
    # 1. Siapkan penerima (pasien + dokter)
    recipients = []
    for addr in [patient_addr, doctor_addr]:
        u = db.get_user(addr)
        if not u: raise ValueError(f"User {addr} tidak ditemukan.")
        recipients.append((u.address, u.enc_pub))
    
    # 2. Enkripsi
    main_blob = mc.encrypt_record(payload, recipients, passphrase)
    phi_blob = mc.encrypt_phi(phi_data, recipients, passphrase) if phi_data else None
    diag_blob = mc.encrypt_diagnosis(diag_data, recipients, passphrase) if diag_data else None
    
    # 3. Tanda tangan diagnosis (opsional, jika dokter punya Ed25519)
    sig_blob = None
    if diag_blob:
        doc_user = db.get_user(doctor_addr)
        if doc_user and doc_user.ed_priv:
            try:
                sig_blob = mc.sign_diagnosis(diag_blob, doc_user.ed_priv)
            except Exception:
                pass  # Jika gagal, lanjut tanpa signature
    
    # 4. Stego
    arr = stego.load_image(cover_data)
    key = mc.derive_stego_key_v2(rec_id, passphrase)
    stego_arr = stego.embed(arr, main_blob, key, phi_blob, diag_blob, sig_blob)
    
    # 5. Klasifikasi AI
    from utils import disease_classifier
    ai_label = disease_classifier.predict_disease_class(payload.get("diagnosis", "")).get("disease_class")
    
    # 6. Simpan file
    ext = Path(cover_name).suffix.upper().replace(".", "") or "PNG"
    if ext not in ("PNG", "BMP"): ext = "PNG"
    fname = f"{rec_id}.{ext.lower()}"
    out_path = Path(config.STEGO_DIR) / fname
    out_bytes = stego.to_png_bytes(stego_arr) if ext == "PNG" else stego.to_bmp_bytes(stego_arr)
    out_path.write_bytes(out_bytes)
    
    # 7. DB
    db.add_record(
        id=rec_id, patient_address=patient_addr, doctor_address=doctor_addr, title=title,
        stego_file=fname, stego_format=ext, cover_name=cover_name,
        sha256=stego.sha256_hex(out_bytes),
        payload_bytes=len(main_blob),
        capacity_bytes=stego.capacity_bytes(arr, len(phi_blob) if phi_blob else 0, len(diag_blob) if diag_blob else 0),
        psnr=stego.psnr(arr, stego_arr),
        ssim=stego.ssim(arr, stego_arr),
        has_passphrase=bool(passphrase),
        has_phi=bool(phi_blob),
        phi_bytes=len(phi_blob) if phi_blob else 0,
        ai_disease_class=ai_label
    )
    
    # Update diagnosis metadata
    if diag_blob:
        with db.session_scope() as s:
            row = s.get(db.MedicalRecord, rec_id)
            row.has_diagnosis = True
            row.diagnosis_bytes = len(diag_blob)
    
    return rec_id


def reencrypt(rec, user, passphrase: str | None = None, add: tuple[str, ...] = (), remove: tuple[str, ...] = ()) -> None:
    """Ubah daftar penerima. Isi dienkripsi ulang (termasuk PHI + diagnosis)."""
    if user.address.lower() != rec.patient_address.lower():
        raise PermissionError("Hanya pasien pemilik yang boleh mengubah akses rekam.")
    path = stego_path(rec)
    arr, blob, phi_blob, diag_blob, sig_blob, key = _read(rec, path.read_bytes(), passphrase)
    
    record = mc.decrypt_record(blob, user.address, user.enc_priv, passphrase or None)
    phi = None
    if phi_blob:
        phi = mc.decrypt_phi(phi_blob, user.address, user.enc_priv, passphrase or None)
    diag = None
    if diag_blob:
        diag = mc.decrypt_diagnosis(diag_blob, user.address, user.enc_priv, passphrase or None)

    current = {r.address: r for r in db.list_recipients(rec.id)}
    wanted = set(current) | {a.lower() for a in add}
    for addr in (a.lower() for a in remove):
        if addr in current and current[addr].role in ("patient", "author"):
            raise ValueError("Pasien pemilik dan dokter pembuat tidak dapat dicabut.")
        wanted.discard(addr)
    
    wanted.add(user.address.lower())
    
    identities = {a: db.get_user(a) for a in wanted}
    missing = [a for a, u in identities.items() if u is None]
    if missing:
        raise ValueError(f"Penerima {missing} belum memiliki dompet tertaut.")
    
    recip_list = [(a, identities[a].enc_pub) for a in sorted(wanted)]
    
    new_blob = mc.encrypt_record(record, recip_list, passphrase or None)
    new_phi_blob = mc.encrypt_phi(phi, recip_list, passphrase or None) if phi else None
    new_diag_blob = mc.encrypt_diagnosis(diag, recip_list, passphrase or None) if diag else None
    
    # Re-sign diagnosis
    new_sig_blob = None
    if new_diag_blob:
        doc_user = db.get_user(rec.doctor_address)
        if doc_user and doc_user.ed_priv:
            try:
                new_sig_blob = mc.sign_diagnosis(new_diag_blob, doc_user.ed_priv)
            except Exception:
                pass
    
    new_arr = stego.embed(arr, new_blob, key, new_phi_blob, new_diag_blob, new_sig_blob)

    out = stego.to_png_bytes(new_arr) if rec.stego_format == "PNG" else stego.to_bmp_bytes(new_arr)
    
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(out)
    os.replace(tmp, path)
    
    db.update_record_file(rec.id, stego.sha256_hex(out), len(new_blob))
    with db.session_scope() as s:
        row = s.get(MedicalRecord, rec.id)
        row.phi_bytes = len(new_phi_blob) if new_phi_blob else 0
        row.has_phi = bool(new_phi_blob)
        row.diagnosis_bytes = len(new_diag_blob) if new_diag_blob else 0
        row.has_diagnosis = bool(new_diag_blob)
    
    for addr in (a.lower() for a in add):
        db.add_recipient(rec.id, addr, "shared", user.address)
    for addr in (a.lower() for a in remove):
        db.remove_recipient(rec.id, addr)
