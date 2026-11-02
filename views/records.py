"""Daftar rekam medis, dekripsi, berbagi akses, dan ekspor FHIR (portal dokter, pasien, admin)."""
from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from components import steganography as stego
from utils import access, fhir
from utils import crypto_utils as mc
from utils import db_helper as db
from utils import record_service as rs
from utils import web3_utils
from views import ui


def decrypt_stored(user, rec, passphrase: str | None) -> dict | None:
    """Ekstrak stego + dekripsi hybrid satu rekam. Menampilkan galat sendiri bila gagal."""
    if not access.can_decrypt(user, rec):
        db.log_event(user.address, "dekripsi_ditolak", rec.id)
        st.error("Akses ditolak: Anda bukan penerima sah rekam ini.")
        return None
    path = rs.stego_path(rec)
    if not path.exists():
        st.error("File stegotext tidak ditemukan di server.")
        return None
    if stego.sha256_hex(path.read_bytes()) != rec.sha256:
        db.log_event(user.address, "integritas_gagal", rec.id, "SHA-256 file berbeda dari catatan")
        st.warning("Peringatan integritas: hash file berbeda dari catatan. File mungkin telah dimodifikasi.")
    try:
        record = rs.open_record(rec, user, passphrase or None)
    except (stego.StegoError, mc.MediCryptError) as exc:
        db.log_event(user.address, "dekripsi_gagal", rec.id, str(exc)[:120])
        st.error(str(exc))
        return None
    db.log_event(user.address, "dekripsi", rec.id)
    return record


def _log_download(actor: str, record_id: str, action: str) -> None:
    db.log_event(actor, action, record_id)


def _names() -> dict:
    return {u.address: u.name for u in db.list_users()}


def _sharing_panel(user, rec) -> None:
    """Pasien: bagikan ke dokter lain atau cabut. Isi dienkripsi ulang; sisa bit lama ditimpa."""
    recips = db.list_recipients(rec.id)
    names = _names()
    role_label = {"patient": "pemilik", "author": "dokter pembuat", "shared": "dibagikan"}
    with st.expander("Kelola akses rekam ini"):
        st.dataframe(pd.DataFrame([{"Nama": names.get(r.address, web3_utils.short(r.address)), "Peran": role_label[r.role],
                                    "Sejak": r.added_at.strftime("%Y-%m-%d %H:%M")} for r in recips]), hide_index=True)
        passphrase = st.text_input("Passphrase rekam ini (diperlukan untuk mengubah akses)", type="password",
                                   key=f"sharepp_{rec.id}") if rec.has_passphrase else None
        current = {r.address for r in recips}
        doctors = [u for u in db.list_users(role="doctor") if u.address not in current]
        if doctors:
            pick = st.selectbox("Bagikan ke dokter", [u.address for u in doctors], key=f"sharesel_{rec.id}",
                                format_func=lambda a: f"{names.get(a, a)} · {web3_utils.short(a)}")
            if st.button("Bagikan", key=f"sharego_{rec.id}"):
                _apply(user, rec, passphrase, add=(pick,), action="akses_dibagikan")
        for r in (x for x in recips if x.role == "shared"):
            if st.button(f"Cabut akses {names.get(r.address, web3_utils.short(r.address))}", key=f"revoke_{rec.id}_{r.address}"):
                _apply(user, rec, passphrase, remove=(r.address,), action="akses_dicabut")
        st.caption("Pencabutan berlaku untuk file terbaru. Dokter yang sudah menyimpan salinan file saat akses diberikan "
                   "masih memegang salinan itu; ini batas yang melekat pada data yang pernah dibagikan.")


def _apply(user, rec, passphrase, add=(), remove=(), action="") -> None:
    try:
        rs.reencrypt(rec, user, passphrase or None, add=add, remove=remove)
    except (PermissionError, ValueError, stego.StegoError, mc.MediCryptError) as exc:
        st.error(str(exc))
        return
    db.log_event(user.address, action, rec.id, ",".join(add or remove))
    st.session_state.get(ui.DEC_CACHE, {}).pop(rec.id, None)
    st.rerun()


def render(user, scope: str) -> None:
    """scope: patient | doctor | admin"""
    recs = db.list_records(
        patient=user.address if scope == "patient" else None,
        recipient=user.address if scope == "doctor" else None,
    )
    if not recs:
        st.info("Belum ada rekam medis.")
        return
    names = _names()

    def relation(r) -> str:
        if scope == "patient":
            return "pemilik"
        mine = next((x for x in db.list_recipients(r.id) if x.address == user.address), None)
        return {"author": "penulis", "shared": "dibagikan"}.get(mine.role, "-") if mine else "-"

    if scope == "patient":
        # TAMPILAN KARTU UNTUK PASIEN
        st.markdown("### Rekam Medis Saya")
        cache = st.session_state.setdefault(ui.DEC_CACHE, {})
        
        for rec in recs:
            doctor_name = names.get(rec.doctor_address, "Dokter")
            date_str = rec.created_at.strftime("%d %B %Y")
            
            # Tombol kartu (expandable)
            with st.expander(f"📋 {date_str} · Dr. {doctor_name}", expanded=False):
                # Auto-dekripsi saat kartu dibuka
                if rec.id not in cache:
                    record = decrypt_stored(user, rec, None)
                    if record:
                        cache[rec.id] = record
                
                shown = cache.get(rec.id)
                if shown:
                    # Tampilkan badge verifikasi
                    diag = shown.get("_diagnosis", {})
                    verified = shown.get("_diagnosis_verified", False)
                    doctor_name_sig = diag.get("signed_by", "dokter") if diag else "dokter"
                    
                    if verified:
                        st.markdown(f'<span style="color:#0b6e6e; font-weight:bold;">✓ Terverifikasi oleh dr. {doctor_name_sig}</span>', unsafe_allow_html=True)
                    else:
                        st.markdown('<span style="color:#d32f2f; font-weight:bold;">⚠ Belum Diverifikasi</span>', unsafe_allow_html=True)
                    
                    st.markdown("---")
                    
                    # Diagnosis utama
                    if shown.get("diagnosis"):
                        st.markdown(f"**Diagnosis**: {shown['diagnosis']}")
                    
                    # Keluhan
                    if shown.get("complaint"):
                        st.markdown(f"**Keluhan**: {shown['complaint']}")
                    
                    # Tabel resep obat
                    if shown.get("medications"):
                        st.markdown("**Daftar Obat**")
                        med_df = pd.DataFrame(shown["medications"])
                        if "name" in med_df.columns:
                            st.dataframe(med_df, hide_index=True)
                    
                    # Catatan klinis
                    if shown.get("history"):
                        st.markdown(f"**Riwayat Klinis**: {shown['history']}")
                    
                    if shown.get("notes"):
                        st.markdown(f"**Catatan**: {shown['notes']}")
                else:
                    st.error("Gagal mendekripsi rekam medis ini.")
        return

    # TAMPILAN TABEL UNTUK DOKTER & ADMIN
    rows = []
    for r in recs:
        row = {
            "ID": r.id[:8], "Tanggal": r.created_at.strftime("%Y-%m-%d %H:%M"), "Judul": r.title,
            "Pasien": names.get(r.patient_address, web3_utils.short(r.patient_address)),
            "Dokter": names.get(r.doctor_address, web3_utils.short(r.doctor_address)),
            "Addendum untuk": (r.amends_id or "")[:8], "Payload (B)": r.payload_bytes,
            "PSNR (dB)": None if r.psnr is None else round(r.psnr, 2),
            "SSIM": None if r.ssim is None else round(r.ssim, 6),
            "PHI": "ya" if r.has_phi else "tidak", "Diagnosis": "ya" if r.has_diagnosis else "tidak",
            "Passphrase": "ya" if r.has_passphrase else "tidak", "SHA-256": r.sha256[:16] + "…",
        }
        if scope == "doctor":
            row["Hubungan"] = relation(r)
        rows.append(row)
    
    st.dataframe(pd.DataFrame(rows), hide_index=True)

    by_id = {r.id: r for r in recs}
    chosen = st.selectbox("Pilih rekam medis", list(by_id), format_func=lambda i: f"{i[:8]} · {by_id[i].title}")
    rec = by_id[chosen]
    passphrase = None
    if rec.has_passphrase and scope != "admin":
        passphrase = st.text_input("Passphrase rekam ini", type="password", key=f"pp_{rec.id}")

    path = rs.stego_path(rec)
    c1, c2 = st.columns([1, 1])
    if path.exists():
        c2.download_button(
            "Unduh stegotext", path.read_bytes(), file_name=f"stegotext_{rec.id[:8]}.{rec.stego_format.lower()}",
            mime=f"image/{rec.stego_format.lower()}", key=f"dl_{rec.id}",
            on_click=_log_download, args=(user.address, rec.id, "unduh_stegotext"),
        )
    if scope == "admin":
        ui.note("Admin hanya melihat metadata. Isi rekam medis tidak dapat didekripsi oleh admin.")
        return

    cache = st.session_state.setdefault(ui.DEC_CACHE, {})
    if c1.button("Ekstrak dan dekripsi", key=f"dec_{rec.id}"):
        record = decrypt_stored(user, rec, passphrase)
        if record:
            cache[rec.id] = record
        else:
            cache.pop(rec.id, None)
    shown = cache.get(rec.id)
    if shown:
        st.success("Dekripsi berhasil. Integritas AES-GCM terverifikasi.")
        ui.render_record(shown, is_patient=False)
        
        # Download buttons untuk komponen terpisah
        c1, c2, c3 = st.columns(3)
        bundle = fhir.record_to_bundle(shown, rec.id)
        c1.download_button("Unduh FHIR R4 (JSON)", json.dumps(bundle, ensure_ascii=False, indent=2),
                           file_name=f"rekam_{rec.id[:8]}_fhir.json", mime="application/fhir+json", key=f"fhir_{rec.id}",
                           on_click=_log_download, args=(user.address, rec.id, "unduh_fhir"))
        
        if shown.get("_phi"):
            c2.download_button("Unduh PHI (JSON)", json.dumps(shown["_phi"], ensure_ascii=False, indent=2),
                               file_name=f"phi_{rec.id[:8]}.json", mime="application/json", key=f"phi_{rec.id}",
                               on_click=_log_download, args=(user.address, rec.id, "unduh_phi"))
        
        if shown.get("_diagnosis"):
            c3.download_button("Unduh Diagnosis (JSON)", json.dumps(shown["_diagnosis"], ensure_ascii=False, indent=2),
                               file_name=f"diagnosis_{rec.id[:8]}.json", mime="application/json", key=f"diag_{rec.id}",
                               on_click=_log_download, args=(user.address, rec.id, "unduh_diagnosis"))
    if access.can_manage_sharing(user, rec):
        _sharing_panel(user, rec)
