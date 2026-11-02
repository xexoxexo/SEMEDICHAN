"""Verifikasi integritas stegotext (SHA-256) dan dekripsi dari file unggahan."""
from __future__ import annotations

import streamlit as st

from components import steganography as stego
from utils import access
from utils import db_helper as db
from utils import web3_utils
from views import records, ui


def render(user) -> None:
    is_patient = user.role == "patient"
    
    if is_patient:
        st.header("Cek Keaslian Dokumen")
        st.markdown("Unggah file gambar medis untuk memeriksa apakah file tersebut asli dari sistem.")
        up = st.file_uploader("Pilih File (PNG/BMP)", type=["png", "bmp"], key="verify_upload")
        if up is None:
            return
        data = up.getvalue()
        sha = stego.sha256_hex(data)
        rec = db.find_record_by_hash(sha)
        db.log_event(user.address, "verifikasi_hash", rec.id if rec else "", "cocok" if rec else "tidak dikenal")
        if rec is None:
            st.error("❌ **Dokumen Tidak Valid**")
            st.markdown("File ini **bukan** stegotext asli dari sistem, atau sudah dimodifikasi (termasuk dikompres ulang atau diedit).")
            return
        st.success("✅ **Dokumen Asli**")
        st.markdown(f"File ini cocok dengan rekam medis **{rec.title}** yang dibuat pada **{rec.created_at.strftime('%Y-%m-%d %H:%M')}**.")
        st.markdown("---")
        st.caption("Hanya memverifikasi keaslian file. Untuk melihat isi rekam medis, gunakan menu **Rekam Medis Saya**.")
    else:
        st.header("Verifikasi file stegotext")
        ui.note("Unggah stegotext untuk mencocokkan hash SHA-256 dengan catatan sistem. Hash berbeda berarti file berubah.")
        up = st.file_uploader("Stegotext (PNG/BMP)", type=["png", "bmp"], key="verify_upload")
        if up is None:
            return
        data = up.getvalue()
        sha = stego.sha256_hex(data)
        st.code(sha, language=None)
        rec = db.find_record_by_hash(sha)
        db.log_event(user.address, "verifikasi_hash", rec.id if rec else "", "cocok" if rec else "tidak dikenal")
        if rec is None:
            st.warning(
                "Hash tidak dikenal. File ini bukan stegotext asli dari sistem, atau sudah dimodifikasi "
                "(termasuk dikompres ulang atau diedit), sehingga data tidak dapat dipulihkan."
            )
            return
        st.success("Hash cocok dengan catatan sistem. File utuh dan tidak berubah.")
        st.write(f"Rekam `{rec.id[:8]}` · {rec.title} · dibuat {rec.created_at:%Y-%m-%d %H:%M} · "
                 f"pasien `{web3_utils.short(rec.patient_address)}`")
        if not access.can_decrypt(user, rec):
            st.info("Anda tidak berhak mendekripsi rekam ini (hanya pasien pemilik dan dokter pembuat).")
            return
        passphrase = None
        if rec.has_passphrase:
            passphrase = st.text_input("Passphrase rekam ini", type="password", key="verify_pp")
        if st.button("Ekstrak dan dekripsi", key="verify_dec"):
            record = records.decrypt_stored(user, rec, passphrase)
            if record:
                ui.render_record(record)
