"""Elemen UI bersama."""
from __future__ import annotations

import pandas as pd
import streamlit as st

CSS = """
<style>
.block-container { padding-top: 2.2rem; max-width: 1180px; }
[data-testid="stMetricValue"] { font-size: 1.55rem; }
.smw-note { border-left: 3px solid #0b6e6e; padding: .5rem .9rem; margin: .4rem 0 1rem;
  background: rgba(11,110,110,.07); border-radius: 0 6px 6px 0; }
.smw-role { display: inline-block; padding: 1px 9px; border-radius: 999px; font-size: .8rem;
  border: 1px solid rgba(11,110,110,.55); color: #0b6e6e; }
</style>
"""

ROLE_LABEL = {"patient": "Pasien", "doctor": "Dokter", "admin_security": "Admin Keamanan", "admin_custom": "Admin Kustom", "admin": "Admin"}

PRIVACY_SUMMARY = (
    "Kami memproses data akun (nama, email, nomor STR untuk dokter) dan data kesehatan yang Anda atau dokter Anda masukkan, "
    "untuk menyediakan rekam medis elektronik. Data kesehatan dienkripsi; hanya Anda dan dokter yang Anda setujui yang dapat "
    "membukanya. Anda berhak mengakses, mengoreksi, mengekspor, dan mengajukan penghapusan data lewat menu Permintaan hak data. "
    "Catatan akses disimpan sebagai jejak audit. Pemberitahuan privasi lengkap disediakan oleh penyelenggara layanan."
)


DEC_CACHE = "dec_cache"   # {record_id: isi rekam terdekripsi}; dibersihkan saat kunci dikunci/keluar


def help_tooltip(text: str) -> None:
    """Tooltip bantuan sederhana untuk pasien."""
    st.markdown(f"ℹ️ *{text}*")


def clear_decrypted() -> None:
    st.session_state.pop(DEC_CACHE, None)
    st.session_state.pop("export_zip", None)


def log_view_once(user, action: str) -> None:
    """Catat akses halaman sensitif satu kali per sesi (bukan setiap rerun)."""
    from utils import db_helper as db
    seen = st.session_state.setdefault("_viewed", set())
    if action not in seen:
        seen.add(action)
        db.log_event(user.address, action)


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
    st.sidebar.image("views/logo.png", width="stretch")



def note(text: str) -> None:
    st.markdown(f'<div class="smw-note">{text}</div>', unsafe_allow_html=True)


def fmt_psnr(v: float | None) -> str:
    return "∞ (identik)" if v is None or v == float("inf") else f"{v:.2f} dB"


def show_metrics(psnr_v, ssim_v, payload: int, capacity: int) -> None:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("PSNR", fmt_psnr(psnr_v))
    c2.metric("SSIM", "—" if ssim_v is None else f"{ssim_v:.6f}")
    c3.metric("Payload", f"{payload:,} B")
    c4.metric("Kapasitas terpakai", f"{(payload / capacity * 100) if capacity else 0:.2f}%")


def render_record(rec: dict, is_patient: bool = False) -> None:
    """Tampilkan rekam medis hasil dekripsi.
    
    Args:
        rec: Record dictionary.
        is_patient: Saat True, sembunyikan metrik teknis dan PHI sensitif,
                    gunakan bahasa ramah untuk badge verifikasi.
    """
    patient, doctor = rec.get("patient", {}), rec.get("doctor", {})
    visit, vitals = rec.get("visit", {}), rec.get("vitals", {})
    st.markdown(f"#### {rec.get('title', 'Rekam medis')}")
    
    c1, c2, c3 = st.columns(3)
    c1.markdown(f"**Pasien**  \n{patient.get('name', '-')}")
    c2.markdown(f"**Dokter**  \n{doctor.get('name', '-')}")
    c3.markdown(f"**Kunjungan**  \n{visit.get('date', '-')} · {visit.get('type', '-')}")
    
    # Hanya tampilkan metrik vital saat bukan pasien
    if not is_patient:
        v1, v2, v3, v4 = st.columns(4)
        v1.metric("Tekanan darah", vitals.get("bp") or "—")
        v2.metric("Suhu", f"{vitals['temp']:.1f} °C" if vitals.get("temp") else "—")
        v3.metric("Nadi", f"{vitals['pulse']} /mnt" if vitals.get("pulse") else "—")
        v4.metric("SpO₂", f"{vitals['spo2']} %" if vitals.get("spo2") else "—")
    
    if rec.get("amends"):
        st.caption(f"Addendum atas rekam {rec['amends'][:8]}")
    
    # Keluhan dan Diagnosis (fokus pasien)
    for label, key in [("Keluhan", "complaint"), ("Diagnosis", "diagnosis")]:
        if rec.get(key):
            st.markdown(f"**{label}**")
            st.write(rec[key])
    
    if rec.get("icd10"):
        st.markdown("**Kode ICD-10**: " + ", ".join(rec["icd10"]))
    
    if rec.get("allergies"):
        st.markdown("**Alergi**")
        st.write("\n".join(f"- {a}" for a in rec["allergies"]))
    
    # Tabel Resep Obat
    if rec.get("medications"):
        st.markdown("**Daftar Obat**")
        med_df = pd.DataFrame(rec["medications"])
        # Pastikan kolom yang diharapkan ada
        if "name" in med_df.columns:
            st.dataframe(med_df, hide_index=True)
        else:
            st.write(rec["medications"])
    
    # Catatan klinis
    for label, key in [("Riwayat klinis", "history"), ("Catatan", "notes")]:
        if rec.get(key):
            st.markdown(f"**{label}**")
            st.write(rec[key])
    
    # Diagnosis Sensitif (hanya untuk bukan pasien / admin / dokter)
    # Pasien melihat badge verifikasi hanya
    diag = rec.get("_diagnosis", {})
    verified = rec.get("_diagnosis_verified", False)
    doctor_name = diag.get("signed_by", "dokter") if diag else "dokter"
    
    if is_patient:
        # Badge ramah untuk pasien
        if verified:
            st.markdown(f'<span style="color:#0b6e6e; font-weight:bold;">✓ Terverifikasi oleh dr. {doctor_name}</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span style="color:#d32f2f; font-weight:bold;">⚠ Belum Diverifikasi</span>', unsafe_allow_html=True)
    else:
        # PHI dan Diagnosis Sensitif untuk dokter/admin
        if rec.get("_phi"):
            st.divider()
            st.markdown("### 🔒 Protected Health Information (PHI)")
            phi = rec["_phi"]
            p1, p2 = st.columns(2)
            p1.markdown(f"**Nama lengkap**: {phi.get('name', '—')}")
            p2.markdown(f"**Nomor rekam medis**: {phi.get('mrn', '—')}")
            p3, p4 = st.columns(2)
            p3.markdown(f"**NIK**: {phi.get('nik', '—')}")
            p4.markdown(f"**Tanggal lahir**: {phi.get('dob', '—')}")
            st.markdown(f"**Jenis kelamin**: {phi.get('gender', '—')}")
            st.markdown(f"**Alamat**: {phi.get('address', '—')}")
            st.markdown(f"**Telepon**: {phi.get('phone', '—')}")
            st.caption(f"Dicatat oleh dokter: {phi.get('recorded_by', '—')} · {phi.get('recorded_at', '—')}")
        
        if diag:
            st.divider()
            st.markdown("### 🔐 Diagnosis Sensitif (Tanda Tangan Digital)")
            if verified:
                st.success("✓ Tanda tangan Ed25519 terverifikasi oleh sistem")
            else:
                st.error("✗ Tanda tangan diagnosis TIDAK VALID atau hilang")
            if diag.get("final_diagnosis"):
                st.markdown(f"**Diagnosis akhir**: {diag['final_diagnosis']}")
            if diag.get("sensitive_history"):
                st.markdown(f"**Riwayat sensitif**: {diag['sensitive_history']}")
            if diag.get("high_dose_meds"):
                st.markdown("**Obat dosis tinggi**")
                df_meds = pd.DataFrame(diag["high_dose_meds"])
                st.dataframe(df_meds, hide_index=True)
            st.caption(f"Ditandatangani oleh dokter: {diag.get('signed_by', '—')} · {diag.get('signed_at', '—')}")
