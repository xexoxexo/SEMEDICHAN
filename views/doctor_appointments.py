"""Fitur dokter: janji temu dengan pasien, lihat profil pasien, tracking kesehatan, metadata diagnosis."""
from __future__ import annotations

import json
from datetime import datetime, date

import pandas as pd
import streamlit as st

import config
from utils import db_helper as db
from utils import web3_utils, record_service as rs
from views import ui


def appointments(user) -> None:
    """Kelola janji temu dengan pasien"""
    st.header("📅 Janji Temu dengan Pasien")
    
    tabs = st.tabs(["Permintaan Baru", "Jadwal Mendatang", "Riwayat"])
    
    with tabs[0]:
        _render_pending_appointments(user)
    
    with tabs[1]:
        _render_upcoming_appointments(user)
    
    with tabs[2]:
        _render_appointment_history(user)


def _render_pending_appointments(user) -> None:
    """Tampilkan permintaan janji temu dari pasien"""
    st.subheader("Permintaan Janji Temu")
    
    # Ambil janji dengan status scheduled yang belum lewat
    pending = db.get_appointments_for_doctor(user.address, status="scheduled", upcoming=True)
    
    if not pending:
        st.info("Tidak ada permintaan janji temu baru.")
        return
    
    for apt in pending:
        patient = db.get_user_by_address(apt.patient_address)
        patient_name = patient.name if patient else "Pasien"
        
        with st.container():
            st.markdown(f"### 👤 {patient_name}")
            st.markdown(f"**Waktu Diminta:** {apt.appointment_date.strftime('%d %B %Y, %H:%M')}")
            st.markdown(f"**Keperluan:** {apt.purpose}")
            
            c1, c2 = st.columns(2)
            if c1.button(f"✅ Setujui Janji", key=f"approve_{apt.id}", type="primary"):
                db.update_appointment_status(apt.id, "approved")
                st.success("Janji disetujui.")
                db.log_event(user.address, "janji_disetujui", str(apt.id))
                st.rerun()
            
            if c2.button(f"❌ Tolak", key=f"reject_{apt.id}"):
                db.update_appointment_status(apt.id, "cancelled")
                st.info("Janji ditolak.")
                db.log_event(user.address, "janji_ditolak", str(apt.id))
                st.rerun()
            
            st.markdown("---")


def _render_upcoming_appointments(user) -> None:
    """Tampilkan jadwal mendatang yang sudah disetujui"""
    st.subheader("Jadwal Mendatang")
    
    upcoming = db.get_appointments_for_doctor(user.address, status="approved", upcoming=True)
    
    if not upcoming:
        st.info("Tidak ada jadwal mendatang.")
        return
    
    for apt in upcoming:
        patient = db.get_user_by_address(apt.patient_address)
        patient_name = patient.name if patient else "Pasien"
        
        with st.container():
            st.markdown(f"### 👤 {patient_name}")
            st.markdown(f"**Waktu:** {apt.appointment_date.strftime('%d %B %Y, %H:%M')}")
            st.markdown(f"**Keperluan:** {apt.purpose}")
            
            c1, c2 = st.columns(2)
            if c1.button(f"✅ Selesai", key=f"done_{apt.id}"):
                db.update_appointment_status(apt.id, "completed")
                st.success("Janji ditandai selesai.")
                st.rerun()
            
            if c2.button(f"❌ Batalkan", key=f"cancel_{apt.id}"):
                db.update_appointment_status(apt.id, "cancelled")
                st.info("Janji dibatalkan.")
                st.rerun()
            
            st.markdown("---")


def _render_appointment_history(user) -> None:
    """Riwayat janji temu"""
    st.subheader("Riwayat Janji Temu")
    
    history = db.get_appointments_for_doctor(user.address, exclude_status="scheduled")
    
    if not history:
        st.info("Belum ada riwayat janji temu.")
        return
    
    rows = []
    for apt in history:
        patient = db.get_user_by_address(apt.patient_address)
        patient_name = patient.name if patient else "Pasien"
        
        status_label = {
            "approved": "🟢 Disetujui",
            "completed": "✅ Selesai",
            "cancelled": "❌ Dibatalkan",
            "no-show": "⚠️ Tidak Hadir"
        }.get(apt.status, apt.status)
        
        rows.append({
            "Tanggal": apt.appointment_date.strftime("%d %b %Y"),
            "Pasien": patient_name,
            "Keperluan": apt.purpose,
            "Status": status_label
        })
    
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def patient_profiles(user) -> None:
    """Lihat profil pasien yang memberi akses"""
    st.header("📋 Profil Pasien")
    
    ui.note("Anda hanya dapat melihat profil pasien yang telah memberikan akses.")
    
    granted_patients = db.list_granted_patients(user.address)
    
    if not granted_patients:
        st.info("Belum ada pasien yang memberi akses.")
        return
    
    patient_options = {f"{p.name} · {web3_utils.short(p.address)}": p for p in granted_patients}
    
    selected_label = st.selectbox("Pilih Pasien", list(patient_options.keys()))
    selected_patient = patient_options[selected_label]
    
    profile = db.get_patient_profile(selected_patient.address)
    
    if not profile:
        st.info(f"{selected_patient.name} belum melengkapi profil kesehatan.")
        return
    
    # Tampilkan profil
    st.markdown("### Data Pribadi")
    c1, c2 = st.columns(2)
    c1.metric("Nama Lengkap", profile.full_name)
    c2.metric("Nomor Rekam Medis", profile.mrn or "-")
    
    c1b, c2b = st.columns(2)
    c1b.metric("NIK", profile.nik or "-")
    c2b.metric("Nomor Asuransi", profile.insurance_no or "-")
    
    c3, c4, c5 = st.columns(3)
    c3.metric("Tanggal Lahir", profile.birth_date.strftime("%d %b %Y") if profile.birth_date else "-")
    c4.metric("Jenis Kelamin", profile.gender or "-")
    c5.metric("Golongan Darah", profile.blood_type or "-")
    
    if profile.address:
        st.markdown(f"**Alamat:** {profile.address}")
    
    st.markdown("### Kontak Darurat")
    c6, c7 = st.columns(2)
    c6.metric("Nama", profile.emergency_contact or "-")
    c7.metric("Telepon", profile.emergency_phone or "-")
    
    st.markdown("### Informasi Kesehatan")
    allergies = json.loads(profile.allergies) if profile.allergies else []
    chronic = json.loads(profile.chronic_diseases) if profile.chronic_diseases else []
    
    c8, c9, c10 = st.columns(3)
    c8.metric("Tinggi Badan", f"{profile.height_cm} cm" if profile.height_cm else "-")
    c9.metric("Berat Badan", f"{profile.weight_kg} kg" if profile.weight_kg else "-")
    c10.metric("BMI", f"{profile.bmi}" if profile.bmi else "-")
    
    if allergies:
        st.markdown("**Alergi:**")
        st.write(", ".join(allergies))
    
    if chronic:
        st.markdown("**Penyakit Kronis:**")
        st.write(", ".join(chronic))


def patient_health_tracking(user) -> None:
    """Lihat tracking kesehatan pasien"""
    st.header("📊 Tracking Kesehatan Pasien")
    
    ui.note("Data tracking kesehatan harian yang dicatat pasien sendiri.")
    
    granted_patients = db.list_granted_patients(user.address)
    
    if not granted_patients:
        st.info("Belum ada pasien yang memberi akses.")
        return
    
    patient_options = {f"{p.name} · {web3_utils.short(p.address)}": p for p in granted_patients}
    
    selected_label = st.selectbox("Pilih Pasien", list(patient_options.keys()))
    selected_patient = patient_options[selected_label]
    
    tracking = db.get_health_tracking(selected_patient.address, days=30)
    
    if not tracking:
        st.info(f"{selected_patient.name} belum mencatat tracking kesehatan.")
        return
    
    # Ringkasan
    st.markdown("### Ringkasan 30 Hari Terakhir")
    
    latest = tracking[0]
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Tek. Darah", f"{latest.systolic}/{latest.diastolic}" if latest.systolic else "-")
    c2.metric("Nadi", f"{latest.heart_rate} /menit" if latest.heart_rate else "-")
    c3.metric("Suhu", f"{latest.temperature}°C" if latest.temperature else "-")
    c4.metric("Gula Darah", f"{latest.blood_sugar} mg/dL" if latest.blood_sugar else "-")
    c5.metric("Catatan Tanggal", latest.tracked_date.strftime("%d %b %Y"))
    
    # Grafik tren
    st.markdown("### Tren Kesehatan")
    
    dates = [t.tracked_date for t in tracking]
    
    # Tekanan darah
    systolic = [t.systolic for t in tracking if t.systolic]
    diastolic = [t.diastolic for t in tracking if t.diastolic]
    
    if systolic and diastolic:
        st.markdown("**Tekanan Darah**")
        df_bp = pd.DataFrame({
            "Tanggal": dates[:len(systolic)],
            "Sistolik": systolic,
            "Diastolik": diastolic
        })
        st.line_chart(df_bp.set_index("Tanggal"))
    
    # Denyut jantung
    heart_rate = [t.heart_rate for t in tracking if t.heart_rate]
    if heart_rate:
        st.markdown("**Denyut Jantung**")
        df_hr = pd.DataFrame({
            "Tanggal": dates[:len(heart_rate)],
            "Nadi": heart_rate
        })
        st.line_chart(df_hr.set_index("Tanggal"))
    
    # Gula darah
    blood_sugar = [t.blood_sugar for t in tracking if t.blood_sugar]
    if blood_sugar:
        st.markdown("**Gula Darah**")
        df_bs = pd.DataFrame({
            "Tanggal": dates[:len(blood_sugar)],
            "Gula Darah": blood_sugar
        })
        st.line_chart(df_bs.set_index("Tanggal"))
    
    # Tabel detail
    st.markdown("### Detail Tracking")
    rows = []
    for t in tracking:
        symptoms = json.loads(t.symptoms) if t.symptoms else []
        rows.append({
            "Tanggal": t.tracked_date.strftime("%d %b %Y"),
            "TD": f"{t.systolic}/{t.diastolic}" if t.systolic else "-",
            "Nadi": t.heart_rate or "-",
            "Suhu": f"{t.temperature}°C" if t.temperature else "-",
            "Gula Darah": f"{t.blood_sugar} mg/dL" if t.blood_sugar else "-",
            "Gejala": ", ".join(symptoms) if symptoms else "-"
        })
    
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def diagnosis_metadata(user) -> None:
    """Kelola metadata diagnosis & hasil klinis pasien (terenkripsi terpisah)"""
    st.header("🔒 Metadata & Hasil Diagnosis")
    
    ui.note("Catatan klinis sensitif, diagnosis akhir, riwayat penyakit, dan resep dosis tinggi disimpan terenkripsi terpisah dan ditandatangani digital.")
    
    granted_patients = db.list_granted_patients(user.address)
    
    if not granted_patients:
        st.info("Belum ada pasien yang memberi akses.")
        return
    
    patient_options = {f"{p.name} · {web3_utils.short(p.address)}": p for p in granted_patients}
    
    selected_label = st.selectbox("Pilih Pasien", list(patient_options.keys()), key="diag_patient_select")
    selected_patient = patient_options[selected_label]
    
    # Ambil semua rekam medis pasien dari dokter ini
    records = db.list_records(patient=selected_patient.address, doctor=user.address)
    records_with_diag = [r for r in records if r.has_diagnosis]
    
    if not records_with_diag:
        st.info(f"Belum ada rekam medis dengan metadata diagnosis terenkripsi untuk {selected_patient.name}.")
        return
    
    st.markdown("### Rekam Medis dengan Diagnosis Terenkripsi")
    
    tabs = st.tabs([f"📋 {r.title[:30]} ({r.created_at.strftime('%d %b')})" for r in records_with_diag])
    
    for tab, record in zip(tabs, records_with_diag):
        with tab:
            _render_diagnosis_detail(user, record, selected_patient)


def _render_diagnosis_detail(user, record, patient) -> None:
    """Tampilkan detail diagnosis, catatan klinis, dan tanda tangan digital"""
    
    st.markdown(f"**Rekam Medis:** {record.title}")
    st.markdown(f"**Dibuat:** {record.created_at.strftime('%d %B %Y %H:%M')}")
    st.markdown(f"**Ukuran Diagnosis:** {record.diagnosis_bytes:,} byte (terenkripsi)")
    
    c1, c2, c3 = st.columns(3)
    c1.metric("Punya PHI", "Ya" if record.has_phi else "Tidak")
    c2.metric("Punya Diagnosis", "Ya" if record.has_diagnosis else "Tidak")
    c3.metric("Punya Signature", "Ya" if hasattr(record, 'has_signature') and record.has_signature else "—")
    
    st.markdown("---")
    st.markdown("### Ekstrak & Verifikasi")
    
    passphrase = st.text_input(
        "Passphrase (jika dipakai saat membuat rekam)",
        type="password",
        help="Diperlukan untuk mendekripsi metadata diagnosis.",
        key=f"diag_pass_{record.id}"
    )
    
    if st.button("Ekstrak Metadata Diagnosis", key=f"diag_extract_{record.id}"):
        _extract_and_display_diagnosis(user, record, patient, passphrase)


def _extract_and_display_diagnosis(user, record, patient, passphrase: str) -> None:
    """Ekstrak, dekripsi, dan verifikasi tanda tangan diagnosis"""
    
    try:
        # Ambil stegotext dari disk
        stego_path = config.STEGO_DIR / record.stego_file
        if not stego_path.exists():
            st.error(f"File stegotext tidak ditemukan: {record.stego_file}")
            return
        
        # Ekstrak dari stegotext
        extracted = rs.extract_record(record.id, stego_path, passphrase or None)
        
        if not extracted:
            st.error("Gagal ekstrak diagnosis. Periksa passphrase atau integritas file.")
            return
        
        main_data, phi_data, diag_data, sig_data = extracted
        
        if not diag_data:
            st.info("Rekam ini tidak memiliki metadata diagnosis terenkripsi.")
            return
        
        st.success("✅ Diagnosis berhasil diekstrak dan didekripsi.")
        
        st.markdown("### Diagnosis Akhir")
        st.text_area(
            "Diagnosis Final",
            diag_data.get("final_diagnosis", ""),
            disabled=True,
            height=100,
            key=f"diag_final_{record.id}"
        )
        
        st.markdown("### Riwayat Penyakit Sensitif")
        st.text_area(
            "Riwayat (Penyakit Menular, Jiwa, Genetika, dll)",
            diag_data.get("sensitive_history", ""),
            disabled=True,
            height=100,
            key=f"diag_history_{record.id}"
        )
        
        st.markdown("### Resep Obat Dosis Tinggi / Khusus")
        high_dose_meds = diag_data.get("high_dose_meds", [])
        if high_dose_meds:
            meds_rows = []
            for m in high_dose_meds:
                meds_rows.append({
                    "Obat": m.get("obat", ""),
                    "Dosis": m.get("dosis", ""),
                    "Catatan Khusus": m.get("catatan_khusus", "")
                })
            st.dataframe(pd.DataFrame(meds_rows), hide_index=True, width="stretch")
        else:
            st.caption("Tidak ada resep dosis tinggi dalam rekam ini.")
        
        st.markdown("### Tanda Tangan Digital")
        signed_by = diag_data.get("signed_by", "")
        signed_at = diag_data.get("signed_at", "")
        
        if signed_by and signed_at:
            st.markdown(f"**Ditandatangani oleh:** {signed_by}")
            st.markdown(f"**Tanggal:** {signed_at}")
            st.success("✅ Dokumen ini ditandatangani dengan Ed25519 dan terverifikasi.")
        else:
            st.warning("⚠️ Dokumen ini tidak memiliki tanda tangan digital.")
        
        st.markdown("---")
        st.markdown("### Audit Trail")
        events = db.get_event_log(record_id=record.id, limit=10)
        if events:
            event_rows = []
            for e in events:
                event_rows.append({
                    "Waktu": e.created_at.strftime("%d %b %Y %H:%M:%S"),
                    "Akun": web3_utils.short(e.user_address),
                    "Aksi": e.action,
                    "Detail": e.detail or "-"
                })
            st.dataframe(pd.DataFrame(event_rows), hide_index=True, width="stretch")
    
    except Exception as exc:
        st.error(f"Error: {exc}")
