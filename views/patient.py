"""Fitur pasien: profil data pribadi, resep obat, tracking kesehatan, janji temu, reminder obat."""
from __future__ import annotations

import json
from datetime import datetime, date, timedelta

import pandas as pd
import streamlit as st

from models import PatientProfile, PrescriptionOrder, HealthTracking, Appointment, MedicationReminder
from utils import db_helper as db
from utils import web3_utils
from views import ui


# =============================================================================
# PROFIL PRIBADI PASIEN
# =============================================================================

def profile(user) -> None:
    """Halaman profil data pribadi pasien"""
    st.header("📋 Profil Kesehatan Saya")
    
    # Ambil atau buat profil
    profile_data = db.get_patient_profile(user.address)
    
    with st.form("profile_form"):
        st.subheader("Data Pribadi")
        c1, c2 = st.columns(2)
        full_name = c1.text_input("Nama Lengkap", value=profile_data.full_name if profile_data else user.name)
        mrn = c2.text_input("Nomor Rekam Medis (RM)", value=profile_data.mrn if profile_data else "", max_chars=32)
        
        c1b, c2b = st.columns(2)
        nik = c1b.text_input("NIK (No. KTP)", value=profile_data.nik if profile_data else "", max_chars=16)
        insurance_no = c2b.text_input("Nomor Asuransi Kesehatan", value=profile_data.insurance_no if profile_data else "", max_chars=32)
        
        c3, c4, c5 = st.columns(3)
        birth_date = c3.date_input("Tanggal Lahir", value=profile_data.birth_date if profile_data else None)
        gender = c4.selectbox("Jenis Kelamin", ["", "Laki-laki", "Perempuan"], 
                              index=["", "Laki-laki", "Perempuan"].index(profile_data.gender) if profile_data and profile_data.gender else 0)
        blood_type = c5.selectbox("Golongan Darah", ["", "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"],
                                   index=["", "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"].index(profile_data.blood_type) if profile_data and profile_data.blood_type else 0)
        
        address = st.text_area("Alamat Lengkap", value=profile_data.address if profile_data else "", max_chars=500)
        
        st.subheader("Kontak Darurat")
        c6, c7 = st.columns(2)
        emergency_contact = c6.text_input("Nama Kontak Darurat", value=profile_data.emergency_contact if profile_data else "")
        emergency_phone = c7.text_input("No. Telepon Darurat", value=profile_data.emergency_phone if profile_data else "")
        
        st.subheader("Informasi Kesehatan")
        allergies_list = profile_data.allergies if profile_data and profile_data.allergies else "[]"
        allergies_str = st.text_area("Alergi (satu per baris)", 
                                      value="\n".join(json.loads(allergies_list)) if allergies_list else "")
        
        chronic_list = profile_data.chronic_diseases if profile_data and profile_data.chronic_diseases else "[]"
        chronic_str = st.text_area("Penyakit Kronis (satu per baris)", 
                                    value="\n".join(json.loads(chronic_list)) if chronic_list else "")
        
        c8, c9, c10 = st.columns(3)
        height = c8.number_input("Tinggi Badan (cm)", min_value=0, max_value=300, 
                                  value=profile_data.height_cm if profile_data else 0)
        weight = c9.number_input("Berat Badan (kg)", min_value=0.0, max_value=500.0, 
                                  value=float(profile_data.weight_kg) if profile_data and profile_data.weight_kg else 0.0)
        
        # Hitung BMI otomatis
        bmi = None
        if height and weight and height > 0:
            bmi = round(weight / ((height / 100) ** 2), 1)
            c10.metric("BMI", bmi)
        
        submitted = st.form_submit_button("Simpan Profil", type="primary")
        
        if submitted:
            allergies_json = json.dumps([x.strip() for x in allergies_str.split("\n") if x.strip()])
            chronic_json = json.dumps([x.strip() for x in chronic_str.split("\n") if x.strip()])
            
            db.save_patient_profile(
                patient_address=user.address,
                full_name=full_name,
                mrn=mrn or None,
                nik=nik or None,
                insurance_no=insurance_no or None,
                birth_date=birth_date if birth_date else None,
                gender=gender or None,
                blood_type=blood_type or None,
                address=address or None,
                emergency_contact=emergency_contact or None,
                emergency_phone=emergency_phone or None,
                allergies=allergies_json,
                chronic_diseases=chronic_json,
                height_cm=height if height else None,
                weight_kg=weight if weight else None,
                bmi=bmi
            )
            st.success("Profil berhasil disimpan!")
            st.rerun()


# =============================================================================
# RESEP OBAT KE ADMIN CUSTOM
# =============================================================================

def prescriptions(user) -> None:
    """Daftar resep obat pasien dan status pemenuhan oleh admin custom"""
    st.header("💊 Resep Obat Saya")
    
    tabs = st.tabs(["Resep Aktif", "Riwayat Resep"])
    
    with tabs[0]:
        st.subheader("Resep Menunggu / Diproses")
        active_prescriptions = db.get_patient_prescriptions(user.address, status=["pending", "approved", "dispensed"])
        
        if not active_prescriptions:
            st.info("Tidak ada resep aktif saat ini.")
        else:
            for rx in active_prescriptions:
                _render_prescription_card(rx, user)
    
    with tabs[1]:
        st.subheader("Riwayat Resep")
        history_prescriptions = db.get_patient_prescriptions(user.address, status=["completed", "cancelled"])
        
        if not history_prescriptions:
            st.info("Belum ada riwayat resep.")
        else:
            for rx in history_prescriptions:
                _render_prescription_card(rx, user, readonly=True)


def _render_prescription_card(rx: PrescriptionOrder, user, readonly: bool = False) -> None:
    """Render kartu resep obat"""
    doctor = db.get_user_by_address(rx.doctor_address)
    doctor_name = doctor.name if doctor else "Dokter"
    
    status_colors = {
        "pending": "🟡 Menunggu",
        "approved": "🟢 Disetujui",
        "dispensed": "💊 Obat Disiapkan",
        "completed": "✅ Selesai",
        "cancelled": "❌ Dibatalkan"
    }
    
    with st.container():
        st.markdown(f"**Dr. {doctor_name}** · {rx.created_at.strftime('%d %b %Y %H:%M')}")
        st.markdown(f"Status: **{status_colors.get(rx.status, rx.status)}**")
        
        meds = json.loads(rx.medications) if rx.medications else []
        if meds:
            st.markdown("**Daftar Obat:**")
            df = pd.DataFrame(meds)
            st.dataframe(df, hide_index=True, width="stretch")
        
        if rx.instructions:
            st.markdown(f"**Aturan Pakai:** {rx.instructions}")
        
        if rx.dispensed_by:
            admin = db.get_account_by_wallet(rx.dispensed_by)
            admin_name = admin.full_name if admin else "Admin"
            st.caption(f"Disiapkan oleh: {admin_name} pada {rx.dispensed_at.strftime('%d %b %Y %H:%M')}")
        
        if rx.notes:
            st.info(f"Catatan Admin: {rx.notes}")
        
        if rx.status == "dispensed" and not readonly:
            if st.button("✅ Konfirmasi Obat Diterima", key=f"confirm_{rx.id}"):
                db.update_prescription_status(rx.id, "completed", user.address)
                st.success("Konfirmasi berhasil. Resep selesai.")
                st.rerun()
        
        st.markdown("---")


# =============================================================================
# DASHBOARD ANALISIS KESEHATAN
# =============================================================================

def health_analysis(user) -> None:
    """Dashboard analisis penyakit dan kesehatan pasien"""
    st.header("📊 Analisis Kesehatan Saya")
    
    # Ringkasan dari rekam medis
    records = db.list_records(patient=user.address)
    
    if not records:
        st.info("Belum ada data kesehatan. Mulai tracking kesehatan harian Anda.")
        return
    
    # Tab analisis
    tabs = st.tabs(["Ringkasan Diagnosa", "Tracking Harian", "Tren Kesehatan", "Input Tracking"])
    
    with tabs[0]:
        _render_diagnosis_summary(records, user)
    
    with tabs[1]:
        _render_daily_tracking(user)
    
    with tabs[2]:
        _render_health_trends(user)
    
    with tabs[3]:
        _render_tracking_input(user)


def _render_diagnosis_summary(records, user) -> None:
    """Ringkasan diagnosa dari rekam medis"""
    st.subheader("Ringkasan Diagnosa")
    
    diagnosis_counts = {}
    icd_codes = []
    
    for rec in records:
        # Decrypt record untuk ambil diagnosa
        # Untuk performa, cache sudah ada di session_state
        cache = st.session_state.get(ui.DEC_CACHE, {})
        if rec.id in cache:
            record_data = cache[rec.id]
            if record_data.get("diagnosis"):
                diag = record_data["diagnosis"]
                diagnosis_counts[diag] = diagnosis_counts.get(diag, 0) + 1
            if record_data.get("icd10"):
                icd_codes.extend(record_data["icd10"])
    
    if diagnosis_counts:
        st.markdown("**Diagnosa Terbanyak:**")
        df_diag = pd.DataFrame([
            {"Diagnosa": k, "Jumlah": v} 
            for k, v in sorted(diagnosis_counts.items(), key=lambda x: x[1], reverse=True)
        ])
        st.dataframe(df_diag, hide_index=True, width="stretch")
    else:
        st.info("Dekripsi rekam medis untuk melihat ringkasan diagnosa.")
    
    if icd_codes:
        st.markdown("**Kode ICD-10:**")
        st.code(", ".join(set(icd_codes)))


def _render_daily_tracking(user) -> None:
    """Tampilkan tracking kesehatan harian"""
    st.subheader("Tracking Harian")
    
    tracking_data = db.get_health_tracking(user.address, days=30)
    
    if not tracking_data:
        st.info("Belum ada data tracking. Gunakan tab 'Input Tracking' untuk mulai.")
        return
    
    # Tabel data
    rows = []
    for t in tracking_data:
        rows.append({
            "Tanggal": t.tracked_date.strftime("%d %b %Y"),
            "TD Sistolik": t.systolic,
            "TD Diastolik": t.diastolic,
            "Nadi": t.heart_rate,
            "Suhu (°C)": t.temperature,
            "Gula Darah": t.blood_sugar,
            "Gejala": t.symptoms
        })
    
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def _render_health_trends(user) -> None:
    """Grafik tren kesehatan"""
    st.subheader("Tren Kesehatan (30 Hari Terakhir)")
    
    tracking_data = db.get_health_tracking(user.address, days=30)
    
    if not tracking_data:
        st.info("Data tracking minimal 7 hari untuk melihat tren.")
        return
    
    # Chart tekanan darah
    dates = [t.tracked_date for t in tracking_data]
    systolic = [t.systolic for t in tracking_data if t.systolic]
    diastolic = [t.diastolic for t in tracking_data if t.diastolic]
    
    if systolic and diastolic:
        st.markdown("**Tekanan Darah**")
        df_bp = pd.DataFrame({
            "Tanggal": dates[:len(systolic)],
            "Sistolik": systolic,
            "Diastolik": diastolic
        })
        st.line_chart(df_bp.set_index("Tanggal"))
    
    # Chart denyut jantung
    heart_rate = [t.heart_rate for t in tracking_data if t.heart_rate]
    if heart_rate:
        st.markdown("**Denyut Jantung**")
        df_hr = pd.DataFrame({
            "Tanggal": dates[:len(heart_rate)],
            "Nadi": heart_rate
        })
        st.line_chart(df_hr.set_index("Tanggal"))
    
    # Chart gula darah
    blood_sugar = [t.blood_sugar for t in tracking_data if t.blood_sugar]
    if blood_sugar:
        st.markdown("**Gula Darah**")
        df_bs = pd.DataFrame({
            "Tanggal": dates[:len(blood_sugar)],
            "Gula Darah": blood_sugar
        })
        st.line_chart(df_bs.set_index("Tanggal"))


def _render_tracking_input(user) -> None:
    """Form input tracking kesehatan"""
    st.subheader("Catat Kesehatan Hari Ini")
    
    with st.form("tracking_form"):
        c1, c2 = st.columns(2)
        systolic = c1.number_input("Tekanan Darah Sistolik", min_value=0, max_value=300, value=120)
        diastolic = c2.number_input("Tekanan Darah Diastolik", min_value=0, max_value=200, value=80)
        
        c3, c4, c5 = st.columns(3)
        heart_rate = c3.number_input("Denyut Jantung (/menit)", min_value=0, max_value=300, value=80)
        temperature = c4.number_input("Suhu Tubuh (°C)", min_value=30.0, max_value=45.0, value=36.5)
        blood_sugar = c5.number_input("Gula Darah (mg/dL)", min_value=0.0, max_value=500.0, value=100.0)
        
        symptoms = st.text_area("Gejala yang Dirasakan (satu per baris)")
        notes = st.text_area("Catatan Tambahan")
        
        submitted = st.form_submit_button("Simpan", type="primary")
        
        if submitted:
            symptoms_json = json.dumps([x.strip() for x in symptoms.split("\n") if x.strip()])
            db.add_health_tracking(
                patient_address=user.address,
                systolic=systolic if systolic else None,
                diastolic=diastolic if diastolic else None,
                heart_rate=heart_rate if heart_rate else None,
                temperature=temperature if temperature else None,
                blood_sugar=blood_sugar if blood_sugar else None,
                symptoms=symptoms_json,
                notes=notes or None
            )
            st.success("Data kesehatan berhasil disimpan!")
            st.rerun()


# =============================================================================
# JANJI TEMU DENGAN DOKTER
# =============================================================================

def appointments(user) -> None:
    """Kelola janji temu dengan dokter"""
    st.header("📅 Janji Temu dengan Dokter")
    
    tabs = st.tabs(["Jadwal Mendatang", "Buat Janji", "Riwayat"])
    
    with tabs[0]:
        _render_upcoming_appointments(user)
    
    with tabs[1]:
        _render_new_appointment(user)
    
    with tabs[2]:
        _render_appointment_history(user)


def _render_upcoming_appointments(user) -> None:
    """Tampilkan janji temu mendatang"""
    st.subheader("Jadwal Mendatang")
    
    upcoming = db.get_appointments(user.address, status="scheduled", upcoming=True)
    
    if not upcoming:
        st.info("Tidak ada janji temu mendatang.")
        return
    
    for apt in upcoming:
        doctor = db.get_user_by_address(apt.doctor_address)
        doctor_name = doctor.name if doctor else "Dokter"
        
        with st.container():
            st.markdown(f"### 🩺 Dr. {doctor_name}")
            st.markdown(f"**Waktu:** {apt.appointment_date.strftime('%d %B %Y, %H:%M')}")
            st.markdown(f"**Keperluan:** {apt.purpose}")
            
            c1, c2 = st.columns(2)
            if c1.button("✅ Selesai", key=f"done_{apt.id}"):
                db.update_appointment_status(apt.id, "completed")
                st.success("Janji ditandai selesai.")
                st.rerun()
            
            if c2.button("❌ Batalkan", key=f"cancel_{apt.id}"):
                db.update_appointment_status(apt.id, "cancelled")
                st.info("Janji dibatalkan.")
                st.rerun()
            
            st.markdown("---")


def _render_new_appointment(user) -> None:
    """Form buat janji baru"""
    st.subheader("Buat Janji Baru")
    
    # Pilih dokter yang sudah diberi akses
    granted_doctors = db.list_granted_doctors(user.address)
    
    if not granted_doctors:
        st.warning("Anda belum memberikan akses ke dokter manapun. Berikan akses di Dashboard terlebih dahulu.")
        return
    
    doctor_options = {f"Dr. {d.name}": d.address for d in granted_doctors}
    
    with st.form("appointment_form"):
        doctor_label = st.selectbox("Pilih Dokter", list(doctor_options.keys()))
        doctor_address = doctor_options[doctor_label]
        
        apt_date = st.date_input("Tanggal Janji", min_value=date.today())
        apt_time = st.time_input("Waktu Janji")
        
        purpose = st.text_area("Keperluan Konsultasi")
        
        submitted = st.form_submit_button("Buat Janji", type="primary")
        
        if submitted:
            apt_datetime = datetime.combine(apt_date, apt_time)
            db.create_appointment(
                patient_address=user.address,
                doctor_address=doctor_address,
                appointment_date=apt_datetime,
                purpose=purpose
            )
            st.success("Janji berhasil dibuat!")
            st.rerun()


def _render_appointment_history(user) -> None:
    """Riwayat janji temu"""
    st.subheader("Riwayat Janji Temu")
    
    history = db.get_appointments(user.address, exclude_status="scheduled")
    
    if not history:
        st.info("Belum ada riwayat janji temu.")
        return
    
    rows = []
    for apt in history:
        doctor = db.get_user_by_address(apt.doctor_address)
        doctor_name = doctor.name if doctor else "Dokter"
        
        status_label = {
            "completed": "✅ Selesai",
            "cancelled": "❌ Dibatalkan",
            "no-show": "⚠️ Tidak Hadir"
        }.get(apt.status, apt.status)
        
        rows.append({
            "Tanggal": apt.appointment_date.strftime("%d %b %Y"),
            "Dokter": f"Dr. {doctor_name}",
            "Keperluan": apt.purpose,
            "Status": status_label
        })
    
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


# =============================================================================
# REMINDER OBAT
# =============================================================================

def medication_reminders(user) -> None:
    """Kelola reminder minum obat"""
    st.header("⏰ Reminder Minum Obat")
    
    tabs = st.tabs(["Reminder Aktif", "Tambah Reminder", "Riwayat"])
    
    with tabs[0]:
        _render_active_reminders(user)
    
    with tabs[1]:
        _render_add_reminder(user)
    
    with tabs[2]:
        _render_reminder_history(user)


def _render_active_reminders(user) -> None:
    """Tampilkan reminder aktif"""
    st.subheader("Reminder Aktif")
    
    reminders = db.get_medication_reminders(user.address, active_only=True)
    
    if not reminders:
        st.info("Tidak ada reminder aktif.")
        return
    
    for rem in reminders:
        with st.container():
            times = json.loads(rem.time_of_day) if rem.time_of_day else []
            times_str = ", ".join(times)
            
            st.markdown(f"### 💊 {rem.medication_name}")
            st.markdown(f"**Dosis:** {rem.dosage}")
            st.markdown(f"**Frekuensi:** {rem.frequency}")
            st.markdown(f"**Waktu:** {times_str}")
            st.markdown(f"**Periode:** {rem.start_date.strftime('%d %b %Y')} - {rem.end_date.strftime('%d %b %Y') if rem.end_date else 'Tidak ditentukan'}")
            
            if st.button(f"❌ Nonaktifkan", key=f"deactivate_{rem.id}"):
                db.deactivate_reminder(rem.id)
                st.success("Reminder dinonaktifkan.")
                st.rerun()
            
            st.markdown("---")


def _render_add_reminder(user) -> None:
    """Form tambah reminder baru"""
    st.subheader("Tambah Reminder Baru")
    
    # Ambil resep aktif untuk pilih obat
    active_rx = db.get_patient_prescriptions(user.address, status=["pending", "approved", "dispensed"])
    
    with st.form("reminder_form"):
        med_name = st.text_input("Nama Obat")
        dosage = st.text_input("Dosis")
        
        frequency = st.selectbox("Frekuensi", ["1x sehari", "2x sehari", "3x sehari", "Setiap 8 jam", "Mingguan"])
        
        # Waktu berdasarkan frekuensi
        st.markdown("**Waktu Minum:**")
        c1, c2, c3 = st.columns(3)
        
        time1 = c1.time_input("Pagi", value=datetime.strptime("08:00", "%H:%M").time())
        time2 = c2.time_input("Siang", value=datetime.strptime("14:00", "%H:%M").time())
        time3 = c3.time_input("Malam", value=datetime.strptime("20:00", "%H:%M").time())
        
        # Pilih waktu yang relevan
        if frequency == "1x sehari":
            times = [time1.strftime("%H:%M")]
        elif frequency == "2x sehari":
            times = [time1.strftime("%H:%M"), time3.strftime("%H:%M")]
        elif frequency in ["3x sehari", "Setiap 8 jam"]:
            times = [time1.strftime("%H:%M"), time2.strftime("%H:%M"), time3.strftime("%H:%M")]
        else:
            times = [time1.strftime("%H:%M")]
        
        c4, c5 = st.columns(2)
        start_date = c4.date_input("Mulai", value=date.today())
        end_date = c5.date_input("Selesai (opsional)", value=None)
        
        submitted = st.form_submit_button("Simpan Reminder", type="primary")
        
        if submitted:
            db.create_medication_reminder(
                patient_address=user.address,
                prescription_id=active_rx[0].id if active_rx else None,
                medication_name=med_name,
                dosage=dosage,
                frequency=frequency,
                time_of_day=json.dumps(times),
                start_date=datetime.combine(start_date, datetime.min.time()),
                end_date=datetime.combine(end_date, datetime.min.time()) if end_date else None
            )
            st.success("Reminder berhasil dibuat!")
            st.rerun()


def _render_reminder_history(user) -> None:
    """Riwayat reminder"""
    st.subheader("Riwayat Reminder")
    
    reminders = db.get_medication_reminders(user.address, active_only=False)
    
    if not reminders:
        st.info("Belum ada riwayat reminder.")
        return
    
    rows = []
    for rem in reminders:
        status = "🟢 Aktif" if rem.active else "⚫ Nonaktif"
        rows.append({
            "Obat": rem.medication_name,
            "Dosis": rem.dosage,
            "Frekuensi": rem.frequency,
            "Mulai": rem.start_date.strftime("%d %b %Y"),
            "Status": status
        })
    
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
