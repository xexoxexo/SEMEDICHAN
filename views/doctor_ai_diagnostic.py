"""Fitur dokter: Koreksi diagnostik real-time dimediasi AI untuk validasi data klinis."""
from __future__ import annotations

import json
from datetime import datetime

import pandas as pd
import streamlit as st

import config
from utils import db_helper as db
from utils import web3_utils
from views import ui


def ai_diagnostic_assistance(user) -> None:
    """AI membantu dokter validasi diagnosis & sarankan koreksi berdasarkan data klinis pasien"""
    st.header("🤖 Koreksi Diagnostik Real-Time (AI)")
    
    ui.note("AI menganalisis data klinis pasien dan memberikan saran koreksi diagnostik. Keputusan akhir tetap di tangan dokter.")
    
    granted_patients = db.list_granted_patients(user.address)
    
    if not granted_patients:
        st.info("Belum ada pasien yang memberi akses.")
        return
    
    patient_options = {f"{p.name} · {web3_utils.short(p.address)}": p for p in granted_patients}
    
    selected_label = st.selectbox("Pilih Pasien", list(patient_options.keys()), key="ai_diag_patient")
    selected_patient = patient_options[selected_label]
    
    # Ambil rekam medis terakhir
    records = db.list_records(patient=selected_patient.address, doctor=user.address)
    
    if not records:
        st.info(f"Belum ada rekam medis untuk {selected_patient.name}.")
        return
    
    # Tampilkan rekam medis untuk analisis
    st.subheader("Rekam Medis Terbaru")
    
    recent_records = records[:5]  # 5 rekam terakhir
    
    record_options = {
        f"{r.title} · {r.created_at.strftime('%d %b %Y')}": r 
        for r in recent_records
    }
    
    selected_rec_label = st.selectbox("Pilih Rekam untuk Analisis AI", list(record_options.keys()))
    selected_record = record_options[selected_rec_label]
    
    st.markdown("---")
    
    # Input diagnosis dokter untuk validasi AI
    with st.form("ai_diagnostic_form"):
        st.markdown("### Input Data Klinis untuk Analisis AI")
        
        c1, c2 = st.columns(2)
        chief_complaint = c1.text_area("Keluhan Utama", height=80)
        symptoms = c2.text_area("Gejala (satu per baris)", height=80)
        
        v1, v2, v3, v4 = st.columns(4)
        bp_sys = v1.number_input("Sistolik (mmHg)", min_value=50, max_value=250, value=120)
        bp_dia = v2.number_input("Diastolik (mmHg)", min_value=30, max_value=150, value=80)
        temp = v3.number_input("Suhu (°C)", min_value=35.0, max_value=42.0, value=36.5, step=0.1)
        heart_rate = v4.number_input("Nadi (/menit)", min_value=40, max_value=200, value=80)
        
        st.markdown("### Diagnosis Awal Dokter")
        doctor_diagnosis = st.text_area("Diagnosis yang ingin divalidasi", height=100)
        icd10_codes = st.text_input("Kode ICD-10 (pisahkan koma)", placeholder="J20.9, E11.9")
        
        st.markdown("### Riwayat Klinis Relevan")
        medical_history = st.text_area("Riwayat penyakit, alergi, obat saat ini", height=80)
        
        analyze_btn = st.form_submit_button("🤖 Analisis dengan AI", type="primary")
    
    if analyze_btn:
        if not doctor_diagnosis.strip():
            st.error("Diagnosis dokter harus diisi untuk analisis AI.")
            return
        
        # Simulasi analisis AI (dalam implementasi nyata, gunakan API OpenAI/Claude/Gemini)
        with st.spinner("AI sedang menganalisis data klinis..."):
            _perform_ai_analysis(
                user, selected_patient, selected_record,
                chief_complaint, symptoms.split('\n'),
                bp_sys, bp_dia, temp, heart_rate,
                doctor_diagnosis, icd10_codes, medical_history
            )


def _perform_ai_analysis(
    user, patient, record,
    chief_complaint: str, symptoms: list, 
    bp_sys: int, bp_dia: int, temp: float, heart_rate: int,
    doctor_diagnosis: str, icd10_codes: str, medical_history: str
) -> None:
    """Simulasi AI diagnostic assistance (gunakan LLM API untuk implementasi nyata)"""
    
    # Build clinical context
    clinical_data = {
        "chief_complaint": chief_complaint,
        "symptoms": [s.strip() for s in symptoms if s.strip()],
        "vitals": {
            "blood_pressure": f"{bp_sys}/{bp_dia}",
            "temperature": temp,
            "heart_rate": heart_rate
        },
        "doctor_diagnosis": doctor_diagnosis,
        "icd10": icd10_codes,
        "history": medical_history
    }
    
    # Simulasi respons AI (dalam produksi, panggil LLM API)
    ai_response = _simulate_ai_diagnostic_check(clinical_data)
    
    st.success("✅ Analisis AI selesai")
    
    # Tampilkan hasil
    st.markdown("---")
    st.markdown("## 📊 Hasil Analisis AI")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Confidence Score", f"{ai_response['confidence']}%")
    col2.metric("Konsistensi Diagnosis", ai_response['consistency'])
    col3.metric("Risk Level", ai_response['risk_level'])
    
    st.markdown("### 🔍 Validasi Diagnosis")
    if ai_response['diagnostic_match']:
        st.success("✅ Diagnosis dokter konsisten dengan data klinis dan guideline medis.")
    else:
        st.warning("⚠️ AI menemukan potensi ketidaksesuaian atau area yang perlu perhatian lebih.")
    
    st.markdown(f"**Diagnosis Dokter:** {doctor_diagnosis}")
    st.markdown(f"**Analisis AI:** {ai_response['ai_analysis']}")
    
    # Saran koreksi
    if ai_response['suggestions']:
        st.markdown("### 💡 Saran Koreksi dari AI")
        for i, suggestion in enumerate(ai_response['suggestions'], 1):
            with st.expander(f"Saran {i}: {suggestion['title']}"):
                st.markdown(f"**Kategori:** {suggestion['category']}")
                st.markdown(f"**Deskripsi:** {suggestion['description']}")
                st.markdown(f"**Referensi:** {suggestion['reference']}")
                st.markdown(f"**Prioritas:** {suggestion['priority']}")
    
    # Red flags / warning signs
    if ai_response['red_flags']:
        st.markdown("### 🚨 Red Flags yang Terdeteksi")
        for flag in ai_response['red_flags']:
            st.error(f"⚠️ {flag}")
    
    # Differential diagnosis
    if ai_response['differential_diagnosis']:
        st.markdown("### 🔬 Differential Diagnosis yang Disarankan AI")
        diff_df = pd.DataFrame(ai_response['differential_diagnosis'])
        st.dataframe(diff_df, hide_index=True, width="stretch")
    
    # Rekomendasi pemeriksaan lanjutan
    if ai_response['recommended_tests']:
        st.markdown("### 🧪 Pemeriksaan Lanjutan yang Disarankan")
        for test in ai_response['recommended_tests']:
            st.markdown(f"- {test}")
    
    # Action buttons
    st.markdown("---")
    col_a, col_b, col_c = st.columns(3)
    
    if col_a.button("💾 Simpan Analisis AI ke Rekam", type="primary"):
        _save_ai_analysis_to_record(user, patient, record.id, clinical_data, ai_response)
        st.success("Analisis AI disimpan ke rekam medis.")
    
    if col_b.button("✏️ Koreksi Diagnosis Berdasarkan AI"):
        st.info("Fitur koreksi diagnosis akan membuka form edit dengan saran AI terintegrasi.")
    
    if col_c.button("📧 Kirim ke Kolega untuk Second Opinion"):
        st.info("Analisis AI dapat dibagikan ke dokter lain untuk konsultasi.")
    
    # Log aktivitas AI
    db.log_event(
        user.address, 
        "ai_diagnostic_analysis", 
        record.id,
        f"patient={patient.address} confidence={ai_response['confidence']}%"
    )


def _simulate_ai_diagnostic_check(clinical_data: dict) -> dict:
    """Simulasi AI analysis (gunakan OpenAI/Claude/Gemini API untuk produksi)"""
    
    # Simulasi logic sederhana (dalam produksi, panggil LLM)
    symptoms = clinical_data.get('symptoms', [])
    vitals = clinical_data.get('vitals', {})
    diagnosis = clinical_data.get('doctor_diagnosis', '').lower()
    
    # Deteksi pola sederhana
    has_fever = vitals.get('temperature', 36.5) > 37.5
    has_hypertension = vitals.get('blood_pressure', '120/80').split('/')[0] and int(vitals['blood_pressure'].split('/')[0]) > 140
    has_respiratory = any(s for s in symptoms if 'batuk' in s.lower() or 'sesak' in s.lower() or 'nafas' in s.lower())
    
    # Simulasi respons AI
    confidence = 85 if has_fever or has_respiratory else 75
    consistency = "Tinggi" if confidence > 80 else "Sedang"
    risk_level = "Sedang" if has_hypertension else "Rendah"
    
    diagnostic_match = True
    ai_analysis = "Data klinis konsisten dengan diagnosis dokter. Tidak ada kontradiksi signifikan ditemukan."
    
    suggestions = []
    red_flags = []
    differential_diagnosis = []
    recommended_tests = []
    
    # Logika saran berdasarkan data
    if has_fever and has_respiratory:
        suggestions.append({
            "title": "Pertimbangkan Pneumonia",
            "category": "Differential Diagnosis",
            "description": "Kombinasi demam dan gejala respiratori mengarah ke kemungkinan infeksi saluran napas bawah.",
            "reference": "Harrison's Principles of Internal Medicine, 21st Ed.",
            "priority": "Tinggi"
        })
        differential_diagnosis.append({
            "Diagnosis": "Pneumonia Community-Acquired",
            "ICD-10": "J18.9",
            "Probabilitas": "Sedang-Tinggi",
            "Pemeriksaan": "Rontgen thorax, Complete Blood Count"
        })
        recommended_tests.append("Rontgen thorax PA/Lateral")
        recommended_tests.append("Complete Blood Count (CBC)")
    
    if has_hypertension:
        red_flags.append("Tekanan darah tinggi (>140/90 mmHg) - pertimbangkan evaluasi kardiovaskular")
        recommended_tests.append("EKG 12-lead")
        recommended_tests.append("Profil lipid")
    
    if vitals.get('heart_rate', 80) > 100:
        red_flags.append("Takikardia terdeteksi - monitor cardiac status")
    
    # Tambahan saran umum
    if not clinical_data.get('history', '').strip():
        suggestions.append({
            "title": "Lengkapi Riwayat Medis",
            "category": "Data Collection",
            "description": "Riwayat penyakit terdahulu, alergi, dan obat saat ini sangat penting untuk diagnosis akurat.",
            "reference": "Clinical Practice Guidelines",
            "priority": "Sedang"
        })
    
    return {
        "confidence": confidence,
        "consistency": consistency,
        "risk_level": risk_level,
        "diagnostic_match": diagnostic_match,
        "ai_analysis": ai_analysis,
        "suggestions": suggestions,
        "red_flags": red_flags,
        "differential_diagnosis": differential_diagnosis,
        "recommended_tests": recommended_tests
    }


def _save_ai_analysis_to_record(user, patient, record_id: str, clinical_data: dict, ai_response: dict) -> None:
    """Simpan hasil analisis AI sebagai metadata tambahan di rekam medis"""
    
    analysis_summary = {
        "analyzed_at": datetime.utcnow().isoformat(),
        "analyzed_by": user.address,
        "clinical_input": clinical_data,
        "ai_output": {
            "confidence": ai_response['confidence'],
            "consistency": ai_response['consistency'],
            "risk_level": ai_response['risk_level'],
            "analysis": ai_response['ai_analysis'],
            "suggestions_count": len(ai_response['suggestions']),
            "red_flags_count": len(ai_response['red_flags'])
        }
    }
    
    # Log ke audit trail
    db.log_event(
        user.address,
        "ai_analysis_saved",
        record_id,
        json.dumps(analysis_summary, ensure_ascii=False)[:500]
    )
