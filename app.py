"""StegoMed-Web3: RME dengan stenografi citra medis, enkripsi hybrid, dan verifikasi dompet Web3.

Jalankan:  streamlit run app.py
"""
from __future__ import annotations

import logging
import time

import streamlit as st

st.set_page_config(page_title="StegoMed-Web3", page_icon="🏥", layout="wide")

import config
from utils import db_helper as db, auth_helpers as ah
from utils import web3_utils
from utils.principal import build_principal
from views import (admin, admin_mgmt, admin_monitoring, consent, dashboard, doctor, doctor_appointments, 
                   doctor_ai_diagnostic, lab, login, patient_rights, records, security, security_rbac, ui,
                   verify, wallet, patient, admin_custom_pharmacy)


@st.cache_resource
def _init() -> bool:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    db.init_db()
    return True


def _patient_records(user):
    st.header("Rekam medis saya")
    records.render(user, "patient")


MENUS = {
    "doctor": {
        "Dashboard": (dashboard.render, False),
        "Pasien saya": (doctor.patients, False),
        "Rekam medis baru": (doctor.new_record, False),
        "Riwayat rekam medis": (doctor.history, False),
        "Janji Temu Pasien": (doctor_appointments.appointments, False),
        "Profil Pasien": (doctor_appointments.patient_profiles, False),
        "Tracking Kesehatan": (doctor_appointments.patient_health_tracking, False),
        "Metadata Diagnosis": (doctor_appointments.diagnosis_metadata, False),
        "🤖 AI Diagnostic Assist": (doctor_ai_diagnostic.ai_diagnostic_assistance, False),
        "Keamanan akun": (security.render, False),
    },
    "patient": {
        "Beranda": (dashboard.render, False),
        "Profil Saya": (patient.profile, False),
        "Rekam Medis Saya": (_patient_records, False),
        "Resep Obat": (patient.prescriptions, False),
        "Analisis Kesehatan": (patient.health_analysis, False),
        "Janji Temu": (patient.appointments, False),
        "Reminder Obat": (patient.medication_reminders, False),
        "Ekspor Data": (patient_rights.export_data, False),
        "Permintaan hak data": (patient_rights.subject_requests, False),
        "Keamanan akun": (security.render, False),
    },
    "admin_security": {
        "Dashboard": (dashboard.render, False),
        "🔍 Monitoring Log": (admin_monitoring.extraction_log, True),
        "🔒 Kontrol Akses": (admin_monitoring.access_control, True),
        "✍️ Audit Signature": (admin_monitoring.signature_audit, True),
        "Lab stenografi": (lab.render, True),
        "Dompet dan kunci stego": (wallet.render_page, True),
        "Keamanan akun": (security.render, False),
    },
    "admin_custom": {
        "Dashboard": (dashboard.render, False),
        "💊 Manajemen Resep": (admin_custom_pharmacy.prescription_management, False),
        "📊 Tracking Obat Pasien": (admin_custom_pharmacy.patient_medication_tracking, False),
        "👥 Manajemen User": (admin_mgmt.user_management, False),
        "📊 Statistik Penggunaan": (admin_mgmt.usage_statistics, False),
        "⚙️ Pengaturan Sistem": (admin_mgmt.system_settings, False),
        "Keamanan akun": (security.render, False),
    },
    "admin": {
        "Dashboard": (dashboard.render, False),
        "Verifikasi dokter": (admin.approvals, False),
        "Metadata rekam medis": (admin.all_records, False),
        "Permintaan hak data": (admin.subject_requests, False),
        "Audit trail": (admin.audit, False),
        "Keamanan akun": (security.render, False),
    },
}


def _menu_for(role: str) -> dict:
    menu = MENUS.get(role, {})
    # Admin Security: selalu tampilkan lab (perlu wallet)
    if role == "admin_security":
        return menu
    # Role lain: hapus lab jika disabled
    if not config.ENABLE_LAB:
        return {k: v for k, v in menu.items() if v[0] is not lab.render}
    return menu


def _logout(user) -> None:
    db.log_event(user.address, "logout")
    st.session_state.clear()
    st.rerun()


def main() -> None:
    problems = config.production_problems()
    if problems:
        st.error("Konfigurasi produksi tidak aman:")
        for item in problems:
            st.write(f"- {item}")
        st.stop()
    
    try:
        _init()
    except RuntimeError as exc:
        st.error(str(exc))
        st.stop()
    
    ui.inject_css()
    
    if not st.session_state.get("account_id"):
        login.render()
        return
    
    ah.check_session_timeout()
    ah.enforce_mfa_if_required()
    
    account = db.get_account(st.session_state["account_id"])
    if not account:
        st.session_state.clear()
        st.rerun()
    
    user = build_principal(account)
    ah.check_doctor_approved()
    
    state = wallet.wallet_state(user)
    
    with st.sidebar:
        st.markdown(f"**{user.name}**")
        st.markdown(f'<span class="smw-role">{ui.ROLE_LABEL[user.role]}</span>', unsafe_allow_html=True)
        st.caption(user.email)
        
        # Tampilkan info wallet HANYA untuk Admin Keamanan
        if user.role == "admin_security":
            st.caption(f"Dompet: {web3_utils.short(user.address)}" if user.wallet_linked else "⚠️ Dompet belum tertaut")
            if user.wallet_linked:
                st.caption(f"Steganografi: {state}")
        
        menu_items = _menu_for(user.role)
        choice = st.radio("Menu", list(menu_items), label_visibility="collapsed") if menu_items else None
        
        if not config.IS_PROD:
            st.caption("Mode pengembangan")
        if st.button("Keluar"):
            _logout(user)
    
    if not menu_items:
        st.error("Peran Anda tidak memiliki menu yang tersedia.")
        return
    
    page, needs_wallet = menu_items[choice]
    
    # Cek wallet requirement per role & fitur
    if needs_wallet:
        policy = security_rbac.get_wallet_requirement(user.role)
        
        # Jika role ini mandatory wallet tapi belum terhubung
        if policy["require_wallet"] and not user.wallet_linked:
            st.warning("⚠️ Peran Anda memerlukan dompet Web3 yang terhubung untuk mengakses fitur ini.")
            wallet.gate(user)
            return
        
        # Jika wallet terhubung tapi perlu unlock
        if user.wallet_linked and state != "open":
            wallet.gate(user)
            return
    
    # Render page
    ah.log_access(f"page_access", choice or "")
    page(user)


main()
