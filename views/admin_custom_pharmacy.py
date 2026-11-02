"""Admin custom: manajemen resep obat, pemenuhan obat, tracking stok."""
from __future__ import annotations

import json
from datetime import datetime

import pandas as pd
import streamlit as st

from utils import db_helper as db
from utils import web3_utils
from views import ui


def prescription_management(user) -> None:
    """Kelola resep obat dari dokter untuk disiapkan dan diberikan ke pasien."""
    st.header("💊 Manajemen Resep Obat")
    
    tabs = st.tabs(["Resep Menunggu", "Resep Diproses", "Riwayat", "Statistik"])
    
    with tabs[0]:
        _render_pending_prescriptions(user)
    
    with tabs[1]:
        _render_processing_prescriptions(user)
    
    with tabs[2]:
        _render_prescription_history(user)
    
    with tabs[3]:
        _render_prescription_stats(user)


def _render_pending_prescriptions(user) -> None:
    """Tampilkan resep yang menunggu persetujuan/persiapan."""
    st.subheader("Resep Menunggu Persetujuan")
    
    pending = db.session_scope().__enter__()
    try:
        from models import PrescriptionOrder
        from sqlalchemy import select
        prescriptions = list(pending.scalars(
            select(PrescriptionOrder).where(PrescriptionOrder.status == "pending").order_by(PrescriptionOrder.created_at.asc())
        ))
    finally:
        pending.__exit__(None, None, None)
    
    if not prescriptions:
        st.info("Tidak ada resep menunggu persetujuan.")
        return
    
    for rx in prescriptions:
        _render_prescription_approval_card(rx, user)


def _render_prescription_approval_card(rx, user) -> None:
    """Kartu untuk approve/reject resep."""
    doctor = db.get_user_by_address(rx.doctor_address)
    patient = db.get_user_by_address(rx.patient_address)
    
    doctor_name = doctor.name if doctor else "Dokter"
    patient_name = patient.name if patient else web3_utils.short(rx.patient_address)
    
    with st.container():
        st.markdown(f"**Resep ID:** {rx.id}")
        st.markdown(f"**Dari:** Dr. {doctor_name}")
        st.markdown(f"**Untuk:** {patient_name}")
        st.markdown(f"**Tanggal:** {rx.created_at.strftime('%d %b %Y %H:%M')}")
        
        # Tampilkan daftar obat
        meds = json.loads(rx.medications) if rx.medications else []
        if meds:
            st.markdown("**Daftar Obat:**")
            df = pd.DataFrame(meds)
            st.dataframe(df, hide_index=True, width="stretch")
        
        if rx.instructions:
            st.markdown(f"**Aturan Pakai:** {rx.instructions}")
        
        # Form persetujuan
        with st.form(f"approve_form_{rx.id}"):
            approval = st.radio("Keputusan", ["Setujui", "Tolak"], horizontal=True, key=f"decision_{rx.id}")
            notes = st.text_area("Catatan (opsional)", key=f"notes_{rx.id}")
            submitted = st.form_submit_button("Kirim", type="primary")
            
            if submitted:
                if approval == "Setujui":
                    db.update_prescription_status(rx.id, "approved", user.address, notes or None)
                    st.success("Resep disetujui!")
                else:
                    db.update_prescription_status(rx.id, "cancelled", user.address, notes or None)
                    st.warning("Resep ditolak.")
                st.rerun()
        
        st.markdown("---")


def _render_processing_prescriptions(user) -> None:
    """Tampilkan resep yang sedang diproses/disiapkan."""
    st.subheader("Resep Diproses")
    
    processing = db.session_scope().__enter__()
    try:
        from models import PrescriptionOrder
        from sqlalchemy import select
        prescriptions = list(processing.scalars(
            select(PrescriptionOrder).where(PrescriptionOrder.status.in_(["approved", "dispensed"])).order_by(PrescriptionOrder.updated_at.asc())
        ))
    finally:
        processing.__exit__(None, None, None)
    
    if not prescriptions:
        st.info("Tidak ada resep dalam proses.")
        return
    
    for rx in prescriptions:
        _render_prescription_fulfillment_card(rx, user)


def _render_prescription_fulfillment_card(rx, user) -> None:
    """Kartu untuk memproses/menyelesaikan resep."""
    doctor = db.get_user_by_address(rx.doctor_address)
    patient = db.get_user_by_address(rx.patient_address)
    
    doctor_name = doctor.name if doctor else "Dokter"
    patient_name = patient.name if patient else web3_utils.short(rx.patient_address)
    
    status_label = {"approved": "🟡 Disetujui", "dispensed": "💊 Disiapkan"}[rx.status]
    
    with st.container():
        st.markdown(f"**Resep ID:** {rx.id} · {status_label}")
        st.markdown(f"**Dari:** Dr. {doctor_name}")
        st.markdown(f"**Untuk:** {patient_name}")
        
        meds = json.loads(rx.medications) if rx.medications else []
        if meds:
            st.markdown("**Daftar Obat:**")
            df = pd.DataFrame(meds)
            st.dataframe(df, hide_index=True, width="stretch")
        
        c1, c2 = st.columns(2)
        
        if rx.status == "approved":
            if c1.button("📝 Tandai Disiapkan", key=f"mark_dispensed_{rx.id}"):
                db.update_prescription_status(rx.id, "dispensed", user.address)
                st.success("Resep ditandai sudah disiapkan.")
                st.rerun()
        
        if rx.status == "dispensed":
            if c1.button("✅ Tandai Selesai", key=f"complete_{rx.id}"):
                db.update_prescription_status(rx.id, "completed", user.address)
                st.success("Resep ditandai selesai.")
                st.rerun()
        
        if c2.button("❌ Batalkan", key=f"cancel_{rx.id}"):
            db.update_prescription_status(rx.id, "cancelled", user.address, "Dibatalkan oleh admin")
            st.warning("Resep dibatalkan.")
            st.rerun()
        
        if rx.notes:
            st.info(f"Catatan: {rx.notes}")
        
        st.markdown("---")


def _render_prescription_history(user) -> None:
    """Riwayat resep yang sudah selesai atau dibatalkan."""
    st.subheader("Riwayat Resep")
    
    history = db.session_scope().__enter__()
    try:
        from models import PrescriptionOrder
        from sqlalchemy import select
        prescriptions = list(history.scalars(
            select(PrescriptionOrder).where(PrescriptionOrder.status.in_(["completed", "cancelled"])).order_by(PrescriptionOrder.updated_at.desc())
        ))
    finally:
        history.__exit__(None, None, None)
    
    if not prescriptions:
        st.info("Belum ada riwayat resep.")
        return
    
    rows = []
    for rx in prescriptions:
        doctor = db.get_user_by_address(rx.doctor_address)
        patient = db.get_user_by_address(rx.patient_address)
        
        doctor_name = doctor.name if doctor else "Dokter"
        patient_name = patient.name if patient else web3_utils.short(rx.patient_address)
        
        status_label = {"completed": "✅ Selesai", "cancelled": "❌ Dibatalkan"}[rx.status]
        
        rows.append({
            "ID": rx.id,
            "Tanggal": rx.created_at.strftime("%d %b %Y"),
            "Dokter": f"Dr. {doctor_name}",
            "Pasien": patient_name,
            "Status": status_label,
            "Obat": len(json.loads(rx.medications)) if rx.medications else 0
        })
    
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def _render_prescription_stats(user) -> None:
    """Statistik resep obat."""
    st.subheader("Statistik Resep")
    
    stats_data = db.session_scope().__enter__()
    try:
        from models import PrescriptionOrder
        from sqlalchemy import select, func
        
        total = stats_data.scalar(select(func.count()).select_from(PrescriptionOrder)) or 0
        pending = stats_data.scalar(select(func.count()).select_from(PrescriptionOrder).where(PrescriptionOrder.status == "pending")) or 0
        approved = stats_data.scalar(select(func.count()).select_from(PrescriptionOrder).where(PrescriptionOrder.status == "approved")) or 0
        dispensed = stats_data.scalar(select(func.count()).select_from(PrescriptionOrder).where(PrescriptionOrder.status == "dispensed")) or 0
        completed = stats_data.scalar(select(func.count()).select_from(PrescriptionOrder).where(PrescriptionOrder.status == "completed")) or 0
        cancelled = stats_data.scalar(select(func.count()).select_from(PrescriptionOrder).where(PrescriptionOrder.status == "cancelled")) or 0
    finally:
        stats_data.__exit__(None, None, None)
    
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total", total)
    c2.metric("Menunggu", pending)
    c3.metric("Disetujui", approved)
    c4.metric("Disiapkan", dispensed)
    c5.metric("Selesai", completed)
    c6.metric("Dibatalkan", cancelled)


def patient_medication_tracking(user) -> None:
    """Tracking pasien minum obat berdasarkan reminder."""
    st.header("📊 Tracking Pasien Minum Obat")
    
    st.subheader("Ringkasan Kepatuhan Pasien")
    
    reminders = db.session_scope().__enter__()
    try:
        from models import MedicationReminder
        from sqlalchemy import select
        active_reminders = list(reminders.scalars(
            select(MedicationReminder).where(MedicationReminder.active.is_(True)).order_by(MedicationReminder.patient_address.asc())
        ))
    finally:
        reminders.__exit__(None, None, None)
    
    if not active_reminders:
        st.info("Tidak ada reminder aktif untuk ditinjau.")
        return
    
    rows = []
    for rem in active_reminders:
        patient = db.get_user_by_address(rem.patient_address)
        patient_name = patient.name if patient else web3_utils.short(rem.patient_address)
        
        # Hitung kepatuhan (jika ada data last_reminded)
        compliance = "Aktif" if rem.last_reminded else "Belum dimulai"
        
        rows.append({
            "Pasien": patient_name,
            "Obat": rem.medication_name,
            "Dosis": rem.dosage,
            "Frekuensi": rem.frequency,
            "Status": compliance,
            "Mulai": rem.start_date.strftime("%d %b %Y")
        })
    
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
