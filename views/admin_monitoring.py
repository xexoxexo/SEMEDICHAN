"""Panel admin: monitoring ekstraksi log, akses rekam medis, verifikasi signature."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from utils import db_helper as db
from views import ui


def extraction_log(user) -> None:
    """Monitor siapa yang ekstrak rekam medis, kapan, dan status verifikasi signature."""
    ui.log_view_once(user, "admin_lihat_ekstraksi_log")
    st.header("Log Ekstraksi Rekam Medis")
    ui.note("Tampilkan setiap akses/ekstraksi rekam medis: siapa, kapan, status verifikasi tanda tangan diagnosis.")
    
    # Ambil semua log ekstraksi
    logs = db.list_logs(limit=1000)
    extraction_logs = [
        l for l in logs 
        if l.action in ("dekripsi", "ekstrak_phi", "ekstrak_diagnosis", "verifikasi_signature_diagnosis")
    ]
    
    if not extraction_logs:
        st.info("Belum ada log ekstraksi.")
        return
    
    # Bangun tabel dengan info kaya
    rows = []
    for log in extraction_logs:
        actor_user = db.get_user(log.actor)
        actor_name = actor_user.name if actor_user else log.actor[:8]
        
        # Ambil info rekam medis
        rec = db.get_record(log.target) if log.target else None
        rec_title = rec.title if rec else "—"
        rec_patient = rec.patient_address if rec else "—"
        
        # Label aksi
        action_labels = {
            "dekripsi": "Ekstrak & Dekripsi (Utama)",
            "ekstrak_phi": "Ekstrak PHI",
            "ekstrak_diagnosis": "Ekstrak Diagnosis",
            "verifikasi_signature_diagnosis": "Verifikasi Signature ✓"
        }
        
        rows.append({
            "Waktu (UTC)": log.ts,
            "Aktor": actor_name,
            "Role": actor_user.role if actor_user else "—",
            "Aksi": action_labels.get(log.action, log.action),
            "Rekam Medis": rec_title[:30],
            "Pasien": rec_patient[:8] if rec_patient != "—" else "—",
            "Detail": log.detail or "—",
        })
    
    # Tampilkan tabel interaktif
    df = pd.DataFrame(rows)
    st.dataframe(df, hide_index=True, width="stretch")
    
    # Filter dan analisis
    st.subheader("Analisis")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total ekstraksi", len(extraction_logs))
    col2.metric("Aktor unik", len({l.actor for l in extraction_logs}))
    col3.metric("Rekam unik", len({l.target for l in extraction_logs if l.target}))
    
    # Filter berdasarkan aktor
    actors = sorted({l.actor for l in extraction_logs})
    selected_actor = st.selectbox("Filter aktor", ["(semua)"] + actors, key="ext_actor_filter",
                                   format_func=lambda a: a if a == "(semua)" else (db.get_user(a).name if db.get_user(a) else a[:8]))
    if selected_actor != "(semua)":
        filtered = [l for l in extraction_logs if l.actor == selected_actor]
        st.write(f"**{len(filtered)} log untuk {db.get_user(selected_actor).name if db.get_user(selected_actor) else selected_actor}**")
        df_filtered = pd.DataFrame([
            {
                "Waktu": l.ts, "Aksi": action_labels.get(l.action, l.action),
                "Rekam": (db.get_record(l.target).title if db.get_record(l.target) else "—")[:20] if l.target else "—",
                "Detail": l.detail or "—"
            }
            for l in filtered
        ])
        st.dataframe(df_filtered, hide_index=True, width="stretch")


def access_control(user) -> None:
    """Monitor akses (sharing) ke rekam medis: siapa punya akses ke rekam mana."""
    ui.log_view_once(user, "admin_lihat_sharing")
    st.header("Kontrol Akses Rekam Medis")
    ui.note("Tampilkan struktur sharing: pasien (pemilik), dokter pembuat, dan dokter yang dibagikan.")
    
    # Ambil semua rekam medis
    records = db.list_records()
    if not records:
        st.info("Belum ada rekam medis.")
        return
    
    st.subheader("Tabel Akses Rekam Medis")
    rows = []
    for rec in records:
        recipients = db.list_recipients(rec.id)
        owner = next((r for r in recipients if r.role == "patient"), None)
        author = next((r for r in recipients if r.role == "author"), None)
        shared = [r for r in recipients if r.role == "shared"]
        
        owner_user = db.get_user(owner.address) if owner else None
        author_user = db.get_user(author.address) if author else None
        
        rows.append({
            "ID Rekam": rec.id[:8],
            "Judul": rec.title,
            "Pemilik (Pasien)": owner_user.name if owner_user else "—",
            "Dokter Pembuat": author_user.name if author_user else "—",
            "Dibagikan ke": ", ".join([db.get_user(s.address).name if db.get_user(s.address) else s.address[:8] for s in shared]) or "(tidak ada)",
            "Jumlah akses": len(recipients),
            "PHI": "ya" if rec.has_phi else "tidak",
            "Diagnosis": "ya" if rec.has_diagnosis else "tidak",
            "Tanda Tangan": "ya" if rec.has_diagnosis and hasattr(rec, 'has_signature') and rec.has_signature else "tidak",
        })
    
    df = pd.DataFrame(rows)
    st.dataframe(df, hide_index=True, width="stretch")
    
    # Filter: lihat siapa yang punya akses terluas
    st.subheader("Dokter dengan akses terbanyak")
    access_counts = {}
    for rec in records:
        for recipient in db.list_recipients(rec.id):
            if recipient.role in ("author", "shared"):
                access_counts[recipient.address] = access_counts.get(recipient.address, 0) + 1
    
    if access_counts:
        top_docs = sorted(access_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_rows = [
            {"Dokter": db.get_user(addr).name if db.get_user(addr) else addr[:8],
             "Rekam medis dapat diakses": count}
            for addr, count in top_docs
        ]
        st.dataframe(pd.DataFrame(top_rows), hide_index=True)


def signature_audit(user) -> None:
    """Monitor verifikasi tanda tangan diagnosis: mana yang valid, mana yang invalid."""
    ui.log_view_once(user, "admin_lihat_signature_audit")
    st.header("Audit Tanda Tangan Diagnosis (Ed25519)")
    ui.note("Rekam diagnosis mana yang memiliki tanda tangan valid, dan siapa yang menandatangani.")
    
    # Ambil log verifikasi signature
    all_logs = db.list_logs(limit=5000)
    sig_logs = [l for l in all_logs if "signature" in l.action.lower() or l.action == "ekstrak_diagnosis"]
    
    if not sig_logs:
        st.info("Belum ada log tanda tangan diagnosis.")
        return
    
    # Build status per rekam
    sig_status = {}
    for log in sig_logs:
        rec_id = log.target
        if rec_id not in sig_status:
            sig_status[rec_id] = {"verified": 0, "failed": 0, "extracted": 0}
        if "verifikasi_signature" in log.action:
            sig_status[rec_id]["verified"] += 1
        elif "gagal" in log.action.lower():
            sig_status[rec_id]["failed"] += 1
        elif "ekstrak_diagnosis" in log.action:
            sig_status[rec_id]["extracted"] += 1
    
    rows = []
    for rec_id, status in sig_status.items():
        rec = db.get_record(rec_id)
        if not rec:
            continue
        
        doc_user = db.get_user(rec.doctor_address)
        rows.append({
            "ID Rekam": rec_id[:8],
            "Judul": rec.title,
            "Dokter": doc_user.name if doc_user else rec.doctor_address[:8],
            "Ekstraksi diagnosis": status["extracted"],
            "Verifikasi ✓": status["verified"],
            "Verifikasi ✗": status["failed"],
            "Status": "Valid ✓" if status["verified"] > 0 else ("Gagal ✗" if status["failed"] > 0 else "Belum ekstrak"),
        })
    
    df = pd.DataFrame(rows)
    st.dataframe(df, hide_index=True, width="stretch")
    
    # Ringkas
    st.subheader("Ringkasan")
    c1, c2, c3 = st.columns(3)
    total_sig = len(sig_status)
    valid = sum(1 for s in sig_status.values() if s["verified"] > 0)
    invalid = sum(1 for s in sig_status.values() if s["failed"] > 0)
    c1.metric("Diagnosis dgn tanda tangan", total_sig)
    c2.metric("Terverifikasi ✓", valid)
    c3.metric("Tidak valid ✗", invalid)
