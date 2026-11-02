"""Panel admin kustom/default: manajemen user, statistik penggunaan, pengaturan sistem."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from utils import db_helper as db
from views import ui


def user_management(user) -> None:
    """Admin Kustom: Kelola user (approve/block/suspend), lihat status."""
    ui.log_view_once(user, "admin_mgmt_user_management")
    st.header("Manajemen User")
    ui.note("Tampilkan semua user, status, role, dan lakukan aksi (approve, block, suspend).")
    
    # Filter role
    role_filter = st.selectbox("Filter role", ["(semua)", "patient", "doctor", "admin_security", "admin_custom"], 
                               key="um_role_filter")
    
    # Ambil semua akun
    all_accts = db.list_accounts()
    if role_filter != "(semua)":
        accts = [a for a in all_accts if a.role == role_filter]
    else:
        accts = all_accts
    
    if not accts:
        st.info("Tidak ada user dengan filter ini.")
        return
    
    # Tabel overview
    st.subheader("Daftar User")
    rows = []
    for a in accts:
        status = "Ditolak" if a.rejection_reason else ("Menunggu" if not a.is_approved and a.role == "doctor" else "Aktif")
        rows.append({
            "ID": a.id,
            "Nama": a.full_name,
            "Email": a.email,
            "Role": ui.ROLE_LABEL.get(a.role, a.role),
            "Status": status,
            "Email Terverifikasi": "✓" if a.email_verified else "✗",
            "MFA": "✓" if a.mfa_enabled else "✗",
            "Terdaftar": a.created_at.strftime("%Y-%m-%d"),
        })
    
    df = pd.DataFrame(rows)
    st.dataframe(df, hide_index=True, width="stretch")
    
    # Aksi per user
    st.subheader("Aksi")
    selected_id = st.selectbox("Pilih user untuk aksi", [a.id for a in accts], 
                                format_func=lambda aid: f"#{aid} · {next((a.full_name for a in accts if a.id == aid), '—')}")
    sel_acct = next((a for a in accts if a.id == selected_id), None)
    if not sel_acct:
        return
    
    st.markdown(f"**{sel_acct.full_name}** ({sel_acct.email}) · {ui.ROLE_LABEL.get(sel_acct.role, sel_acct.role)}")
    
    col1, col2, col3 = st.columns(3)
    
    # Reset password
    if col1.button(f"Reset Password", key=f"reset_pw_{selected_id}"):
        otp_code = db.issue_otp(selected_id, "admin_reset_password")
        st.info(f"Kode OTP untuk reset password: `{otp_code}` (berlaku 10 menit). "
                f"Kirimkan ke user via email atau channel aman lain.")
        db.log_event(user.address, "admin_reset_password_initiated", f"acct:{selected_id}")
    
    # Suspend/Unsuspend
    if sel_acct.role == "doctor":
        if not sel_acct.is_approved:
            if col2.button("Aktifkan/Setujui", key=f"approve_{selected_id}"):
                note = st.text_input("Catatan verifikasi", key=f"approve_note_{selected_id}")
                if st.button("Konfirmasi", key=f"approve_confirm_{selected_id}"):
                    if len(note.strip()) < 5:
                        st.error("Catatan minimal 5 karakter.")
                    else:
                        db.approve_doctor(selected_id, user.address, note.strip())
                        db.log_event(user.address, "dokter_disetujui_admin_custom", f"acct:{selected_id}")
                        st.success("Dokter disetujui.")
                        st.rerun()
        else:
            if col2.button("Suspend (Cegah akses)", key=f"suspend_{selected_id}"):
                reason = st.text_input("Alasan suspend", key=f"suspend_reason_{selected_id}")
                if st.button("Konfirmasi Suspend", key=f"suspend_confirm_{selected_id}"):
                    if len(reason.strip()) < 5:
                        st.error("Alasan minimal 5 karakter.")
                    else:
                        db.reject_doctor(selected_id, user.address, reason.strip())
                        db.log_event(user.address, "user_disuspend", f"acct:{selected_id}", reason.strip()[:100])
                        st.success("User disuspend.")
                        st.rerun()
    
    # Block/Unblock
    if col3.button("Lock Akun", key=f"lock_{selected_id}"):
        db.lock_account(selected_id)
        db.log_event(user.address, "akun_dikunci_admin", f"acct:{selected_id}")
        st.success("Akun dikunci.")
        st.rerun()


def usage_statistics(user) -> None:
    """Admin Kustom: Statistik penggunaan sistem."""
    ui.log_view_once(user, "admin_mgmt_statistics")
    st.header("Statistik Penggunaan")
    ui.note("Tampilkan metrik utama: jumlah user, rekam medis, aktivitas.")
    
    # Hitung statistik
    all_accts = db.list_accounts()
    all_recs = db.list_records()
    all_logs = db.list_logs(limit=10000)
    
    patients = [a for a in all_accts if a.role == "patient"]
    doctors = [a for a in all_accts if a.role == "doctor"]
    admins = [a for a in all_accts if a.role in ("admin_security", "admin_custom", "admin")]
    
    approved_docs = [d for d in doctors if d.is_approved]
    pending_docs = [d for d in doctors if not d.is_approved and not d.rejection_reason]
    rejected_docs = [d for d in doctors if d.rejection_reason]
    
    # Metrik
    st.subheader("Ringkasan Akun")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total User", len(all_accts))
    m2.metric("Pasien", len(patients))
    m3.metric("Dokter", len(doctors))
    m4.metric("Admin", len(admins))
    
    m5, m6, m7 = st.columns(3)
    m5.metric("Dokter Disetujui", len(approved_docs))
    m6.metric("Dokter Menunggu", len(pending_docs))
    m7.metric("Dokter Ditolak", len(rejected_docs))
    
    st.subheader("Rekam Medis")
    m8, m9, m10 = st.columns(3)
    m8.metric("Total Rekam", len(all_recs))
    m9.metric("Dengan PHI", sum(1 for r in all_recs if r.has_phi))
    m10.metric("Dengan Diagnosis", sum(1 for r in all_recs if r.has_diagnosis))
    
    # Aktivitas harian
    st.subheader("Aktivitas Harian (30 hari terakhir)")
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    day_30_ago = now - timedelta(days=30)
    
    daily_logs = {}
    for log in all_logs:
        if log.ts >= day_30_ago.isoformat():
            date_str = log.ts[:10]
            daily_logs[date_str] = daily_logs.get(date_str, 0) + 1
    
    if daily_logs:
        df_daily = pd.DataFrame([
            {"Tanggal": date, "Event": count}
            for date, count in sorted(daily_logs.items())
        ])
        st.bar_chart(df_daily.set_index("Tanggal"))
    else:
        st.info("Belum ada aktivitas dalam 30 hari terakhir.")
    
    # Top actions
    st.subheader("Aksi Paling Sering")
    action_counts = {}
    for log in all_logs:
        action_counts[log.action] = action_counts.get(log.action, 0) + 1
    
    top_actions = sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    df_actions = pd.DataFrame([
        {"Aksi": action, "Jumlah": count}
        for action, count in top_actions
    ])
    st.dataframe(df_actions, hide_index=True)


def system_settings(user) -> None:
    """Admin Kustom: Pengaturan sistem."""
    ui.log_view_once(user, "admin_mgmt_system_settings")
    st.header("Pengaturan Sistem")
    ui.note("Tampilkan konfigurasi sistem yang dapat diubah (email notifikasi, SMTP, rate limit, dll).")
    
    st.info("⚙️ Fitur pengaturan sistem akan ditambahkan di fase berikutnya.")
    st.write("Rencana:")
    st.write("- Email notifikasi (SMTP config)")
    st.write("- Rate limit per IP")
    st.write("- Session timeout settings")
    st.write("- Fitur lab stenografi (enable/disable)")
    st.write("- Backup dan restore database")
