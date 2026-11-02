"""Panel admin: persetujuan dokter, metadata rekam, audit trail."""
from __future__ import annotations

import csv
import io
import json

import pandas as pd
import streamlit as st

from utils import db_helper as db
from views import records, ui


def approvals(user) -> None:
    ui.log_view_once(user, "admin_lihat_akun")
    st.header("Verifikasi dokter")
    ui.note("Periksa nomor STR dokter pada sumber resmi (mis. Konsil Kedokteran Indonesia), lalu catat sumber dan tanggal "
            "pemeriksaan. Sistem ini tidak memverifikasi keaslian STR secara otomatis.")
    doctors = db.list_accounts(role="doctor")
    pending = [a for a in doctors if not a.is_approved and not a.rejection_reason]
    rejected = [a for a in doctors if not a.is_approved and a.rejection_reason]
    if not pending:
        st.info("Tidak ada dokter yang menunggu persetujuan.")
    for a in pending + rejected:
        with st.container(border=True):
            st.markdown(f"**{a.full_name}** · {a.email} · STR `{a.license_no}` · terdaftar {a.created_at:%Y-%m-%d}")
            if a.rejection_reason:
                st.caption(f"Ditolak oleh {a.verified_by}: {a.rejection_reason}")
            note = st.text_input("Catatan verifikasi (sumber dan tanggal pemeriksaan, minimal 10 karakter)", key=f"ap_note_{a.id}")
            reason = st.text_input("Alasan penolakan (minimal 5 karakter)", key=f"rej_reason_{a.id}")
            c1, c2 = st.columns(2)
            if c1.button("Setujui", key=f"ap_{a.id}"):
                if len(note.strip()) < 10:
                    st.error("Isi catatan verifikasi lebih lengkap (sumber dan tanggal pemeriksaan).")
                else:
                    db.approve_doctor(a.id, user.address, note.strip())
                    db.log_event(user.address, "dokter_disetujui", f"acct:{a.id}", note.strip()[:100])
                    st.rerun()
            if c2.button("Tolak", key=f"rej_{a.id}"):
                if len(reason.strip()) < 5:
                    st.error("Isi alasan penolakan.")
                else:
                    db.reject_doctor(a.id, user.address, reason.strip())
                    db.log_event(user.address, "dokter_ditolak", f"acct:{a.id}", reason.strip()[:100])
                    st.rerun()
    st.subheader("Semua akun")
    st.dataframe(pd.DataFrame([
        {"Nama": a.full_name, "Email": a.email, "Peran": ui.ROLE_LABEL[a.role], "Disetujui": a.is_approved,
         "Email terverifikasi": a.email_verified, "MFA": a.mfa_enabled, "Dompet": a.wallet_address or "belum tertaut",
         "Terdaftar": a.created_at.strftime("%Y-%m-%d %H:%M")}
        for a in db.list_accounts()
    ]), hide_index=True)


def all_records(user) -> None:
    ui.log_view_once(user, "admin_lihat_metadata")
    st.header("Metadata rekam medis")
    records.render(user, "admin")


def audit(user) -> None:
    ui.log_view_once(user, "admin_lihat_audit")
    st.header("Audit trail")
    ui.note("Setiap entri memuat hash entri sebelumnya (rantai SHA-256). Perubahan atau penghapusan entri lama akan terdeteksi.")
    if st.button("Verifikasi rantai audit"):
        ok, bad_id, total = db.verify_audit_chain()
        if ok:
            st.success(f"Rantai audit utuh ({total} entri).")
        else:
            st.error(f"Rantai audit rusak mulai entri #{bad_id}.")
    st.subheader("Checkpoint eksternal")
    st.caption("Unduh checkpoint bertanda tangan dan simpan di luar server (mis. penyimpanan tak dapat diubah). "
               "Dengan checkpoint, pemangkasan atau penulisan ulang rantai oleh pengelola database ikut terdeteksi.")
    cp = db.audit_checkpoint()
    st.download_button("Unduh checkpoint audit (JSON)", json.dumps(cp, indent=2), file_name=f"audit_checkpoint_{cp['ts']}.json",
                       mime="application/json", key="cp_dl", on_click=db.log_event, args=(user.address, "audit_checkpoint_diunduh"))
    up = st.file_uploader("Verifikasi checkpoint (JSON)", type=["json"], key="cp_up")
    if up is not None:
        try:
            ok, msg = db.verify_checkpoint(json.loads(up.getvalue()))
        except ValueError:
            ok, msg = False, "Berkas bukan JSON yang valid."
        (st.success if ok else st.error)(msg)
    logs = db.list_logs(500)
    if not logs:
        st.info("Belum ada entri audit.")
        return
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "waktu_utc", "pelaku", "aksi", "target", "rincian", "hash"])
    for l in logs:
        w.writerow([l.id, l.ts, l.actor, l.action, l.target, l.detail, l.entry_hash])
    st.download_button("Ekspor audit (CSV)", buf.getvalue(), file_name="audit_trail.csv", mime="text/csv", key="audit_csv",
                       on_click=db.log_event, args=(user.address, "audit_diekspor"))
    action = st.selectbox("Filter aksi", ["(semua)"] + sorted({l.action for l in logs}))
    rows = [l for l in logs if action == "(semua)" or l.action == action]
    st.dataframe(pd.DataFrame([
        {"#": l.id, "Waktu (UTC)": l.ts, "Aktor": l.actor, "Aksi": l.action, "Target": l.target,
         "Detail": l.detail, "Hash": l.entry_hash[:16] + "…"}
        for l in rows
    ]), hide_index=True)


def subject_requests(user) -> None:
    ui.log_view_once(user, "admin_lihat_hak_data")
    st.header("Permintaan hak data")
    status = st.selectbox("Status", ["baru", "diproses", "selesai", "ditolak"], key="sr_admin_status")
    items = db.list_subject_requests(status=status)
    if not items:
        st.info("Tidak ada permintaan pada status ini.")
    for r in items:
        acct = db.get_account(r.account_id)
        with st.container(border=True):
            st.markdown(f"**#{r.id} · {r.kind}** · {acct.full_name if acct else '-'} ({acct.email if acct else '-'}) · {r.created_at:%Y-%m-%d %H:%M}")
            st.write(r.detail)
            new_status = st.selectbox("Ubah status", ["diproses", "selesai", "ditolak"], key=f"sr_st_{r.id}")
            reply = st.text_input("Jawaban untuk pasien (minimal 10 karakter)", key=f"sr_reply_{r.id}")
            if st.button("Simpan", key=f"sr_save_{r.id}"):
                if len(reply.strip()) < 10:
                    st.error("Isi jawaban untuk pasien.")
                else:
                    db.update_subject_request(r.id, new_status, reply, user.address)
                    db.log_event(user.address, "hak_data_ditangani", f"req:{r.id}", new_status)
                    st.rerun()
