"""Portal pasien: persetujuan akses dokter (minta/beri/cabut)."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from utils import db_helper as db
from utils import web3_utils
from views import ui


def render(user) -> None:
    st.header("Akses dokter")
    ui.note("Dokter hanya dapat menulis rekam medis baru untuk Anda setelah Anda menyetujui. "
            "Anda bisa mencabut persetujuan kapan saja.")
    names = {u.address: u.name for u in db.list_users()}
    label = lambda a: f"Dr. {names.get(a, web3_utils.short(a))}"  # noqa: E731

    incoming = [g for g in db.list_grants(patient=user.address, status="pending") if g.requested_by == "doctor"]
    st.subheader("Permintaan masuk")
    if not incoming:
        st.caption("Tidak ada permintaan.")
    for g in incoming:
        c1, c2, c3 = st.columns([3, 1, 1])
        c1.markdown(f"**{label(g.doctor_address)}** meminta akses")
        if c2.button("Setujui", key=f"consent_ok_{g.id}"):
            db.respond_access(user.address, g.doctor_address, True)
            db.log_event(user.address, "akses_disetujui", g.doctor_address)
            st.rerun()
        if c3.button("Tolak", key=f"consent_no_{g.id}"):
            db.respond_access(user.address, g.doctor_address, False)
            db.log_event(user.address, "akses_ditolak", g.doctor_address)
            st.rerun()

    st.subheader("Dokter dengan akses aktif")
    active = db.list_grants(patient=user.address, status="active")
    if not active:
        st.caption("Belum ada.")
    for g in active:
        c1, c2 = st.columns([4, 1])
        c1.markdown(f"**{label(g.doctor_address)}** · sejak {g.updated_at:%Y-%m-%d}")
        if c2.button("Cabut", key=f"consent_revoke_{g.id}"):
            db.revoke_access(user.address, g.doctor_address)
            db.log_event(user.address, "akses_dicabut_dokter", g.doctor_address)
            still = [r for r in db.list_records(patient=user.address)
                     if any(x.address == g.doctor_address and x.role == "shared" for x in db.list_recipients(r.id))]
            st.session_state["consent_notice"] = (
                f"Akses {label(g.doctor_address)} dicabut untuk rekam baru." +
                (f" Masih dibagikan pada {len(still)} rekam: cabut per rekam di menu Rekam medis saya." if still else ""))
            st.rerun()
    notice = st.session_state.pop("consent_notice", None)
    if notice:
        st.warning(notice)

    st.subheader("Bagikan Data ke Dokter Baru")
    taken = {g.doctor_address for g in db.list_grants(patient=user.address, status="active")}
    doctors = [u for u in db.list_users(role="doctor") if u.address not in taken]
    if doctors:
        pick = st.selectbox("Pilih Dokter", [u.address for u in doctors], format_func=label, key="consent_pick")
        if st.button("Izinkan", key="consent_give", width="stretch"):
            db.grant_access(user.address, pick)
            db.log_event(user.address, "akses_diberikan", pick)
            st.rerun()
    else:
        st.caption("Belum ada dokter terverifikasi dengan dompet tertaut.")

    hist = [g for g in db.list_grants(patient=user.address) if g.status in ("revoked", "denied")]
    if hist:
        st.subheader("Riwayat")
        st.dataframe(pd.DataFrame([{"Dokter": label(g.doctor_address), "Status": g.status,
                                    "Diperbarui": g.updated_at.strftime("%Y-%m-%d %H:%M")} for g in hist]), hide_index=True)
