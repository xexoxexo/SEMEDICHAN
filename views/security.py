"""Keamanan akun: 2MFA (TOTP + kode pemulihan) dan ganti password."""
from __future__ import annotations

import json

import streamlit as st

import config
from utils import auth, totp
from utils import db_helper as db
from views import ui


def render_enroll(email: str, secret: str, recovery: list[str], prefix: str) -> int | None:
    """Tampilkan QR/secret + kode pemulihan, minta konfirmasi kode. Return langkah TOTP bila terkonfirmasi."""
    uri = totp.provisioning_uri(secret, email)
    png = totp.qr_png(uri)
    c1, c2 = st.columns([1, 2])
    if png:
        c1.image(png, width=190)
    c2.markdown("Pindai QR dengan aplikasi autentikator (Google Authenticator, Authy, dll.), atau masukkan kunci ini manual:")
    c2.code(secret, language=None)
    st.markdown("**Kode pemulihan** (simpan di tempat aman; hanya ditampilkan sekali, tiap kode sekali pakai):")
    st.code("\n".join(recovery), language=None)
    saved = st.checkbox("Saya sudah menyimpan kode pemulihan", key=f"{prefix}_saved")
    with st.form(f"{prefix}_enroll_form"):
        code = st.text_input("Kode 6 digit dari aplikasi autentikator", key=f"{prefix}_enroll_code", max_chars=6)
        ok = st.form_submit_button("Aktifkan MFA")
    if not ok:
        return None
    if not saved:
        st.error("Centang dulu bahwa kode pemulihan sudah disimpan.")
        return None
    step = totp.verify(secret, code)
    if step is None:
        st.error("Kode tidak cocok. Pastikan jam perangkat akurat, lalu coba lagi.")
    return step


def _mfa_panel(acct) -> None:
    required = acct.role in config.REQUIRE_MFA_ROLES
    if not acct.mfa_enabled:
        if required:
            ui.note("MFA wajib untuk peran Anda. Aktifkan sekarang.")
        enroll = st.session_state.get("sec_enroll")
        if enroll is None:
            if st.button("Aktifkan MFA", key="sec_start_enroll"):
                st.session_state["sec_enroll"] = {"secret": totp.new_secret(), "recovery": totp.new_recovery_codes()}
                st.rerun()
            return
        step = render_enroll(acct.email, enroll["secret"], enroll["recovery"], "sec")
        if step is not None:
            db.enable_mfa(acct.id, enroll["secret"], enroll["recovery"], step)
            db.log_event(f"acct:{acct.id}", "mfa_diaktifkan")
            st.session_state.pop("sec_enroll", None)
            st.rerun()
        return

    left = len(json.loads(acct.recovery_hashes or "[]"))
    st.success(f"MFA aktif. Kode pemulihan tersisa: {left}.")
    flash = st.session_state.pop("sec_new_codes", None)
    if flash:
        st.markdown("**Kode pemulihan baru** (hanya ditampilkan sekali):")
        st.code("\n".join(flash), language=None)
    with st.form("sec_mfa_manage"):
        code = st.text_input("Kode 6 digit saat ini (untuk konfirmasi)", key="sec_mfa_code", max_chars=6)
        regen = st.form_submit_button("Buat ulang kode pemulihan")
        off = st.form_submit_button("Matikan MFA", disabled=required)
    if not (regen or off):
        return
    step = totp.verify(acct.totp_secret, code, acct.totp_last_step)
    if step is None:
        st.error("Kode tidak cocok.")
        return
    if regen:
        new = totp.new_recovery_codes()
        db.enable_mfa(acct.id, acct.totp_secret, new, step)
        db.log_event(f"acct:{acct.id}", "mfa_kode_pemulihan_baru")
        st.session_state["sec_new_codes"] = new
    else:
        db.disable_mfa(acct.id)
        db.log_event(f"acct:{acct.id}", "mfa_dimatikan")
    st.rerun()


def _password_panel(acct) -> None:
    st.subheader("Ganti Password")
    st.write("Masukkan password saat ini dan password baru sesuai kebijakan keamanan.")
    
    with st.form("sec_pw_form"):
        current = st.text_input("Password saat ini", type="password", key="sec_pw_current")
        new = st.text_input("Password baru", type="password", key="sec_pw_new",
                           help="Minimal 8 karakter, terdiri dari huruf dan angka, tidak umum.")
        new2 = st.text_input("Ulangi password baru", type="password", key="sec_pw_new2")
        ok = st.form_submit_button("Ganti password")
    
    if not ok:
        return
    
    if not current.strip():
        st.error("Masukkan password saat ini terlebih dahulu.")
        return
    
    if not auth.verify_password(current, acct.password_hash):
        db.log_event(f"acct:{acct.id}", "ganti_password_gagal", detail="password lama salah")
        st.error("❌ Password saat ini salah.")
        return
    
    if not new.strip():
        st.error("Masukkan password baru terlebih dahulu.")
        return
    
    validate_error = auth.validate_password(new, acct.email)
    if validate_error:
        st.error(f"❌ Password tidak memenuhi syarat: {validate_error}")
        return
    
    if new != new2:
        st.error("❌ Konfirmasi password tidak sama.")
        return
    
    db.set_password(acct.id, auth.hash_password(new))
    db.log_event(f"acct:{acct.id}", "ganti_password", detail=f"peran:{acct.role}")
    st.success("✅ Password berhasil diganti. Silakan masuk kembali dengan password baru.")
    st.info("Untuk alasan keamanan, sesi Anda akan berakhir. Silakan masuk kembali.")


def render(user) -> None:
    st.header("Keamanan akun")
    acct = db.get_account(user.account_id)
    tab_mfa, tab_pw = st.tabs(["Autentikasi dua langkah (MFA)", "Ganti password"])
    with tab_mfa:
        _mfa_panel(acct)
    with tab_pw:
        _password_panel(acct)
