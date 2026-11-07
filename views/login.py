"""Masuk, daftar, verifikasi email (OTP), MFA (TOTP), dan reset password."""
from __future__ import annotations

import hashlib
import math
import time

import streamlit as st

import config
from utils import auth, mailer, totp
from utils import db_helper as db
from utils.clientinfo import client_ip
from views import security, ui

FLOW = "auth_flow"
GENERIC_ERROR = "Email atau password salah."


# --------------------------------------------------------------------------- alur setelah password benar
def _finish_login(acct) -> None:
    now = time.time()
    st.session_state.pop(FLOW, None)
    st.session_state.update(account_id=acct.id, auth_at=now, last_seen=now)
    db.log_event(f"acct:{acct.id}", "login", detail="email+password")
    st.rerun()


def _send_otp(acct, purpose: str, subject: str) -> str | None:
    if db.rate_limited(f"otp:{acct.email_key[:40]}:{purpose}", config.RATE_OTP_PER_EMAIL, 3600):
        return "Terlalu banyak permintaan kode. Coba lagi dalam satu jam."
    code = db.issue_otp(acct.id, purpose)
    try:
        mailer.send_mail(acct.email, subject,
                         f"Kode Anda: {code}\nBerlaku {config.OTP_TTL_SECONDS // 60} menit. Abaikan email ini jika Anda tidak memintanya.")
    except mailer.MailError as exc:
        return str(exc)
    return None


def _after_password(acct, email_checked: bool = False) -> None:
    """Verifikasi email -> MFA (terdaftar atau wajib) -> masuk."""
    acct = db.promote_if_admin(acct)
    if config.REQUIRE_EMAIL_VERIFICATION and not acct.email_verified and not email_checked:
        error = _send_otp(acct, "verify_email", "Kode verifikasi SeMediChain")
        st.session_state[FLOW] = {"step": "verify_email", "id": acct.id, "error": error}
        st.rerun()
    if acct.mfa_enabled:
        st.session_state[FLOW] = {"step": "mfa", "id": acct.id}
        st.rerun()
    if acct.role in config.REQUIRE_MFA_ROLES:
        st.session_state[FLOW] = {"step": "enroll", "id": acct.id, "secret": totp.new_secret(),
                                  "recovery": totp.new_recovery_codes()}
        st.rerun()
    _finish_login(acct)


def _attempt_login(email: str, password: str) -> str | None:
    if not email.strip() or not password:
        return "Isi email dan password."
    if db.rate_limited(f"login:{client_ip()}", config.RATE_LOGIN_PER_IP, 600):
        return "Terlalu banyak percobaan dari jaringan Anda. Coba lagi beberapa menit lagi."
    acct = db.get_account_by_email(email)
    if acct is None:
        auth.dummy_verify(password)
        tag = hashlib.sha256(auth.canonical_email(email).encode()).hexdigest()[:10]
        db.log_event(f"email:{tag}", "login_gagal", detail="email tidak dikenal")
        return GENERIC_ERROR
    now = time.time()
    if acct.locked_until > now:
        return f"Akun dikunci sementara karena terlalu banyak percobaan. Coba lagi dalam {math.ceil((acct.locked_until - now) / 60)} menit."
    if not auth.verify_password(password, acct.password_hash):
        db.record_login_failure(acct.id)
        db.log_event(f"acct:{acct.id}", "login_gagal", detail="password salah")
        return GENERIC_ERROR
    db.reset_login_failures(acct.id)
    _after_password(acct)
    return None


# --------------------------------------------------------------------------- langkah-langkah
def _login_form() -> None:
    with st.form("login_form"):
        email = st.text_input("Email", key="login_email", placeholder="nama@gmail.com")
        password = st.text_input("Password", type="password", key="login_password")
        submitted = st.form_submit_button("Masuk")
    if submitted:
        error = _attempt_login(email, password)
        if error:
            st.error(error)


def _register_form() -> None:
    st.info("Fitur steganografi (rekam medis, verifikasi file, Lab) mewajibkan dompet Web3 (MetaMask atau dompet EVM "
            "lain) yang tertaut dan terverifikasi. Dompet ditautkan setelah Anda masuk.")
    with st.form("register_form"):
        name = st.text_input("Nama lengkap", key="reg_name")
        email = st.text_input("Email (Gmail)", key="reg_email", placeholder="nama@gmail.com")
        role_label = st.radio("Posisi pengguna", ["Pasien", "Dokter", "Admin Keamanan", "Admin Kustom"], horizontal=True, key="reg_role")
        license_no = st.text_input("Nomor STR (khusus dokter)", key="reg_str", disabled=(role_label != "Dokter"))
        password = st.text_input("Password", type="password", key="reg_pw",
                                 help="Minimal 8 karakter, memuat huruf dan angka, tidak umum.")
        password2 = st.text_input("Ulangi password", type="password", key="reg_pw2")
        with st.expander("Ringkasan pemberitahuan privasi"):
            st.write(ui.PRIVACY_SUMMARY)
        consent = st.checkbox("Saya telah membaca pemberitahuan privasi dan menyetujui pemrosesan data saya.", key="reg_consent")
        submitted = st.form_submit_button("Daftar")
    if not submitted:
        return
    error = (
        ("Nama lengkap minimal 5 karakter." if len(name.strip()) < 5 else None)
        or auth.validate_email(email)
        or auth.validate_password(password, email)
        or ("Konfirmasi password tidak sama." if password != password2 else None)
        or (auth.validate_license(license_no) if role_label == "Dokter" else None)
        or (None if consent else "Anda harus menyetujui pemrosesan data untuk mendaftar.")
        # or ("Terlalu banyak pendaftaran dari jaringan ini. Coba lagi nanti."
        #     if db.rate_limited(f"register:{client_ip()}", config.RATE_REGISTER_PER_IP, 3600) else None)
    )
    if error:
        st.error(error)
        return
    try:
        ROLE_MAP = {"Pasien": "patient", "Dokter": "doctor", "Admin Keamanan": "admin_security", "Admin Kustom": "admin_custom"}
        acct = db.create_account(email, name, ROLE_MAP[role_label],
                                 auth.hash_password(password), license_no.strip() or None, config.PRIVACY_VERSION)
    except ValueError as exc:
        st.error(str(exc))
        return
    db.log_event(f"acct:{acct.id}", "registrasi", detail=acct.role)
    _after_password(acct)


def _forgot_form() -> None:
    # --- Tambahan: Tampilkan log demo untuk tester ---
    if not config.IS_PROD:
        with st.expander("🧪 Demo Testing: Lihat Kode OTP Terakhir"):
            log_path = config.DATA_DIR / "mail_outbox.log"
            if log_path.exists():
                st.code(log_path.read_text(encoding="utf-8"), language=None)
            else:
                st.write("Belum ada email terkirim.")
    # --------------------------------------------------

    flow = st.session_state.get("reset_flow")
    
    if not flow:
        st.subheader("Lupa Password")
        st.write("Masukkan email akun Anda. Jika email terdaftar, kami akan mengirim kode reset password.")
        
        with st.form("forgot_form"):
            email = st.text_input("Email akun", key="forgot_email", placeholder="nama@gmail.com")
            submitted = st.form_submit_button("Kirim kode reset")
        
        if submitted:
            if not email.strip():
                st.error("Masukkan email terlebih dahulu.")
            else:
                acct = db.get_account_by_email(email)
                if acct is None:
                    st.info("Jika email terdaftar di sistem kami, Anda akan menerima kode reset password dalam beberapa menit.")
                else:
                    error = _send_otp(acct, "reset_password", "Kode reset password SeMediChain")
                    if error:
                        st.error(f"Gagal mengirim kode: {error}")
                    else:
                        st.success("Kode reset password sudah dikirim ke email Anda. Berlaku 10 menit.")
                        db.log_event(f"acct:{acct.id}", "reset_password_diminta")
                        st.session_state["reset_flow"] = {"email": email, "account_id": acct.id}
                        st.rerun()
        return
    
    st.subheader("Reset Password")
    acct = db.get_account(flow.get("account_id"))
    if acct is None:
        st.error("Akun tidak ditemukan.")
        if st.button("Mulai ulang", key="reset_restart_error"):
            st.session_state.pop("reset_flow", None)
            st.rerun()
        return
    
    local, _, domain = acct.email.partition("@")
    st.info(f"Kode verifikasi telah dikirim ke {local[:1]}***@{domain}. Kode berlaku {config.OTP_TTL_SECONDS // 60} menit.")
    
    with st.form("reset_form"):
        code = st.text_input("Kode dari email", key="reset_code", max_chars=6, placeholder="000000")
        pw = st.text_input("Password baru", type="password", key="reset_pw")
        pw2 = st.text_input("Ulangi password baru", type="password", key="reset_pw2")
        submitted = st.form_submit_button("Ubah password")
    
    if submitted:
        if not code.strip():
            st.error("Masukkan kode terlebih dahulu.")
        elif not pw.strip():
            st.error("Masukkan password baru.")
        else:
            error = auth.validate_password(pw, flow["email"]) or ("Konfirmasi password tidak sama." if pw != pw2 else None)
            if error:
                st.error(error)
            elif not db.check_otp(acct.id, "reset_password", code):
                st.error("Kode salah atau kedaluwarsa.")
            else:
                db.set_password(acct.id, auth.hash_password(pw))
                db.log_event(f"acct:{acct.id}", "reset_password_berhasil")
                st.session_state.pop("reset_flow", None)
                st.session_state["login_notice"] = "✅ Password berhasil diubah. Silakan masuk dengan password baru."
                st.success("✅ Password berhasil diubah. Silakan masuk dengan password baru.")
                st.balloons()
                st.info("Silakan klik tab 'Masuk' untuk login dengan password baru Anda.")
    
    c1, c2 = st.columns(2)
    if c1.button("Kirim ulang kode", key="reset_resend"):
        error = _send_otp(acct, "reset_password", "Kode reset password SeMediChain")
        if error:
            st.error(f"Gagal mengirim ulang: {error}")
        else:
            st.success("Kode baru sudah dikirim.")
    if c2.button("Mulai ulang", key="reset_restart"):
        st.session_state.pop("reset_flow", None)
        st.rerun()


def _step_verify_email(flow: dict) -> None:
    acct = db.get_account(flow["id"])
    if acct is None:
        st.error("Akun tidak ditemukan. Silakan masuk kembali.")
        st.session_state.pop(FLOW, None)
        st.stop()
    local, _, domain = acct.email.partition("@")
    st.subheader("Verifikasi email")
    st.write(f"Kami mengirim kode 6 digit ke {local[:1]}***@{domain}. Kode berlaku {config.OTP_TTL_SECONDS // 60} menit.")
    if flow.get("error"):
        st.error(flow["error"])
    with st.form("verify_form"):
        code = st.text_input("Kode verifikasi", key="verify_code", max_chars=6)
        ok = st.form_submit_button("Verifikasi")
    if ok:
        if db.check_otp(acct.id, "verify_email", code):
            db.mark_email_verified(acct.id)
            db.log_event(f"acct:{acct.id}", "email_terverifikasi")
            _after_password(acct, email_checked=True)
        else:
            st.error("Kode salah atau kedaluwarsa.")
    c1, c2 = st.columns(2)
    if c1.button("Kirim ulang kode", key="verify_resend"):
        flow["error"] = _send_otp(acct, "verify_email", "Kode verifikasi SeMediChain")
        st.rerun()
    if c2.button("Batal", key="verify_cancel"):
        st.session_state.pop(FLOW, None)
        st.rerun()


def _step_mfa(flow: dict) -> None:
    acct = db.get_account(flow["id"])
    if acct is None:
        st.error("Akun tidak ditemukan. Silakan masuk kembali.")
        st.session_state.pop(FLOW, None)
        st.stop()
    if acct.totp_secret is None:
        st.error("Pengaturan autentikasi tidak valid. Silakan masuk kembali.")
        st.session_state.pop(FLOW, None)
        st.stop()
    st.subheader("Autentikasi dua langkah")
    with st.form("mfa_form"):
        code = st.text_input("Kode 6 digit dari aplikasi autentikator, atau kode pemulihan", key="mfa_code")
        ok = st.form_submit_button("Verifikasi")
    if ok:
        step = totp.verify(acct.totp_secret, code, acct.totp_last_step) if "-" not in code else None
        if step is not None:
            db.set_totp_step(acct.id, step)
            db.log_event(f"acct:{acct.id}", "mfa_berhasil")
            _finish_login(acct)
        if "-" in code and db.use_recovery_code(acct.id, code):
            db.log_event(f"acct:{acct.id}", "mfa_kode_pemulihan_dipakai")
            _finish_login(acct)
        db.record_login_failure(acct.id)
        db.log_event(f"acct:{acct.id}", "mfa_gagal")
        current_acct = db.get_account(acct.id)
        if current_acct is not None and current_acct.locked_until > time.time():
            st.session_state.pop(FLOW, None)
            st.session_state["login_notice"] = "Akun dikunci sementara karena terlalu banyak kode salah."
            st.rerun()
        st.error("Kode tidak cocok.")
    if st.button("Batal", key="mfa_cancel"):
        st.session_state.pop(FLOW, None)
        st.rerun()


def _step_enroll(flow: dict) -> None:
    acct = db.get_account(flow["id"])
    if acct is None:
        st.error("Akun tidak ditemukan. Silakan masuk kembali.")
        st.session_state.pop(FLOW, None)
        st.stop()
    st.subheader("Aktifkan autentikasi dua langkah")
    st.info("Peran Anda mewajibkan MFA. Pindai QR lalu konfirmasi sekali untuk melanjutkan.")
    step = security.render_enroll(acct.email, flow["secret"], flow["recovery"], "login")
    if step is not None:
        db.enable_mfa(acct.id, flow["secret"], flow["recovery"], step)
        db.log_event(f"acct:{acct.id}", "mfa_diaktifkan")
        _finish_login(acct)
    if st.button("Batal", key="enroll_cancel"):
        st.session_state.pop(FLOW, None)
        st.rerun()


def _dev_outbox() -> None:
    if config.IS_PROD or config.MAIL_BACKEND != "console" or not mailer.DEV_OUTBOX:
        return
    with st.expander("Kotak masuk pengembangan (email yang \"terkirim\")"):
        for m in reversed(mailer.DEV_OUTBOX[-3:]):
            st.caption(f"{m['subject']} untuk {m['to']}")
            st.code(m["body"], language=None)


def render() -> None:
    st.title("SeMediChain")
    st.caption("")
    notice = st.session_state.pop("login_notice", None)
    if notice:
        st.warning(notice)
    flow = st.session_state.get(FLOW)
    if flow:
        {"verify_email": _step_verify_email, "mfa": _step_mfa, "enroll": _step_enroll}[flow["step"]](flow)
    else:
        tab_in, tab_up, tab_pw = st.tabs(["Masuk", "Daftar", "Lupa password"])
        with tab_in:
            _login_form()
        with tab_up:
            _register_form()
        with tab_pw:
            _forgot_form()
    _dev_outbox()
