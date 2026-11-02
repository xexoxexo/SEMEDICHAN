"""Auth helpers: role check, permission enforce, session validate."""
import time
import streamlit as st
import config
from utils import db_helper as db


def require_role(*allowed_roles: str) -> dict | None:
    """Decorator: cek role akun. Return principal atau None jika unauthorized."""
    account_id = st.session_state.get("account_id")
    if not account_id:
        st.error("Silakan masuk terlebih dahulu.")
        st.stop()
    
    acct = db.get_account(account_id)
    if not acct:
        st.error("Akun tidak ditemukan.")
        st.session_state.clear()
        st.rerun()
    
    if acct.role not in allowed_roles:
        st.error(f"Akses ditolak. Peran Anda ({acct.role}) tidak memiliki izin.")
        st.stop()
    
    return acct


def check_session_timeout() -> None:
    """Cek idle timeout dan absolute timeout."""
    auth_at = st.session_state.get("auth_at", 0)
    last_seen = st.session_state.get("last_seen", 0)
    now = time.time()
    
    idle_seconds = config.SESSION_IDLE_MINUTES * 60
    max_seconds = config.SESSION_MAX_HOURS * 3600
    
    if now - last_seen > idle_seconds:
        st.session_state.clear()
        st.warning("Sesi Anda berakhir karena inaktif. Silakan masuk kembali.")
        st.stop()
    
    if now - auth_at > max_seconds:
        st.session_state.clear()
        st.warning("Sesi Anda berakhir. Silakan masuk kembali.")
        st.stop()
    
    st.session_state["last_seen"] = now


def get_principal() -> dict | None:
    """Ambil principal (user/dompet) dari session."""
    account_id = st.session_state.get("account_id")
    if not account_id:
        return None
    
    acct = db.get_account(account_id)
    if not acct or not acct.wallet_address:
        return None
    
    return db.get_user(acct.wallet_address)


def require_wallet_linked() -> dict:
    """Pastikan dompet sudah tertaut dan terverifikasi."""
    account_id = st.session_state.get("account_id")
    if not account_id:
        st.error("Silakan masuk terlebih dahulu.")
        st.stop()
    
    acct = db.get_account(account_id)
    if not acct or not acct.wallet_address:
        st.error("Dompet belum tertaut. Tautkan dompet Anda terlebih dahulu.")
        st.stop()
    
    user = db.get_user(acct.wallet_address)
    if not user:
        st.error("Identitas dompet tidak ditemukan.")
        st.stop()
    
    return user


def is_wallet_open() -> bool:
    """Cek apakah session state DEK (data encryption key) ada."""
    return "DEK" in st.session_state


def check_doctor_approved() -> None:
    """Cek apakah dokter sudah disetujui admin."""
    account_id = st.session_state.get("account_id")
    acct = db.get_account(account_id)
    
    if acct.role == "doctor" and not acct.is_approved:
        st.warning("Akun dokter Anda masih menunggu verifikasi admin.")
        if st.button("Keluar"):
            st.session_state.clear()
            st.rerun()
        st.stop()


def enforce_mfa_if_required() -> None:
    """Paksa MFA untuk role tertentu."""
    account_id = st.session_state.get("account_id")
    acct = db.get_account(account_id)
    
    if acct.role in config.REQUIRE_MFA_ROLES and not acct.mfa_enabled:
        st.warning(f"Peran {acct.role} mewajibkan autentikasi dua langkah (MFA).")
        st.info("Silakan aktifkan MFA di halaman Keamanan Akun.")
        st.stop()


def log_access(action: str, target: str = "", detail: str = "") -> None:
    """Log akses user untuk audit trail."""
    account_id = st.session_state.get("account_id")
    acct = db.get_account(account_id)
    if acct:
        db.log_event(acct.wallet_address or f"acct:{acct.id}", action, target, detail)
