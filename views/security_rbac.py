"""Security & Wallet - Role-based Access Control (RBAC).

Per peran, tentukan apakah wallet wajib, opsi, atau tidak perlu.
Simplify UX: hide complexity di belakang "Advanced Security Settings".
"""
import streamlit as st
import config
from utils import db_helper as db
from views import ui

def get_wallet_requirement(role: str) -> dict:
    """Return policy untuk setiap role."""
    policies = {
        "patient": {
            "require_wallet": False,
            "description": "Akses rekam medis pribadi Anda tanpa perlu dompet. Keamanan dijamin oleh enkripsi database.",
            "features_locked": [],  # Semua fitur bisa diakses tanpa wallet
            "optional_security": True,
        },
        "doctor": {
            "require_wallet": False,
            "description": "Kelola pasien dan buat rekam medis dengan akun email Anda. Opsional: hubungkan dompet untuk security tambahan.",
            "features_locked": ["export_diagnosis_with_signature"],  # Hanya export diagnosis signed perlu wallet
            "optional_security": True,
        },
        "admin_security": {
            "require_wallet": True,
            "description": "Admin Keamanan wajib gunakan dompet Web3 untuk semua aksi audit & monitoring.",
            "features_locked": [],  # Semua fitur perlu wallet
            "optional_security": False,
        },
        "admin_custom": {
            "require_wallet": False,
            "description": "Kelola resep dan user. Keamanan level production dengan MFA.",
            "features_locked": [],
            "optional_security": True,
        },
        "admin": {
            "require_wallet": True,
            "description": "Admin Utama wajib gunakan dompet untuk verifikasi dokter, audit, & backup.",
            "features_locked": [],
            "optional_security": False,
        },
    }
    return policies.get(role, policies["patient"])


def should_require_wallet_for_feature(role: str, feature: str) -> bool:
    """Check apakah fitur tertentu butuh wallet unlock untuk role ini."""
    policy = get_wallet_requirement(role)
    
    if policy["require_wallet"]:
        return True  # Semua fitur perlu wallet
    
    return feature in policy["features_locked"]  # Fitur tertentu butuh wallet


def render_security_options(user) -> None:
    """Tampilkan opsi keamanan tambahan (optional) untuk role yang mendukung."""
    policy = get_wallet_requirement(user.role)
    
    if not policy["optional_security"]:
        return  # Role ini tidak ada opsi tambahan
    
    with st.expander("🔒 Opsi Keamanan Tambahan (Optional)"):
        st.write("Hubungkan dompet Web3 untuk keamanan berlapis:")
        st.markdown("""
- **Verifikasi Identitas Ganda:** Setiap aksi penting butuh tanda tangan dompet
- **Audit Trail Blockchain:** Semua aksi tercatat di dompet Anda
- **Recovery dengan Dompet:** Jika lupa password, bisa recover via dompet
        """)
        
        if not user.wallet_linked:
            if st.button("Hubungkan dompet sekarang", key="sec_link_wallet"):
                st.session_state["show_wallet_link"] = True
                st.rerun()
        else:
            st.success(f"✅ Dompet sudah terhubung: {user.address[:6]}...{user.address[-4:]}")
            if st.button("Ganti dompet", key="sec_change_wallet"):
                st.session_state["show_wallet_unlink"] = True
                st.rerun()


def display_role_security_info(user) -> None:
    """Tampilkan info security yang sesuai per role."""
    policy = get_wallet_requirement(user.role)
    
    st.info(f"**Keamanan untuk peran {policy.get('role_label', user.role)}:**\n\n{policy['description']}")
    
    if policy["require_wallet"]:
        if not user.wallet_linked:
            st.warning("⚠️ Peran Anda wajib menghubungkan dompet Web3 untuk semua fitur.")
        else:
            st.success(f"✅ Dompet tertaut: {user.address[:6]}...{user.address[-4:]}")
    elif policy["optional_security"]:
        st.caption("💡 Dompet bersifat opsional. Hubungkan jika ingin keamanan tambahan.")


def is_feature_accessible(user, feature: str) -> bool:
    """Check apakah user bisa access feature tertentu (berdasarkan wallet requirement)."""
    role = user.role
    policy = get_wallet_requirement(role)
    
    # Jika wallet wajib untuk role ini
    if policy["require_wallet"]:
        if not user.wallet_linked:
            return False  # Akun belum tautkan dompet
        # TODO: Check jika kunci stego terbuka (session-based unlock)
    
    # Jika fitur tertentu perlu wallet unlock
    if should_require_wallet_for_feature(role, feature):
        # TODO: Check jika session unlock masih berlaku
        pass
    
    return True
