"""Dashboard per peran/user."""
from __future__ import annotations

import streamlit as st

from utils import db_helper as db
from views import ui

# Flowchart teknis (hanya untuk dokter & admin, bukan pasien)
PIPELINE = """
digraph G {
  rankdir=LR; bgcolor="transparent";
  node [shape=box, style="rounded,filled", fillcolor="#E3F1F0", color="#0B6E6E", fontname="Helvetica", fontsize=11];
  edge [color="#0B6E6E", fontname="Helvetica", fontsize=9];
  form  [label="Form RME\\n(dokter)"];
  hybrid [label="MediCrypt hybrid\\nAES-256-GCM + X25519"];
  cover [label="Covertext\\n(citra medis)", fillcolor="#FBEFD9", color="#B7791F"];
  lsb   [label="LSB acak berkunci"];
  stego [label="Stegotext\\n+ SHA-256"];
  web3  [label="Login MetaMask\\n(SIWE, tanpa gas)", fillcolor="#E6E8FB", color="#4C51BF"];
  pasien [label="Dekripsi di\\nportal pasien"];
  form -> hybrid -> lsb -> stego -> pasien;
  cover -> lsb;
  web3 -> pasien [style=dashed, label="izin akses"];
}
"""


def render(user) -> None:
    if user.role == "patient":
        _patient_dashboard(user)
    elif user.role == "doctor":
        _doctor_dashboard(user)
    else:
        _admin_dashboard(user)


def _patient_dashboard(user) -> None:
    """Beranda ramah lansia: sederhana, tanpa jargon teknis."""
    st.markdown(f'<span class="smw-role">{ui.ROLE_LABEL[user.role]}</span>', unsafe_allow_html=True)
    st.markdown("")

    # Kartu sapaan
    st.markdown(f"### Halo, {user.name}!")
    st.markdown("Selamat datang kembali di SeMediChain.")

    # 1. Notifikasi Persetujuan Akses Dokter (Medical Permission)
    pending_requests = db.list_grants(patient=user.address, status="pending")
    if pending_requests:
        all_users = {u.address: u.name for u in db.list_users()}
        for req in pending_requests:
            doc_name = all_users.get(req.doctor_address, "Dokter")
            with st.container():
                st.warning(f"### 🔔 Permintaan Akses Medis\n\n**dr. {doc_name}** ingin mengakses rekam medis Anda untuk keperluan pemeriksaan. Apakah Anda mengizinkan?")
                col_a, col_b = st.columns([1, 4])
                if col_a.button(f"Izinkan dr. {doc_name}", key=f"app_{req.id}", type="primary"):
                    db.respond_access(user.address, req.doctor_address, approve=True)
                    st.success(f"Akses diberikan kepada dr. {doc_name}")
                    st.rerun()
                if col_b.button(f"Tolak", key=f"rej_{req.id}"):
                    db.respond_access(user.address, req.doctor_address, approve=False)
                    st.info("Permintaan akses ditolak.")
                    st.rerun()
                st.markdown('<p style="font-size: 0.9rem; color: #666; margin-top: 10px;"><i>Izin ini diperlukan agar dokter dapat melihat riwayat penyakit dan obat Anda sebelumnya untuk mencegah kesalahan medis.</i></p>', unsafe_allow_html=True)
        st.markdown("---")

    # Status ringkas
    st.subheader("Ringkasan Kesehatan")
    records_list = db.list_records(patient=user.address)
    n = len(records_list)
    
    col1, col2 = st.columns(2)
    col1.metric("Total Rekam Medis", n)
    
    if records_list:
        latest = records_list[0]
        all_users = {u.address: u.name for u in db.list_users()}
        status = "🟢 Terverifikasi" if latest.has_phi else "🟡 Menunggu Verifikasi Dokter"
        doctor_name = all_users.get(latest.doctor_address, "Dokter")
        date = latest.created_at.strftime("%Y-%m-%d") if hasattr(latest, "created_at") else "Hari ini"
        col2.info(f"**Terakhir**: {status} oleh dr. {doctor_name} pada {date}")
    else:
        col2.write("Belum ada rekam medis.")

    st.markdown("---")

    # 2. Cari Dokter untuk Berobat
    st.subheader("🩺 Cari Dokter untuk Berobat")
    st.markdown("Jika Anda ingin berkonsultasi dengan dokter baru, cari namanya di bawah ini untuk memberikan izin akses medis.")
    all_doctors = [u for u in db.list_users() if u.role == "doctor"]
    doc_options = {f"dr. {d.name}": d.address for d in all_doctors}
    
    selected_doc_label = st.selectbox("Cari nama dokter:", options=[""] + list(doc_options.keys()), index=0)
    if selected_doc_label:
        doc_addr = doc_options[selected_doc_label]
        # Cek apakah sudah ada akses aktif
        existing = db.list_grants(patient=user.address, doctor=doc_addr, status="active")
        if not existing:
            if st.button(f"Berikan Izin Akses ke {selected_doc_label}", type="primary"):
                db.grant_access(user.address, doc_addr)
                st.success(f"Berhasil! {selected_doc_label} sekarang dapat melihat rekam medis Anda.")
                st.rerun()
        else:
            st.info(f"{selected_doc_label} sudah memiliki akses ke rekam medis Anda.")

    st.markdown("---")

    # Tombol navigasi cepat
    col_nav1, col_nav2 = st.columns(2)
    with col_nav1:
        if st.button("📋 Buka Rekam Medis Saya", width="stretch"):
            st.session_state["requested_page"] = "Rekam Medis Saya"
            st.rerun()
    with col_nav2:
        if st.button("📥 Unduh Data Medis (ZIP)", width="stretch"):
            st.session_state["requested_page"] = "Ekspor Data"
            st.rerun()

    st.markdown("---")
    st.info("🔒 Data medis Anda aman. Hanya Anda dan dokter yang Anda pilih yang dapat melihatnya.")


def _doctor_dashboard(user) -> None:
    st.header(f"Halo, Dr. {user.name}")
    st.markdown(f'<span class="smw-role">{ui.ROLE_LABEL[user.role]}</span>', unsafe_allow_html=True)
    n = len(db.list_records(doctor=user.address))
    c1, c2 = st.columns(2)
    c1.metric("Rekam medis yang saya buat", n)
    c2.metric("Pasien terdaftar", db.counts()["patients"])
    if not user.wallet_linked:
        ui.note("Dompet Web3 belum tertaut. Fitur steganografi (rekam medis, verifikasi file, Lab) terkunci sampai "
                "dompet ditautkan dan diverifikasi lewat menu Dompet dan kunci stego.")
    st.subheader("Alur perlindungan data")
    st.graphviz_chart(PIPELINE)
    st.markdown(
        "Data rekam medis dienkripsi hybrid, disembunyikan di piksel citra medis, lalu hanya dapat dibuka "
        "oleh pasien pemilik atau dokter pembuat setelah masuk dengan dompetnya."
    )


def _admin_dashboard(user) -> None:
    st.header(f"Halo, {user.name}")
    st.markdown(f'<span class="smw-role">{ui.ROLE_LABEL[user.role]}</span>', unsafe_allow_html=True)
    c = db.counts()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Pasien", c["patients"])
    c2.metric("Dokter", c["doctors"])
    c3.metric("Rekam medis", c["records"])
    c4.metric("Entri audit", c["audit"])
    if not user.wallet_linked:
        ui.note("Dompet Web3 belum tertaut. Fitur steganografi (rekam medis, verifikasi file, Lab) terkunci sampai "
                "dompet ditautkan dan diverifikasi lewat menu Dompet dan kunci stego.")
    st.subheader("Alur perlindungan data")
    st.graphviz_chart(PIPELINE)
    st.markdown(
        "Data rekam medis dienkripsi hybrid, disembunyikan di piksel citra medis, lalu hanya dapat dibuka "
        "oleh pasien pemilik atau dokter pembuat setelah masuk dengan dompetnya."
    )
