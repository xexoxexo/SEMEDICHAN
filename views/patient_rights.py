"""Hak pasien atas datanya: riwayat akses, ekspor data, dan permintaan hak subjek data."""
from __future__ import annotations

import csv
import io
import json
import zipfile

import pandas as pd
import streamlit as st

from utils import db_helper as db
from utils import fhir, record_service as rs
from utils import web3_utils
from views import ui

ACTION_LABEL = {
    "rekam_dibuat": "Rekam dibuat", "dekripsi": "Rekam dibuka", "dekripsi_ditolak": "Pembukaan ditolak",
    "dekripsi_gagal": "Pembukaan gagal", "integritas_gagal": "Peringatan integritas file", "unduh_stegotext": "Unduh stegotext",
    "unduh_fhir": "Unduh FHIR", "unduh_phi": "Unduh PHI", "unduh_diagnosis": "Unduh diagnosis",
    "akses_dibagikan": "Rekam dibagikan", "akses_dicabut": "Akses rekam dicabut",
    "akses_diminta": "Dokter meminta akses", "akses_disetujui": "Anda menyetujui akses", "akses_ditolak": "Anda menolak akses",
    "akses_diberikan": "Anda memberi akses", "akses_dicabut_dokter": "Anda mencabut akses dokter", "ekspor_data": "Ekspor data",
    "ekstrak_phi": "PHI diekstrak", "ekstrak_diagnosis": "Diagnosis diekstrak", "verifikasi_signature_diagnosis": "Signature diagnosis diverifikasi",
    "kunci_stego_dibuka": "Kunci steganografi dibuka", "dompet_tertaut": "Dompet ditautkan", "verifikasi_hash": "Verifikasi file",
}


def access_history(user) -> None:
    st.header("Riwayat akses")
    ui.note("Daftar aksi pada rekam medis Anda (siapa, kapan, apa) dan aksi dari akun Anda. Catatan dilindungi rantai hash.")
    ids = [r.id for r in db.list_records(patient=user.address)]
    logs = db.list_logs_for_patient(user.address, ids)
    if not logs:
        st.info("Belum ada catatan.")
        return
    names = {u.address: u.name for u in db.list_users()}
    st.dataframe(pd.DataFrame([{
        "Waktu (UTC)": l.ts, "Pelaku": names.get(l.actor, web3_utils.short(l.actor) if l.actor.startswith("0x") else l.actor),
        "Aksi": ACTION_LABEL.get(l.action, l.action), "Rekam": l.target[:8] if l.target in ids else "",
        "Rincian": l.detail[:80],
    } for l in logs]), hide_index=True)


def _build_export(user, account, passphrases: dict[str, str]) -> tuple[bytes, list[str]]:
    buf, skipped = io.BytesIO(), []
    records = db.list_records(patient=user.address)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("akun.json", json.dumps({
            "nama": account.full_name, "email": account.email, "peran": account.role, "dompet": account.wallet_address,
            "terdaftar": account.created_at.isoformat(), "email_terverifikasi": account.email_verified, "mfa": account.mfa_enabled,
        }, ensure_ascii=False, indent=2))
        for r in records:
            tag = r.id[:8]
            path = rs.stego_path(r)
            if path.exists():
                z.writestr(f"stegotext/{tag}.{r.stego_format.lower()}", path.read_bytes())
            pp = passphrases.get(r.id) or None
            if r.has_passphrase and not pp:
                skipped.append(f"{tag} (butuh passphrase)")
                continue
            try:
                rec = rs.open_record(r, user, pp)
            except Exception:  # noqa: BLE001 - satu rekam gagal tidak menggagalkan ekspor lain
                skipped.append(f"{tag} (gagal dibuka)")
                continue
            z.writestr(f"rekam/{tag}.json", json.dumps(rec, ensure_ascii=False, indent=2))
            z.writestr(f"fhir/{tag}_fhir.json", json.dumps(fhir.record_to_bundle(rec, r.id), ensure_ascii=False, indent=2))
            
            # Ekspor PHI terpisah jika ada
            if rec.get("_phi"):
                z.writestr(f"phi/{tag}_phi.json", json.dumps(rec["_phi"], ensure_ascii=False, indent=2))
            
            # Ekspor Diagnosis terpisah jika ada
            if rec.get("_diagnosis"):
                diag_with_sig = {**rec["_diagnosis"], "signature_verified": rec.get("_diagnosis_verified", False)}
                z.writestr(f"diagnosis/{tag}_diagnosis.json", json.dumps(diag_with_sig, ensure_ascii=False, indent=2))
        
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["waktu_utc", "pelaku", "aksi", "target", "rincian"])
        for l in db.list_logs_for_patient(user.address, [r.id for r in records], limit=5000):
            w.writerow([l.ts, l.actor, l.action, l.target, l.detail])
        z.writestr("riwayat_akses.csv", out.getvalue())

        z.writestr("BACA-SAYA.txt",
                   "Ekspor data StegoMed-Web3.\nFile ini berisi data kesehatan TIDAK terenkripsi. Simpan dengan aman.\n"
                   "rekam/: isi rekam medis (JSON); fhir/: format HL7 FHIR R4; phi/: identitas pasien terpisah; "
                   "diagnosis/: diagnosis sensitif & tanda tangan; stegotext/: file citra berisi rekam terenkripsi.\n"
                   + ("Dilewati: " + ", ".join(skipped) + "\n" if skipped else ""))
    return buf.getvalue(), skipped


def export_data(user) -> None:
    st.header("Ekspor data saya")
    ui.note("Unduh salinan seluruh rekam medis Anda (JSON dan FHIR), file stegotext, dan riwayat akses dalam satu berkas ZIP. "
            "Isinya tidak terenkripsi, jadi simpan dengan aman.")
    records = db.list_records(patient=user.address)
    if not records:
        st.info("Belum ada rekam medis.")
        return
    
    st.markdown(f"**Jumlah rekam medis**: {len(records)}")
    st.markdown("---")
    
    # Hilangkan input passphrase per rekam, gunakan sesi login otomatis
    if st.button("Unduh Semua Rekam Medis (ZIP)", key="export_prepare", width="stretch"):
        account = db.get_account(user.account_id)
        # Passphrase kosong: asumsi pasien login dengan dompet, sistem otomatis dekripsi
        passphrases = {}
        data, skipped = _build_export(user, account, passphrases)
        st.session_state["export_zip"] = (data, skipped)
    
    ready = st.session_state.get("export_zip")
    if ready:
        data, skipped = ready
        if skipped:
            st.warning("Tidak ikut diekspor: " + ", ".join(skipped))
        st.download_button("Unduh ekspor (ZIP)", data, file_name="ekspor_data_stegomed.zip", mime="application/zip",
                           key="export_dl", on_click=db.log_event, args=(user.address, "ekspor_data"))


def subject_requests(user) -> None:
    st.header("Permintaan hak data")
    ui.note("Ajukan permintaan akses, koreksi, atau penghapusan data pribadi Anda. Admin akan meninjau dan menjawab. "
            "Permintaan penghapusan rekam medis dapat dibatasi oleh kewajiban penyimpanan yang berlaku bagi fasilitas kesehatan.")
    with st.form("subject_form"):
        kind = st.selectbox("Jenis permintaan", ["akses", "koreksi", "penghapusan"], key="sr_kind")
        detail = st.text_area("Rincian permintaan", key="sr_detail", help="Jelaskan data apa dan alasannya.")
        ok = st.form_submit_button("Kirim permintaan")
    if ok:
        if len(detail.strip()) < 10:
            st.error("Jelaskan permintaan Anda (minimal 10 karakter).")
        elif db.rate_limited(f"subjreq:{user.account_id}", 5, 3600):
            st.error("Terlalu banyak permintaan. Coba lagi nanti.")
        else:
            req = db.create_subject_request(user.account_id, kind, detail)
            db.log_event(user.address, "permintaan_hak_data", f"req:{req.id}", kind)
            st.success("Permintaan terkirim.")
    mine = db.list_subject_requests(account_id=user.account_id)
    if mine:
        st.dataframe(pd.DataFrame([{
            "ID": r.id, "Jenis": r.kind, "Status": r.status, "Diajukan": r.created_at.strftime("%Y-%m-%d %H:%M"),
            "Jawaban admin": r.response or "",
        } for r in mine]), hide_index=True)
