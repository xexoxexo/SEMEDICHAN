"""Portal dokter: pasien saya (persetujuan), rekam medis baru -> enkripsi hybrid -> stegotext, riwayat."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

import pandas as pd
import streamlit as st

import config
from components import steganography as stego
from utils import clinical, crypto_utils, record_service as rs
from utils import db_helper as db
from utils import web3_utils, disease_classifier
from views import records, ui


def _show_last_result() -> None:
    r = st.session_state.get("last_record")
    if not r:
        return
    st.success(f"Rekam medis tersimpan sebagai stegotext. ID {r['id'][:8]}, hash SHA-256 `{r['sha'][:16]}…`")
    c1, c2, c3 = st.columns(3)
    c1.image(r["cover"], caption="Covertext (asli)")
    c2.image(r["stego"], caption="Stegotext")
    c3.image(r["heat"], caption="Peta selisih piksel (diperkuat)")
    ui.show_metrics(r["psnr"], r["ssim"], r["payload"], r["capacity"])
    st.download_button("Unduh stegotext", r["data"], file_name=r["file_name"], mime=r["mime"], key="dl_last_record",
                       on_click=db.log_event, args=(r["actor"], "unduh_stegotext", r["id"]))


# --------------------------------------------------------------------------- pasien saya (persetujuan)
def patients(user) -> None:
    st.header("Pasien saya")
    ui.note("Anda hanya dapat menulis rekam medis untuk pasien yang menyetujui akses. Pasien menyetujui di menu "
            "Akses dokter pada akunnya.")
    with st.form("request_access_form"):
        email = st.text_input("Email pasien (Gmail)", key="req_patient_email")
        go = st.form_submit_button("Minta akses")
    if go:
        if db.rate_limited(f"req:{user.address}", 20, 3600):
            st.error("Terlalu banyak permintaan. Coba lagi nanti.")
        else:
            acct = db.get_account_by_email(email) if email.strip() else None
            if acct is not None and acct.role == "patient" and acct.wallet_address:
                status = db.request_access(user.address, acct.wallet_address)
                db.log_event(user.address, "akses_diminta", acct.wallet_address, status)
            # Respons sama untuk semua kasus: dokter tidak bisa menebak siapa saja yang menjadi pasien terdaftar.
            st.info("Jika pasien terdaftar dan sudah menautkan dompet, permintaan dikirim dan muncul pada daftar di bawah.")
    names = {u.address: u.name for u in db.list_users()}
    grants = db.list_grants(doctor=user.address)
    if not grants:
        st.caption("Belum ada permintaan atau persetujuan.")
        return
    st.dataframe(pd.DataFrame([{
        "Pasien": names.get(g.patient_address, web3_utils.short(g.patient_address)) if g.status == "active"
        else web3_utils.short(g.patient_address),
        "Status": {"pending": "menunggu persetujuan", "active": "aktif", "revoked": "dicabut", "denied": "ditolak"}[g.status],
        "Diperbarui": g.updated_at.strftime("%Y-%m-%d %H:%M"),
    } for g in grants]), hide_index=True)


# --------------------------------------------------------------------------- rekam medis baru
def new_record(user) -> None:
    st.header("Rekam medis baru")
    ui.note("Form RME → enkripsi hybrid (AES-256-GCM + X25519) → penyisipan LSB acak berkunci pada citra medis.")
    granted = db.list_granted_patients(user.address)
    if not granted:
        st.info("Belum ada pasien yang memberi akses. Minta akses lewat menu Pasien saya.")
        _show_last_result()
        return
    options = {f"{p.name} · {web3_utils.short(p.address)}": p for p in granted}
    patient = options[st.selectbox("Pasien", list(options))]
    previous = db.list_records(patient=patient.address, doctor=user.address)
    amend_options = {"(rekam baru)": None, **{f"{r.id[:8]} · {r.title}": r.id for r in previous}}

    with st.form("form_rme"):
        amends = amend_options[st.selectbox("Addendum atas rekam sebelumnya (opsional)", list(amend_options))]
        c1, c2 = st.columns(2)
        visit_date = c1.date_input("Tanggal kunjungan", value=date.today())
        visit_type = c2.selectbox("Jenis kunjungan", ["Rawat jalan", "IGD", "Rawat inap", "Radiologi"])
        title = st.text_input("Judul rekam", placeholder="Contoh: Kontrol batuk berkepanjangan")
        
        # PHI Section (opsional, disembunyikan terpisah)
        st.markdown("---")
        with st.expander("📋 PHI - Protected Health Information (opsional)", expanded=False):
            st.caption("Data identitas pasien disimpan terenkripsi terpisah dengan payload utama.")
            phi_name = st.text_input("Nama lengkap pasien", placeholder="Sesuai KTP")
            p1, p2 = st.columns(2)
            phi_mrn = p1.text_input("Nomor rekam medis", placeholder="RM-123456")
            phi_nik = p2.text_input("NIK (KTP)", placeholder="16 digit")
            p3, p4 = st.columns(2)
            phi_dob = p3.date_input("Tanggal lahir", value=None)
            phi_gender = p4.selectbox("Jenis kelamin", ["", "Laki-laki", "Perempuan"])
            phi_address = st.text_area("Alamat lengkap", placeholder="Jalan, RT/RW, Kelurahan, Kecamatan, Kota")
            phi_phone = st.text_input("Nomor telepon", placeholder="+62...")
        
        st.markdown("---")
        complaint = st.text_area("Keluhan utama")
        v1, v2, v3, v4 = st.columns(4)
        bp = v1.text_input("Tekanan darah", placeholder="120/80")
        temp = v2.number_input("Suhu (°C)", min_value=30.0, max_value=45.0, value=36.5, step=0.1)
        pulse = v3.number_input("Nadi (/mnt)", min_value=20, max_value=250, value=80)
        spo2 = v4.number_input("SpO₂ (%)", min_value=50, max_value=100, value=98)
        diagnosis = st.text_area("Diagnosis")
        
        # Auto-Labeling Preview dari Dataset D-DoPathways
        if diagnosis.strip():
            pred = disease_classifier.predict_disease_class(diagnosis)
            st.caption(f"🤖 Klasifikasi AI Otomatis: **{pred['disease_class']}** (Match: `{pred['matched_disease'] or 'Tidak ada padanan langsung'})`")
        
        icd10 = st.text_input("Kode ICD-10 (pisahkan koma)", placeholder="J20.9, E11")
        allergies = st.text_area("Alergi (satu per baris)")
        meds = st.data_editor(
            pd.DataFrame([{"nama": "", "dosis": "", "frekuensi": "", "durasi": ""}]),
            num_rows="dynamic",
            hide_index=True,
            key="meds_editor",
            column_config={
                "nama": st.column_config.TextColumn("Nama Obat", required=True),
                "dosis": st.column_config.TextColumn("Dosis"),
                "frekuensi": st.column_config.TextColumn("Frekuensi"),
                "durasi": st.column_config.TextColumn("Durasi"),
            }
        )
        prescription = st.text_area("Catatan resep (opsional)")
        history = st.text_area("Riwayat klinis")
        notes = st.text_area("Catatan tambahan")
        
        # Diagnosis Sensitif Section (opsional, terpisah dari rekam utama)
        st.markdown("---")
        with st.expander("🔒 Diagnosis Sensitif & Resep Dosis Tinggi (opsional)", expanded=False):
            st.caption("Diagnosis akhir, riwayat sensitif, atau resep obat dosis tinggi disimpan terenkripsi terpisah dan ditandatangani digital Ed25519.")
            diag_final = st.text_area("Diagnosis akhir (terenkripsi terpisah)", placeholder="Diagnosis final setelah pemeriksaan lengkap")
            diag_history = st.text_area("Riwayat sensitif", placeholder="Riwayat penyakit menular, HIV, gangguan jiwa, dll")
            diag_meds_high = st.data_editor(
                pd.DataFrame([{"obat": "", "dosis": "", "catatan_khusus": ""}]),
                num_rows="dynamic",
                hide_index=True,
                key="diag_meds_editor",
                column_config={
                    "obat": st.column_config.TextColumn("Obat Dosis Tinggi", required=True),
                    "dosis": st.column_config.TextColumn("Dosis"),
                    "catatan_khusus": st.column_config.TextColumn("Catatan Khusus"),
                }
            )
        st.markdown("**Citra medis sebagai covertext**")
        cover_file = st.file_uploader("PNG, BMP, atau JPG (hasil disimpan lossless)", type=["png", "bmp", "jpg", "jpeg"])
        passphrase = st.text_input("Passphrase tambahan (opsional)", type="password",
                                   help="Menjadi faktor tambahan kunci. Tanpa passphrase ini rekam tidak bisa dibuka.")
        out_fmt = st.radio("Format stegotext", ["PNG", "BMP"], horizontal=True)
        submitted = st.form_submit_button("Enkripsi dan sisipkan")

    if submitted:
        codes, icd_error = clinical.parse_icd10(icd10)
        if not diagnosis.strip():
            st.error("Diagnosis wajib diisi.")
        elif icd_error:
            st.error(icd_error)
        elif not db.has_active_grant(patient.address, user.address):      # dicek ulang di server, bukan hanya di UI
            st.error("Persetujuan akses pasien tidak aktif. Minta akses lewat menu Pasien saya.")
        else:
            # Bangun payload lengkap
            payload = {
                "title": title.strip() or f"Pemeriksaan {visit_date:%d-%m-%Y}", "complaint": complaint,
                "diagnosis": diagnosis, "icd10": codes, "allergies": clinical.parse_lines(allergies),
                "medications": clinical.clean_medications(meds.to_dict("records")),
                "prescription": prescription, "history": history, "notes": notes, "amends": amends,
                "visit": {"date": visit_date.isoformat(), "type": visit_type},
                "vitals": {"bp": bp, "temp": float(temp), "pulse": int(pulse), "spo2": int(spo2)},
            }
            
            # Tambah PHI data jika ada
            if phi_name.strip() or phi_nik.strip():
                payload["phi_name"] = phi_name.strip()
                payload["phi_mrn"] = phi_mrn.strip()
                payload["phi_nik"] = phi_nik.strip()
                payload["phi_dob"] = phi_dob.isoformat() if phi_dob else None
                payload["phi_gender"] = phi_gender
                payload["phi_address"] = phi_address.strip()
                payload["phi_phone"] = phi_phone.strip()
            
            # Tambah Diagnosis sensitif jika ada
            if diag_final.strip() or diag_history.strip():
                payload["diag_final"] = diag_final.strip()
                payload["diag_history"] = diag_history.strip()
                payload["diag_meds_high"] = clinical.clean_medications(diag_meds_high.to_dict("records"))
            
            _process(user, patient, payload, cover_file, passphrase or None, out_fmt)
    _show_last_result()


def _process(user, patient, body: dict, cover_file, passphrase, out_fmt: str) -> None:
    try:
        if cover_file is not None:
            cover = stego.load_image(cover_file.getvalue(), config.MAX_COVER_PIXELS)
            cover_name = cover_file.name
        else:
            cover, cover_name = stego.make_sample_cover(512), "citra_sintetis_512.png"
            st.info("Tidak ada citra diunggah, memakai citra sintetis contoh (bukan citra medis asli).")

        # PHI data (jika diisi)
        phi_data = {}
        if body.get("phi_name") or body.get("phi_nik"):
            phi_data = {
                "name": body.get("phi_name", "").strip(),
                "mrn": body.get("phi_mrn", "").strip(),
                "nik": body.get("phi_nik", "").strip(),
                "dob": body.get("phi_dob", ""),
                "gender": body.get("phi_gender", ""),
                "address": body.get("phi_address", "").strip(),
                "phone": body.get("phi_phone", "").strip(),
                "recorded_by": user.address,
                "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        
        # Diagnosis sensitif (jika diisi)
        diag_data = {}
        if body.get("diag_final") or body.get("diag_history"):
            diag_data = {
                "final_diagnosis": body.get("diag_final", "").strip(),
                "sensitive_history": body.get("diag_history", "").strip(),
                "high_dose_meds": body.get("diag_meds_high", []),
                "signed_by": user.address,
                "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        
        # Payload utama (RME standard)
        record = {
            "schema": "SeMediChain", **body,
            "patient": {"name": patient.name, "address": patient.address},
            "doctor": {"name": user.name, "address": user.address, "str": user.license_no},
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        # Hapus field PHI/diagnosis dari payload utama (tidak perlu double)
        for key in ["phi_name", "phi_mrn", "phi_nik", "phi_dob", "phi_gender", "phi_address", "phi_phone",
                    "diag_final", "diag_history", "diag_meds_high"]:
            record.pop(key, None)
        
        # Enkripsi semua komponen
        recipients = [(patient.address, patient.enc_pub), (user.address, user.enc_pub)]
        main_blob = crypto_utils.encrypt_record(record, recipients, passphrase)
        phi_blob = crypto_utils.encrypt_phi(phi_data, recipients, passphrase) if phi_data else None
        diag_blob = crypto_utils.encrypt_diagnosis(diag_data, recipients, passphrase) if diag_data else None
        
        # Tanda tangan diagnosis (Ed25519)
        sig_blob = None
        if diag_blob and user.ed_priv:
            try:
                sig_blob = crypto_utils.sign_diagnosis(diag_blob, user.ed_priv)
            except Exception:
                st.warning("Tanda tangan digital diagnosis gagal (kunci Ed25519 tidak tersedia). Lanjut tanpa signature.")
        
        # Kapasitas stego (termasuk PHI + Diagnosis + Signature)
        phi_len = len(phi_blob) if phi_blob else 0
        diag_len = len(diag_blob) if diag_blob else 0
        sig_len = len(sig_blob) if sig_blob else 0
        capacity = stego.capacity_bytes(cover, phi_len=phi_len, diag_len=diag_len)
        
        if len(main_blob) > capacity:
            st.error(
                f"Data terenkripsi ({len(main_blob):,} B) melebihi kapasitas citra ({capacity:,} B). "
                "Pakai citra lebih besar atau persingkat isian."
            )
            return
        
        record_id = uuid.uuid4().hex
        key = crypto_utils.derive_stego_key_v2(record_id, passphrase)
        stego_arr = stego.embed(cover, main_blob, key, phi_blob, diag_blob, sig_blob)
        data = stego.to_png_bytes(stego_arr) if out_fmt == "PNG" else stego.to_bmp_bytes(stego_arr)
        
        # Verifikasi putar-balik
        extracted_main, extracted_phi, extracted_diag, extracted_sig = stego.extract(stego.load_image(data), key)
        if extracted_main != main_blob:
            st.error("Verifikasi putar-balik gagal; rekam tidak disimpan.")
            return
        
        psnr_v, ssim_v = stego.psnr(cover, stego_arr), stego.ssim(cover, stego_arr)
        sha = stego.sha256_hex(data)
        config.ensure_dirs()
        file_name = f"{record_id}.{out_fmt.lower()}"
        (config.STEGO_DIR / file_name).write_bytes(data)
        
        # Simpan ke database
        db.add_record(
            id=record_id, patient_address=patient.address, doctor_address=user.address, title=body["title"][:200],
            stego_file=file_name, stego_format=out_fmt, cover_name=cover_name[:200], sha256=sha,
            payload_bytes=len(main_blob), capacity_bytes=capacity, amends_id=body.get("amends"), key_version=2,
            psnr=None if psnr_v == float("inf") else psnr_v, ssim=ssim_v, has_passphrase=bool(passphrase),
            has_phi=bool(phi_blob), phi_bytes=phi_len,
            has_diagnosis=bool(diag_blob), diagnosis_bytes=diag_len,
        )
        db.add_recipient(record_id, patient.address, "patient", user.address)
        db.add_recipient(record_id, user.address, "author", user.address)
        db.log_event(user.address, "rekam_dibuat", record_id, f"pasien={patient.address}")
        
        # Log tambahan jika ada PHI/diagnosis
        if phi_blob:
            db.log_event(user.address, "phi_disimpan", record_id, f"size={phi_len}")
        if diag_blob:
            db.log_event(user.address, "diagnosis_disimpan", record_id, f"size={diag_len}")
        if sig_blob:
            db.log_event(user.address, "diagnosis_ditandatangani", record_id)
        
        # Buat resep obat otomatis jika ada medications
        if body.get("medications") and len(body["medications"]) > 0:
            meds_clean = [m for m in body["medications"] if m.get("nama", "").strip()]
            if meds_clean:
                instructions = body.get("prescription", "")
                db.create_prescription_order(
                    record_id=record_id,
                    patient_address=patient.address,
                    doctor_address=user.address,
                    medications=meds_clean,
                    instructions=instructions or None
                )
                db.log_event(user.address, "resep_dibuat", record_id, f"obat={len(meds_clean)}")
        
        st.session_state["last_record"] = {
            "id": record_id, "sha": sha, "cover": cover, "stego": stego_arr, "heat": stego.diff_heatmap(cover, stego_arr),
            "psnr": psnr_v, "ssim": ssim_v, "payload": len(main_blob), "capacity": capacity, "data": data, "actor": user.address,
            "file_name": f"stegotext_{record_id[:8]}.{out_fmt.lower()}", "mime": f"image/{out_fmt.lower()}",
            "has_phi": bool(phi_blob), "phi_bytes": phi_len,
            "has_diagnosis": bool(diag_blob), "diagnosis_bytes": diag_len,
            "has_signature": bool(sig_blob),
        }
    except (stego.StegoError, crypto_utils.MediCryptError) as exc:
        st.error(str(exc))


def history(user) -> None:
    st.header("Riwayat rekam medis")
    records.render(user, "doctor")
