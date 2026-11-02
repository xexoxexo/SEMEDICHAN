"""Lab steganografi: sisipkan/ekstrak payload apa saja, analisis PSNR/SSIM, hex diff (setara HxD)."""
from __future__ import annotations

import os

import pandas as pd
import streamlit as st

import config
from components import steganography as stego
from utils import crypto_utils
from utils import db_helper as db
from views import ui


def _cover_input(prefix: str):
    up = st.file_uploader("Covertext (disarankan BMP; PNG/JPG juga diterima)", type=["bmp", "png", "jpg", "jpeg"],
                          key=f"{prefix}_cover")
    if up is None:
        size = st.select_slider("Ukuran citra sintetis", [256, 512, 768, 1024], 512, key=f"{prefix}_size")
        st.caption("Tanpa unggahan, dipakai citra sintetis mirip rontgen (bukan citra medis asli).")
        return stego.make_sample_cover(size), f"sample_{size}"
    try:
        return stego.load_image(up.getvalue(), config.MAX_COVER_PIXELS), up.name
    except stego.StegoError as exc:
        st.error(str(exc))
        return None


def _embed_tab(user) -> None:
    got = _cover_input("embed")
    if got is None:
        return
    cover, cover_name = got
    st.caption(f"Kapasitas covertext: {stego.capacity_bytes(cover):,} byte ({cover.shape[1]}×{cover.shape[0]}, "
               f"{'RGB' if cover.ndim == 3 else 'grayscale'})")
    kind = st.radio("Payload", ["Teks", "File (audio, gambar, video, dll.)"], horizontal=True)
    if kind == "Teks":
        text = st.text_area("Pesan rahasia", "Pesan rahasia untuk uji stenografi.")
        name, data = "pesan.txt", text.encode("utf-8")
    else:
        up = st.file_uploader("File payload", key="lab_payload")
        name, data = (up.name, up.getvalue()) if up else ("", b"")
    key = st.text_input("Kunci (passphrase)", type="password",
                        help="Diisi: payload dienkripsi AES-256-GCM dan posisi LSB diacak berkunci. Kosong: LSB berurutan tanpa enkripsi.")
    fmt = st.radio("Format stegotext", ["BMP", "PNG"], horizontal=True)

    if st.button("Sisipkan dan analisis"):
        if not data:
            st.error("Payload kosong.")
            return
        try:
            blob = crypto_utils.pack_lab_payload(name, data, key or None)
            stego_arr = stego.embed(cover, blob, crypto_utils.lab_stego_key(key) if key else None)
        except (stego.StegoError, crypto_utils.MediCryptError) as exc:
            st.error(str(exc))
            return
        out = stego.to_bmp_bytes(stego_arr) if fmt == "BMP" else stego.to_png_bytes(stego_arr)
        cover_bmp, stego_bmp = stego.to_bmp_bytes(cover), stego.to_bmp_bytes(stego_arr)
        st.session_state["lab_result"] = {
            "cover": cover, "stego": stego_arr, "heat": stego.diff_heatmap(cover, stego_arr),
            "psnr": stego.psnr(cover, stego_arr), "ssim": stego.ssim(cover, stego_arr),
            "payload": len(blob), "capacity": stego.capacity_bytes(cover), "out": out, "fmt": fmt.lower(),
            "changed": stego.changed_values(cover, stego_arr), "cover_name": cover_name,
            "cover_bmp": cover_bmp, "stego_bmp": stego_bmp, "diff": stego.byte_diffs(cover_bmp, stego_bmp),
            "sha": stego.sha256_hex(out), "cover_sha": stego.sha256_hex(cover_bmp),
        }
        db.log_event(user.address, "lab_sisip", detail=f"payload={len(blob)}B format={fmt}")
    r = st.session_state.get("lab_result")
    if not r:
        return
    st.divider()
    c1, c2, c3 = st.columns(3)
    c1.image(r["cover"], caption="Covertext")
    c2.image(r["stego"], caption="Stegotext")
    c3.image(r["heat"], caption="Peta selisih (diperkuat)")
    ui.show_metrics(r["psnr"], r["ssim"], r["payload"], r["capacity"])
    st.write(f"Nilai piksel berubah: **{r['changed']:,}** · SHA-256 stegotext: `{r['sha'][:24]}…`")
    st.download_button("Unduh stegotext", r["out"], file_name=f"stegotext.{r['fmt']}", mime=f"image/{r['fmt']}",
                       key="lab_dl")
    _hex_section(r)


def _hex_section(r: dict) -> None:
    st.subheader("Analisis hex covertext vs stegotext")
    st.caption("Keduanya dibandingkan dalam format BMP (piksel mentah) sehingga offset sejajar seperti pada HxD.")
    d = r["diff"]
    m1, m2, m3 = st.columns(3)
    m1.metric("Byte berbeda", f"{d['total']:,}")
    m2.metric("Ukuran covertext / stegotext", f"{d['size_a']:,} / {d['size_b']:,} B")
    m3.metric("Offset beda pertama", "—" if d["first_offset"] is None else f"0x{d['first_offset']:08X}")
    if d["rows"]:
        st.dataframe(pd.DataFrame(d["rows"]).head(60), hide_index=True)
    where = st.radio("Lihat dump hex", ["Header file", "Sekitar perbedaan pertama", "Offset manual"], horizontal=True)
    if where == "Header file":
        offset = 0
    elif where == "Sekitar perbedaan pertama":
        offset = max(0, ((d["first_offset"] or 0) // 16) * 16 - 32)
    else:
        offset = int(st.number_input("Offset (desimal)", min_value=0, max_value=max(d["size_a"] - 1, 0), value=0))
    a, b = st.columns(2)
    a.caption("Covertext")
    a.code(stego.hex_dump(r["cover_bmp"], offset, 192), language=None)
    b.caption("Stegotext")
    b.code(stego.hex_dump(r["stego_bmp"], offset, 192), language=None)


def _extract_tab(user) -> None:
    up = st.file_uploader("Stegotext (BMP/PNG)", type=["bmp", "png"], key="lab_extract_file")
    key = st.text_input("Kunci (kosongkan bila saat menyisipkan tidak memakai kunci)", type="password", key="lab_extract_key")
    if up is None or not st.button("Ekstrak"):
        return
    try:
        arr = stego.load_image(up.getvalue(), config.MAX_COVER_PIXELS)
        blob, *_ = stego.extract(arr, crypto_utils.lab_stego_key(key) if key else None)
        name, data, enc = crypto_utils.unpack_lab_payload(blob, key or None)
    except (stego.StegoError, crypto_utils.MediCryptError) as exc:
        st.error(f"{exc} Periksa kunci, atau file bukan hasil Lab ini.")
        return
    db.log_event(user.address, "lab_ekstrak", detail=f"{len(data)}B")
    st.success(f"Berhasil mengekstrak `{name}` ({len(data):,} B){' · terdekripsi AES-256-GCM' if enc else ''}")
    try:
        txt = data.decode("utf-8")
        if name.lower().endswith(".txt") and len(txt) < 20000:
            st.text_area("Isi pesan", txt, disabled=True)
    except UnicodeDecodeError:
        pass
    st.download_button("Unduh hasil ekstraksi", data, file_name=name or "hasil_ekstraksi.bin", key="lab_extract_dl")


def _capacity_tab(user) -> None:
    got = _cover_input("cap")
    if got is None:
        return
    cover, _ = got
    keyed = st.checkbox("LSB acak berkunci", True)
    st.caption("Payload acak (statistik setara data terenkripsi/terkompresi: teks, audio, atau gambar) diuji pada beberapa persentase kapasitas.")
    if not st.button("Jalankan pengujian"):
        return
    cap = stego.capacity_bytes(cover)
    rows, bar = [], st.progress(0.0)
    fractions = [0.01, 0.05, 0.10, 0.25, 0.50, 0.75, 1.0]
    for i, f in enumerate(fractions, 1):
        n = max(1, int(cap * f))
        out = stego.embed(cover, os.urandom(n), b"k" * 32 if keyed else None)
        rows.append({"Kapasitas terpakai (%)": f * 100, "Payload (B)": n,
                     "bit/piksel": round(n * 8 / (cover.shape[0] * cover.shape[1]), 3),
                     "PSNR (dB)": round(stego.psnr(cover, out), 2), "SSIM": round(stego.ssim(cover, out), 6)})
        bar.progress(i / len(fractions))
    db.log_event(user.address, "lab_kapasitas", detail=f"{len(rows)} titik uji")
    df = pd.DataFrame(rows)
    st.dataframe(df, hide_index=True)
    st.line_chart(df.set_index("Kapasitas terpakai (%)")["PSNR (dB)"])
    st.line_chart(df.set_index("Kapasitas terpakai (%)")["SSIM"])
    st.download_button("Unduh CSV", df.to_csv(index=False).encode(), file_name="kapasitas_vs_kualitas.csv", key="cap_csv")


def render(user) -> None:
    st.header("Lab stenografi")
    ui.note("Alat uji untuk laporan: sisipkan payload apa saja, ukur PSNR/SSIM, bandingkan byte seperti HxD, dan uji kapasitas.")
    t1, t2, t3 = st.tabs(["Sisipkan dan analisis", "Ekstrak", "Kapasitas vs kualitas"])
    with t1:
        _embed_tab(user)
    with t2:
        _extract_tab(user)
    with t3:
        _capacity_tab(user)
