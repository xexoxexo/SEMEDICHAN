"""Verifikasi dompet Web3: menautkan dompet ke akun dan membuka kunci fitur steganografi.

Fitur steganografi hanya terbuka bila (1) akun punya dompet tertaut dan (2) pemilik dompet menandatangani
pesan SIWE pada sesi ini (berlaku STEGO_UNLOCK_MINUTES). Tanpa itu, rekam medis tidak bisa dibuat maupun dibuka.
"""
from __future__ import annotations

import time

import streamlit as st

import config
from components import web3_auth
from utils import db_helper as db
from utils import web3_utils
from views import ui

UNLOCK_KEY = "stego_unlock"


# --------------------------------------------------------------------------- status kunci
def is_unlocked(address: str) -> bool:
    u = st.session_state.get(UNLOCK_KEY)
    return bool(u and u["address"] == address and u["until"] > time.time())


def wallet_state(user) -> str:
    """no_wallet | locked | open"""
    if not user.wallet_linked:
        return "no_wallet"
    return "open" if is_unlocked(user.address) else "locked"


def _unlock(address: str) -> None:
    st.session_state[UNLOCK_KEY] = {"address": address, "until": time.time() + config.STEGO_UNLOCK_MINUTES * 60}


def lock() -> None:
    st.session_state.pop(UNLOCK_KEY, None)
    ui.clear_decrypted()


# --------------------------------------------------------------------------- bukti kepemilikan dompet
def _challenge() -> dict:
    ch = st.session_state.get("siwe_challenge")
    if not ch or ch["expires_ts"] - time.time() < 30:
        ch = db.issue_challenge()
        st.session_state["siwe_challenge"] = ch
    return ch


def _verify_signed(result: dict) -> tuple[str | None, str | None]:
    address = (result.get("address") or "").lower()
    message, signature, nonce = result.get("message", ""), result.get("signature", ""), result.get("nonce", "")
    if not web3_utils.is_valid_address(address):
        return None, "Alamat dompet tidak valid."
    if not web3_utils.verify_signature(message, signature, address):
        db.log_event(address, "verifikasi_dompet_gagal", detail="tanda tangan tidak cocok")
        return None, "Tanda tangan tidak cocok dengan alamat dompet."
    if not db.consume_challenge(address, nonce, message):
        db.log_event(address, "verifikasi_dompet_gagal", detail="challenge tidak valid/kedaluwarsa/terpakai")
        return None, "Pesan kedaluwarsa, tidak sesuai, atau sudah dipakai. Silakan coba lagi."
    st.session_state.pop("siwe_challenge", None)
    return address, None


def _fail(scope: str, error: str) -> None:
    st.session_state[f"wallet_error_{scope}"] = error
    st.session_state[f"mm_counter_{scope}"] = st.session_state.get(f"mm_counter_{scope}", 0) + 1
    st.session_state.pop("siwe_challenge", None)
    st.rerun()


def _metamask_tab(scope: str) -> str | None:
    st.markdown(
        "Tanda tangani pesan di dompet Anda (MetaMask atau dompet EVM lain). Gratis: tanpa gas fee, "
        "tanpa transaksi, tanpa testnet maupun mainnet."
    )
    ch = _challenge()
    counter = st.session_state.get(f"mm_counter_{scope}", 0)
    result = web3_auth.metamask_siwe(
        template=ch["template"], nonce=ch["nonce"], expires_ts=ch["expires_ts"], key=f"metamask_{scope}_{counter}"
    )
    if not result:
        return None
    if result.get("stage") == "expired":
        _fail(scope, "Pesan kedaluwarsa. Klik tombol sekali lagi.")
    if result.get("stage") == "signed":
        address, error = _verify_signed(result)
        if error:
            _fail(scope, error)
        return address
    return None


def _dev_tab(scope: str) -> str | None:
    st.warning(
        "Mode pengembangan: kunci dompet demo diturunkan dari master key server, hanya untuk uji coba dan "
        "presentasi. Set ALLOW_DEV_WALLET=0 pada produksi."
    )
    preset = st.selectbox("Akun demo", ["pasien-demo", "dokter-demo", "admin-demo", "akun kustom"],
                          key=f"dev_preset_{scope}")
    label = preset if preset != "akun kustom" else st.text_input("Nama akun kustom", "pasien-2", key=f"dev_custom_{scope}")
    if label.strip():
        st.caption("Alamat dompet demo")
        st.code(web3_utils.dev_wallet(label).address, language=None)
    if st.button("Gunakan dompet demo", key=f"dev_btn_{scope}") and label.strip():
        ch = _challenge()
        address = web3_utils.dev_wallet(label).address.lower()
        message = web3_utils.build_siwe_message(address, ch["nonce"], ch["issued_ts"], ch["expires_ts"])
        _, signature = web3_utils.sign_with_dev_wallet(label, message)
        address, error = _verify_signed(
            {"address": address, "nonce": ch["nonce"], "message": message, "signature": signature}
        )
        if error:
            _fail(scope, error)
        return address
    return None


def prove_wallet(scope: str) -> str | None:
    """Tampilkan pilihan verifikasi; return alamat terverifikasi (huruf kecil) setelah tanda tangan sah."""
    error = st.session_state.pop(f"wallet_error_{scope}", None)
    if error:
        st.error(error)
    if config.ALLOW_DEV_WALLET:
        tab_mm, tab_dev = st.tabs(["MetaMask / dompet EVM", "Dompet demo"])
        with tab_mm:
            address = _metamask_tab(scope)
        if address:
            return address
        with tab_dev:
            return _dev_tab(scope)
    return _metamask_tab(scope)


# --------------------------------------------------------------------------- gerbang & halaman
def gate(user) -> None:
    """Halaman penghalang untuk fitur steganografi: tautkan dompet, atau buka kunci dengan tanda tangan."""
    ui.clear_decrypted()
    st.header("Fitur steganografi terkunci")
    if not user.wallet_linked:
        ui.note(
            "Fitur steganografi mewajibkan alamat dompet Web3 (MetaMask atau dompet EVM lain). Tanpa dompet yang "
            "tertaut dan terverifikasi, rekam medis tidak dapat dienkripsi maupun dibuka, sehingga data tidak aman."
        )
        st.subheader("Tautkan dompet Anda")
        scope = "link"
    else:
        ui.note(
            f"Dompet tertaut: <code>{web3_utils.short(user.address)}</code>. Tanda tangani pesan dengan dompet yang "
            f"sama untuk membuka fitur selama {config.STEGO_UNLOCK_MINUTES} menit."
        )
        st.subheader("Buka kunci dengan dompet")
        scope = "unlock"

    address = prove_wallet(scope)
    if not address:
        return
    if scope == "link":
        try:
            db.link_wallet(user.account_id, address)
        except ValueError as exc:
            _fail(scope, str(exc))
        db.log_event(address, "dompet_tertaut", f"acct:{user.account_id}")
    elif address != user.address:
        db.log_event(user.address, "buka_kunci_gagal", detail=f"dompet berbeda: {address}")
        _fail(scope, f"Dompet yang dipakai ({web3_utils.short(address)}) berbeda dari dompet tertaut "
                     f"({web3_utils.short(user.address)}).")
    _unlock(address)
    db.log_event(address, "kunci_stego_dibuka")
    st.rerun()


def render_page(user) -> None:
    if wallet_state(user) != "open":
        gate(user)
        return
    st.header("Dompet dan kunci steganografi")
    until = st.session_state[UNLOCK_KEY]["until"]
    st.success(f"Kunci steganografi terbuka sampai {time.strftime('%H:%M', time.localtime(until))}.")
    st.markdown("Dompet tertaut")
    st.code(user.address, language=None)
    ui.note("Dompet ini adalah identitas kunci enkripsi rekam medis Anda dan tidak dapat diganti. "
            "Kunci akan terkunci otomatis setelah waktu habis atau saat Anda keluar.")
    if st.button("Kunci sekarang", key="lock_now"):
        lock()
        db.log_event(user.address, "kunci_stego_dikunci")
        st.rerun()
