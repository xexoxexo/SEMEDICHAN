"""Komponen Streamlit dua arah untuk login MetaMask (Sign-In with Ethereum), satu klik.

Frontend statis (tanpa build npm) ada di components/web3_frontend/index.html dan berbicara dengan
Streamlit lewat protokol postMessage. Alur:
  1. Server menerbitkan challenge (nonce + template pesan SIWE) SEBELUM komponen dirender.
  2. Pengguna klik sekali -> komponen meminta akun (tanpa popup bila situs sudah diizinkan), mengisi
     alamat EIP-55 ke template, langsung memanggil personal_sign.
  3. Komponen mengirim {stage: "signed", address, nonce, message, signature} -> Python memverifikasi.
Tidak ada transaksi, tidak ada gas fee.
"""
from __future__ import annotations

from pathlib import Path

import streamlit.components.v1 as components

_FRONTEND = Path(__file__).parent / "web3_frontend"
_component = components.declare_component("metamask_siwe", path=str(_FRONTEND))


def metamask_siwe(template: str, nonce: str, expires_ts: int, key: str | None = None) -> dict | None:
    return _component(template=template, nonce=nonce, expires_ts=expires_ts, key=key, default=None)
