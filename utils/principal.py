"""Gabungan akun (email) + identitas dompet, dipakai semua tampilan."""
from __future__ import annotations

from dataclasses import dataclass

from utils import db_helper as db


@dataclass
class Principal:
    account_id: int
    email: str
    name: str
    role: str
    address: str            # alamat dompet terverifikasi, atau "acct:<id>" bila belum menautkan dompet
    enc_pub: str | None
    enc_priv: str | None
    license_no: str | None
    is_approved: bool
    wallet_linked: bool


def build_principal(account) -> Principal:
    ident = db.get_user(account.wallet_address) if account.wallet_address else None
    return Principal(
        account_id=account.id, email=account.email, name=account.full_name, role=account.role,
        address=ident.address if ident else f"acct:{account.id}",
        enc_pub=ident.enc_pub if ident else None, enc_priv=ident.enc_priv if ident else None,
        license_no=account.license_no, is_approved=account.is_approved, wallet_linked=ident is not None,
    )
