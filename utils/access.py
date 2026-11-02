"""Kebijakan akses rekam medis (least privilege)."""
from __future__ import annotations

from utils import db_helper as db


def can_decrypt(user, record) -> bool:
    """Hanya penerima kriptografis aktif (pasien pemilik, dokter pembuat, dokter yang diberi akses). Admin: tidak."""
    if user is None or user.role == "admin" or not getattr(user, "wallet_linked", True):
        return False
    return db.is_recipient(record.id, user.address)


def can_manage_sharing(user, record) -> bool:
    """Hanya pasien pemilik rekam yang boleh membagikan atau mencabut akses."""
    return user is not None and user.role == "patient" and user.address.lower() == record.patient_address.lower()


def can_view_meta(user, record) -> bool:
    return user is not None and (user.role == "admin" or can_decrypt(user, record))
