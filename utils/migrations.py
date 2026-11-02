"""Migrasi skema ringan dan idempoten (tanpa dependensi tambahan).

create_all() membuat tabel yang belum ada; langkah di bawah menambah kolom ke tabel lama, mengenkripsi data
lama yang masih plaintext, dan mengisi data turunan. Setiap langkah dicatat di schema_migrations.
"""
from __future__ import annotations

import re

from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from models import Base, SchemaMigration
from utils import auth, fieldcrypt

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _cols(conn, table: str) -> set[str]:
    insp = inspect(conn)
    return {c["name"] for c in insp.get_columns(table)} if insp.has_table(table) else set()


def _add(conn, table: str, name: str, ddl: str) -> None:
    if name not in _cols(conn, table):
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def _bool(conn, true: bool) -> str:
    pg = conn.dialect.name == "postgresql"
    return ("TRUE" if true else "FALSE") if pg else ("1" if true else "0")


def _v1_columns(conn) -> None:
    if not inspect(conn).has_table("accounts"):
        return
    ts = "TIMESTAMP"
    for name, ddl in [
        ("email_verified", f"BOOLEAN DEFAULT {_bool(conn, True)}"),   # akun lama dianggap sudah terverifikasi
        ("totp_secret", "TEXT"), ("mfa_enabled", f"BOOLEAN DEFAULT {_bool(conn, False)}"),
        ("totp_last_step", "INTEGER DEFAULT 0"), ("recovery_hashes", "TEXT"),
        ("verification_note", "TEXT"), ("rejection_reason", "TEXT"),
        ("verified_by", "VARCHAR(64)"), ("verified_at", ts),
    ]:
        _add(conn, "accounts", name, ddl)
    if inspect(conn).has_table("medical_records"):
        _add(conn, "medical_records", "amends_id", "VARCHAR(32)")
        _add(conn, "medical_records", "key_version", "INTEGER DEFAULT 1")  # rekam lama memakai stego-key v1


def _v2_seal_existing(conn) -> None:
    """Enkripsi kolom plaintext lama + ubah email_key menjadi blind index."""
    insp = inspect(conn)
    if insp.has_table("accounts"):
        for r in conn.execute(text("SELECT id, email, email_key, full_name, license_no FROM accounts")).mappings():
            key = r["email_key"] if _HEX64.match(r["email_key"] or "") else fieldcrypt.blind_index(
                auth.canonical_email(r["email"] if not fieldcrypt.is_sealed(r["email"]) else fieldcrypt.unseal(r["email"])))
            conn.execute(text("UPDATE accounts SET email=:e, email_key=:k, full_name=:n, license_no=:l WHERE id=:i"), {
                "e": fieldcrypt.seal(r["email"]), "k": key, "n": fieldcrypt.seal(r["full_name"]),
                "l": fieldcrypt.seal(r["license_no"]), "i": r["id"]})
    if insp.has_table("users"):
        for r in conn.execute(text("SELECT id, name, license_no FROM users")).mappings():
            conn.execute(text("UPDATE users SET name=:n, license_no=:l WHERE id=:i"),
                         {"n": fieldcrypt.seal(r["name"]), "l": fieldcrypt.seal(r["license_no"]), "i": r["id"]})
    if insp.has_table("medical_records"):
        for r in conn.execute(text("SELECT id, title, cover_name FROM medical_records")).mappings():
            conn.execute(text("UPDATE medical_records SET title=:t, cover_name=:c WHERE id=:i"),
                         {"t": fieldcrypt.seal(r["title"]), "c": fieldcrypt.seal(r["cover_name"]), "i": r["id"]})
    if conn.dialect.name == "postgresql":  # ciphertext lebih panjang dari VARCHAR lama
        for table, col in [("accounts", "email"), ("accounts", "full_name"), ("accounts", "license_no"),
                           ("users", "name"), ("users", "license_no"),
                           ("medical_records", "title"), ("medical_records", "cover_name")]:
            if col in _cols(conn, table):
                conn.execute(text(f"ALTER TABLE {table} ALTER COLUMN {col} TYPE TEXT"))


def _v3_backfill_recipients(conn) -> None:
    if not inspect(conn).has_table("record_recipients"):
        return
    have = {r[0] for r in conn.execute(text("SELECT DISTINCT record_id FROM record_recipients"))}
    for r in conn.execute(text("SELECT id, patient_address, doctor_address, created_at FROM medical_records")).mappings():
        if r["id"] in have:
            continue
        for addr, role in ((r["patient_address"], "patient"), (r["doctor_address"], "author")):
            conn.execute(text("INSERT INTO record_recipients (record_id, address, role, added_by, added_at) "
                              "VALUES (:r, :a, :ro, :ab, :at)"),
                         {"r": r["id"], "a": addr, "ro": role, "ab": r["doctor_address"], "at": r["created_at"]})


def _v4_consent(conn) -> None:
    if inspect(conn).has_table("accounts"):
        _add(conn, "accounts", "consent_version", "VARCHAR(24)")
        _add(conn, "accounts", "consent_at", "TIMESTAMP")


def _v5_phi_diag_ed(conn) -> None:
    if inspect(conn).has_table("medical_records"):
        _add(conn, "medical_records", "has_phi", f"BOOLEAN DEFAULT {_bool(conn, False)}")
        _add(conn, "medical_records", "phi_bytes", "INTEGER DEFAULT 0")
        _add(conn, "medical_records", "has_diagnosis", f"BOOLEAN DEFAULT {_bool(conn, False)}")
        _add(conn, "medical_records", "diagnosis_bytes", "INTEGER DEFAULT 0")
    if inspect(conn).has_table("users"):
        _add(conn, "users", "ed_pub", "VARCHAR(64)")
        _add(conn, "users", "ed_priv", "TEXT")


def _v6_patient_features(conn) -> None:
    """Tabel fitur pasien: profil kesehatan, resep obat, tracking, janji temu, reminder."""
    for table in ("patient_profiles", "prescription_orders", "health_tracking", "appointments", "medication_reminders"):
        if not inspect(conn).has_table(table):
            conn.execute(text(f"""
                CREATE TABLE {table} (
                    id SERIAL PRIMARY KEY,
                    patient_address VARCHAR(42) NOT NULL,
                    doctor_address VARCHAR(64),
                    record_id VARCHAR(32),
                    medications TEXT,
                    instructions TEXT,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    dispensed_by VARCHAR(64),
                    dispensed_at TIMESTAMP,
                    notes TEXT,
                    appointment_date TIMESTAMP,
                    purpose TEXT,
                    reminder_sent BOOLEAN DEFAULT FALSE,
                    full_name TEXT, nik TEXT, birth_date TIMESTAMP, gender VARCHAR(10), blood_type VARCHAR(5),
                    emergency_contact TEXT, emergency_phone TEXT, allergies TEXT, chronic_diseases TEXT,
                    height_cm INTEGER, weight_kg FLOAT, bmi FLOAT, last_updated TIMESTAMP,
                    tracked_date TIMESTAMP, systolic INTEGER, diastolic INTEGER, heart_rate INTEGER, temperature FLOAT,
                    blood_sugar FLOAT, symptoms TEXT, tracked_at TIMESTAMP,
                    frequency VARCHAR(50), time_of_day TEXT, start_date TIMESTAMP, end_date TIMESTAMP, active BOOLEAN DEFAULT TRUE,
                    last_reminded TIMESTAMP, created_at TIMESTAMP, updated_at TIMESTAMP
                )"""))


def _v7_patient_extended_fields(conn) -> None:
    """Tambah kolom MRN, nomor asuransi, dan alamat lengkap ke patient_profiles."""
    if inspect(conn).has_table("patient_profiles"):
        _add(conn, "patient_profiles", "mrn", "TEXT")  # Nomor rekam medis
        _add(conn, "patient_profiles", "insurance_no", "TEXT")  # Nomor asuransi kesehatan
        _add(conn, "patient_profiles", "address", "TEXT")  # Alamat lengkap


def _v8_ai_label(conn) -> None:
    """Add AI disease classification column."""
    if inspect(conn).has_table("medical_records"):
        _add(conn, "medical_records", "ai_disease_class", "VARCHAR(100)")

MIGRATIONS = [(1, _v1_columns), (2, _v2_seal_existing), (3, _v3_backfill_recipients), (4, _v4_consent), (5, _v5_phi_diag_ed),
              (6, _v6_patient_features), (7, _v7_patient_extended_fields), (8, _v8_ai_label)]


def migrate(engine) -> list[int]:
    """Terapkan migrasi yang belum dijalankan. Return daftar versi yang baru diterapkan."""
    Base.metadata.create_all(engine)
    applied: list[int] = []
    with Session(engine) as s:
        done = set(s.scalars(select(SchemaMigration.version)))
    for version, fn in MIGRATIONS:
        if version in done:
            continue
        with engine.begin() as conn:
            fn(conn)
            conn.execute(text("INSERT INTO schema_migrations (version, applied_at) VALUES (:v, CURRENT_TIMESTAMP)"),
                         {"v": version})
        applied.append(version)
    return applied
