"""Skema database (SQLAlchemy 2.0). Kolom bertipe Sealed terenkripsi otomatis (lihat utils/fieldcrypt.py)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from utils.fieldcrypt import Sealed


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Account(Base):
    """Akun login (email + password). Identitas dompet untuk steganografi ada di tabel ``users``."""

    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(Sealed())
    email_key: Mapped[str] = mapped_column(String(254), unique=True, index=True)  # blind index HMAC email kanonik
    full_name: Mapped[str] = mapped_column(Sealed())
    role: Mapped[str] = mapped_column(String(16))  # patient | doctor | admin
    password_hash: Mapped[str] = mapped_column(String(300))
    is_approved: Mapped[bool] = mapped_column(Boolean, default=True)
    license_no: Mapped[str | None] = mapped_column(Sealed(), nullable=True)
    wallet_address: Mapped[str | None] = mapped_column(String(42), unique=True, index=True, nullable=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # verifikasi email & MFA
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret: Mapped[str | None] = mapped_column(Sealed(), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0)
    recovery_hashes: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON daftar SHA-256 kode pemulihan
    # verifikasi dokter oleh admin
    verification_note: Mapped[str | None] = mapped_column(Sealed(), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Sealed(), nullable=True)
    verified_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # persetujuan pemrosesan data (versi pemberitahuan privasi yang disetujui + waktu)
    consent_version: Mapped[str | None] = mapped_column(String(24), nullable=True)
    consent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class User(Base):
    """Identitas dompet (kunci enkripsi X25519) yang dipakai fitur steganografi."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(String(42), unique=True, index=True)
    name: Mapped[str] = mapped_column(Sealed())
    role: Mapped[str] = mapped_column(String(16))  # admin | doctor | patient
    is_approved: Mapped[bool] = mapped_column(Boolean, default=True)
    license_no: Mapped[str | None] = mapped_column(Sealed(), nullable=True)
    enc_pub: Mapped[str] = mapped_column(String(64))  # kunci publik X25519 (hex)
    enc_priv: Mapped[str] = mapped_column(Text)  # kunci privat X25519 terbungkus (hex)
    # Ed25519 untuk tanda tangan digital diagnosis
    ed_pub: Mapped[str | None] = mapped_column(String(64), nullable=True)  # kunci publik Ed25519 (hex, 32 B)
    ed_priv: Mapped[str | None] = mapped_column(Text, nullable=True)  # kunci privat Ed25519 terbungkus (hex)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuthNonce(Base):
    __tablename__ = "auth_nonces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(String(42), index=True)
    nonce: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[float] = mapped_column(Float)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class OtpCode(Base):
    """Kode sekali pakai (verifikasi email / reset password). Hanya hash yang disimpan."""

    __tablename__ = "otp_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(Integer, index=True)
    purpose: Mapped[str] = mapped_column(String(24))  # verify_email | reset_password
    salt: Mapped[str] = mapped_column(String(32))
    code_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[float] = mapped_column(Float)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class RateLimit(Base):
    __tablename__ = "rate_limits"

    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    window_start: Mapped[float] = mapped_column(Float)
    count: Mapped[int] = mapped_column(Integer, default=0)


class MedicalRecord(Base):
    __tablename__ = "medical_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # uuid4 hex
    patient_address: Mapped[str] = mapped_column(String(42), index=True)
    doctor_address: Mapped[str] = mapped_column(String(42), index=True)  # dokter pembuat
    title: Mapped[str] = mapped_column(Sealed())
    stego_file: Mapped[str] = mapped_column(String(80))  # nama file di data/stego/
    stego_format: Mapped[str] = mapped_column(String(8))
    cover_name: Mapped[str] = mapped_column(Sealed())
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    payload_bytes: Mapped[int] = mapped_column(Integer)
    capacity_bytes: Mapped[int] = mapped_column(Integer)
    psnr: Mapped[float | None] = mapped_column(Float, nullable=True)  # None = identik (tak hingga)
    ssim: Mapped[float | None] = mapped_column(Float, nullable=True)
    public_key: Mapped[str | None] = mapped_column(String(66), nullable=True)  # Hex X25519
    wrapped_dek: Mapped[str | None] = mapped_column(Text, nullable=True)      # JSON wrapped DEK per recipient
    has_passphrase: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    amends_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)  # addendum atas rekam lain
    key_version: Mapped[int] = mapped_column(Integer, default=2)  # 1 = stego-key turunan master (lama), 2 = tanpa master
    # PHI (Protected Health Information) tersembunyi
    has_phi: Mapped[bool] = mapped_column(Boolean, default=False)  # apakah rekam ini menyimpan PHI terpisah di stego
    phi_bytes: Mapped[int] = mapped_column(Integer, default=0)  # ukuran payload PHI terenkripsi
    # Diagnosis metadata
    has_diagnosis: Mapped[bool] = mapped_column(Boolean, default=False)  # apakah rekam ini menyimpan diagnosis terpisah
    diagnosis_bytes: Mapped[int] = mapped_column(Integer, default=0)  # ukuran payload diagnosis terenkripsi
    ai_disease_class: Mapped[str | None] = mapped_column(String(100), nullable=True)


class RecordRecipient(Base):
    """Penerima kriptografis sebuah rekam (pasien, penulis, dokter yang diberi akses)."""

    __tablename__ = "record_recipients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    record_id: Mapped[str] = mapped_column(String(32), index=True)
    address: Mapped[str] = mapped_column(String(42), index=True)
    role: Mapped[str] = mapped_column(String(12))  # patient | author | shared
    added_by: Mapped[str] = mapped_column(String(42))
    added_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AccessGrant(Base):
    """Persetujuan pasien kepada dokter (pending -> active -> revoked/denied)."""

    __tablename__ = "access_grants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patient_address: Mapped[str] = mapped_column(String(42), index=True)
    doctor_address: Mapped[str] = mapped_column(String(42), index=True)
    status: Mapped[str] = mapped_column(String(10))  # pending | active | revoked | denied
    requested_by: Mapped[str] = mapped_column(String(10))  # patient | doctor
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SubjectRequest(Base):
    """Permintaan hak subjek data dari pasien (akses, koreksi, penghapusan)."""

    __tablename__ = "subject_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(Integer, index=True)
    kind: Mapped[str] = mapped_column(String(16))  # akses | koreksi | penghapusan
    detail: Mapped[str] = mapped_column(Sealed())
    status: Mapped[str] = mapped_column(String(12), default="baru")  # baru | diproses | selesai | ditolak
    response: Mapped[str | None] = mapped_column(Sealed(), nullable=True)
    handled_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    """Jejak audit berantai-hash (tamper-evident)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(42))
    action: Mapped[str] = mapped_column(String(48), index=True)
    target: Mapped[str] = mapped_column(String(80), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


class SystemMeta(Base):
    __tablename__ = "system_meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class SchemaMigration(Base):
    __tablename__ = "schema_migrations"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# Fitur Pasien - Data Pribadi dan Kesehatan
class PatientProfile(Base):
    """Data profil pribadi pasien (selain rekam medis)"""
    __tablename__ = "patient_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patient_address: Mapped[str] = mapped_column(String(42), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(Sealed())
    mrn: Mapped[str | None] = mapped_column(Sealed(), nullable=True)  # Nomor rekam medis
    nik: Mapped[str | None] = mapped_column(Sealed(), nullable=True)  # NIK/KTP
    insurance_no: Mapped[str | None] = mapped_column(Sealed(), nullable=True)  # Nomor asuransi kesehatan
    birth_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    gender: Mapped[str | None] = mapped_column(String(10), nullable=True)  # Male/Female/Other
    blood_type: Mapped[str | None] = mapped_column(String(5), nullable=True)  # A+/O-/etc
    address: Mapped[str | None] = mapped_column(Sealed(), nullable=True)  # Alamat lengkap
    emergency_contact: Mapped[str | None] = mapped_column(Sealed(), nullable=True)
    emergency_phone: Mapped[str | None] = mapped_column(Sealed(), nullable=True)
    allergies: Mapped[str | None] = mapped_column(Sealed(), nullable=True)  # JSON list
    chronic_diseases: Mapped[str | None] = mapped_column(Sealed(), nullable=True)  # JSON list
    height_cm: Mapped[int | None] = mapped_column(Integer, nullable=True)
    weight_kg: Mapped[float | None] = mapped_column(Float, nullable=True)
    bmi: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_updated: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class PrescriptionOrder(Base):
    """Resep obat dari dokter yang ditunjukkan ke admin custom untuk pemenuhan obat"""
    __tablename__ = "prescription_orders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    record_id: Mapped[str] = mapped_column(String(32), index=True)  # terkait rekam medis
    patient_address: Mapped[str] = mapped_column(String(42), index=True)
    doctor_address: Mapped[str] = mapped_column(String(42), index=True)
    medications: Mapped[str] = mapped_column(Sealed())  # JSON list obat & dosis
    instructions: Mapped[str | None] = mapped_column(Sealed(), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending/approved/dispensed/completed/cancelled
    dispensed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)  # admin custom yang memenuhi
    dispensed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    notes: Mapped[str | None] = mapped_column(Sealed(), nullable=True)  # catatan admin
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class HealthTracking(Base):
    """Tracking kesehatan pasien harian/mingguan (untuk dashboard analisis)"""
    __tablename__ = "health_tracking"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patient_address: Mapped[str] = mapped_column(String(42), index=True)
    tracked_date: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    systolic: Mapped[int | None] = mapped_column(Integer, nullable=True)  # tekanan darah sistolik
    diastolic: Mapped[int | None] = mapped_column(Integer, nullable=True)  # tekanan darah diastolik
    heart_rate: Mapped[int | None] = mapped_column(Integer, nullable=True)  # denyut jantung
    temperature: Mapped[float | None] = mapped_column(Float, nullable=True)  # suhu
    blood_sugar: Mapped[float | None] = mapped_column(Float, nullable=True)  # gula darah (mg/dL)
    symptoms: Mapped[str | None] = mapped_column(Sealed(), nullable=True)  # JSON gejala harian
    notes: Mapped[str | None] = mapped_column(Sealed(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Appointment(Base):
    """Janji temu pasien dengan dokter"""
    __tablename__ = "appointments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patient_address: Mapped[str] = mapped_column(String(42), index=True)
    doctor_address: Mapped[str] = mapped_column(String(42), index=True)
    appointment_date: Mapped[datetime] = mapped_column(DateTime)
    purpose: Mapped[str] = mapped_column(Sealed())
    status: Mapped[str] = mapped_column(String(20), default="scheduled")  # scheduled/completed/cancelled/no-show
    reminder_sent: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str | None] = mapped_column(Sealed(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class MedicationReminder(Base):
    """Reminder minum obat untuk pasien"""
    __tablename__ = "medication_reminders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patient_address: Mapped[str] = mapped_column(String(42), index=True)
    prescription_id: Mapped[int] = mapped_column(Integer, index=True)  # terkait prescription_orders
    medication_name: Mapped[str] = mapped_column(Sealed())
    dosage: Mapped[str] = mapped_column(Sealed())
    frequency: Mapped[str] = mapped_column(String(50))  # daily/twice daily/3x daily/weekly
    time_of_day: Mapped[str] = mapped_column(String(100))  # JSON waktu: ["08:00", "14:00", "20:00"]
    start_date: Mapped[datetime] = mapped_column(DateTime)
    end_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_reminded: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
