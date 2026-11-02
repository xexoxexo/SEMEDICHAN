"""Lapisan database: engine, sesi, CRUD, nonce SIWE, dan audit trail berantai-hash."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache

from sqlalchemy import create_engine, delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import config
import logging

from models import (Account, AccessGrant, AuditLog, AuthNonce, MedicalRecord, OtpCode, RateLimit, RecordRecipient,
                    SubjectRequest, SystemMeta, User, PatientProfile, PrescriptionOrder, HealthTracking, Appointment, MedicationReminder)
from models import utcnow
from utils import auth, crypto_utils, fieldcrypt, migrations, web3_utils


@lru_cache(maxsize=1)
def get_engine():
    config.ensure_dirs()
    kwargs = {}
    if config.DATABASE_URL.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(config.DATABASE_URL, pool_pre_ping=True, **kwargs)


def init_db() -> None:
    """Buat/migrasikan skema, lalu pastikan master key cocok dengan data yang sudah ada."""
    migrations.migrate(get_engine())
    check_master_key()


def check_master_key() -> None:
    """Cegah data rusak diam-diam: master key yang salah/berganti tanpa rotasi ditolak saat start."""
    current = fieldcrypt.fingerprint(config.master_key())
    ring = {fieldcrypt.fingerprint(m) for m in config.master_keys()}
    with session_scope() as s:
        row = s.get(SystemMeta, "master_fingerprint")
        if row is None:
            s.add(SystemMeta(key="master_fingerprint", value=current))
            return
        if row.value not in ring:
            raise RuntimeError(
                "MEDICRYPT_MASTER_KEY tidak cocok dengan data yang tersimpan. Pasang kunci yang benar, atau isi "
                "MEDICRYPT_MASTER_KEY_OLD dengan kunci lama lalu jalankan `python -m tools.manage rotate-master`."
            )
        if row.value != current:
            logging.getLogger("stegomed").warning("Master key lama masih dipakai: jalankan rotate-master.")


@contextmanager
def session_scope():
    session = Session(get_engine(), expire_on_commit=False)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# --------------------------------------------------------------------------- identitas dompet (steganografi)
def get_user(address: str) -> User | None:
    with session_scope() as s:
        return s.scalars(select(User).where(User.address == address.lower())).first()


def create_user(address: str, name: str, role: str, license_no: str | None = None) -> User:
    """Buat identitas dompet + pasangan kunci X25519 + Ed25519 (tanda tangan diagnosis). Dipanggil saat akun menautkan dompet."""
    address = address.lower()
    if role not in {"patient", "doctor", "admin", "admin_security", "admin_custom"}:
        raise ValueError("Peran tidak valid.")
    x_pub, x_priv = crypto_utils.generate_user_keypair(address)
    ed_pub, ed_priv = crypto_utils.generate_ed25519_keypair(address)
    user = User(
        address=address, name=name.strip()[:120], role=role, is_approved=True,
        license_no=(license_no or None), enc_pub=x_pub, enc_priv=x_priv,
        ed_pub=ed_pub, ed_priv=ed_priv,
    )
    with session_scope() as s:
        s.add(user)
    return user


def list_users(role: str | None = None) -> list[User]:
    with session_scope() as s:
        q = select(User).order_by(User.created_at.desc())
        if role:
            q = q.where(User.role == role)
        return list(s.scalars(q))


def _ensure_identity(address: str, name: str, role: str, license_no: str | None) -> None:
    existing = get_user(address)
    if existing is None:
        create_user(address, name, role, license_no)
        return
    with session_scope() as s:  # identitas yatim dari versi lama: diadopsi pemilik dompet yang terbukti
        row = s.get(User, existing.id)
        if row is None:
            return
        row.name, row.role, row.license_no, row.is_approved = name[:120], role, license_no, True


# --------------------------------------------------------------------------- akun (email + password)
def get_account(account_id: int) -> Account | None:
    with session_scope() as s:
        return s.get(Account, account_id)


def get_account_by_email(email: str) -> Account | None:
    with session_scope() as s:
        keys = fieldcrypt.blind_indexes(auth.canonical_email(email))
        return s.scalars(select(Account).where(Account.email_key.in_(keys))).first()


def create_account(email: str, full_name: str, role: str, password_hash: str, license_no: str | None = None,
                   consent_version: str | None = None) -> Account:
    if role not in {"patient", "doctor", "admin", "admin_security", "admin_custom"}:
        raise ValueError("Posisi pengguna tidak valid.")
    canonical = auth.canonical_email(email)
    key = fieldcrypt.blind_index(canonical)
    if canonical in auth.admin_email_keys():
        role = "admin"
    acct = Account(
        email=auth.normalize_email(email), email_key=key, full_name=full_name.strip()[:120], role=role,
        password_hash=password_hash, license_no=(license_no or None),
        is_approved=(role != "doctor" or config.AUTO_APPROVE_DOCTORS),
        consent_version=consent_version, consent_at=utcnow() if consent_version else None,
    )
    try:
        with session_scope() as s:
            if s.scalars(select(Account).where(Account.email_key.in_(fieldcrypt.blind_indexes(canonical)))).first():
                raise ValueError("Email sudah terdaftar.")
            s.add(acct)
    except IntegrityError as exc:
        raise ValueError("Email sudah terdaftar.") from exc
    return acct


def create_admin_account(email: str, full_name: str, password_hash: str) -> Account:
    """Buat akun admin langsung (CLI bootstrap): email terverifikasi, disetujui."""
    canonical = auth.canonical_email(email)
    acct = Account(email=auth.normalize_email(email), email_key=fieldcrypt.blind_index(canonical), full_name=full_name.strip()[:120],
                   role="admin", password_hash=password_hash, is_approved=True, email_verified=True)
    try:
        with session_scope() as s:
            if s.scalars(select(Account).where(Account.email_key.in_(fieldcrypt.blind_indexes(canonical)))).first():
                raise ValueError("Email sudah terdaftar.")
            s.add(acct)
    except IntegrityError as exc:
        raise ValueError("Email sudah terdaftar.") from exc
    return acct


def promote_if_admin(account: Account) -> Account:
    """Email yang tercantum di ADMIN_EMAILS selalu berperan admin."""
    if auth.canonical_email(account.email) in auth.admin_email_keys() and account.role != "admin":
        with session_scope() as s:
            row = s.get(Account, account.id)
            if row is None:
                return account
            row.role, row.is_approved = "admin", True
            return row
    return account


def record_login_failure(account_id: int) -> None:
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is None:
            return
        row.failed_attempts += 1
        if row.failed_attempts >= auth.MAX_FAILED:
            row.locked_until = time.time() + auth.LOCK_SECONDS
            row.failed_attempts = 0


def reset_login_failures(account_id: int) -> None:
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is None:
            return
        row.failed_attempts, row.locked_until = 0, 0.0


def list_accounts(role: str | None = None, pending_only: bool = False) -> list[Account]:
    with session_scope() as s:
        q = select(Account).order_by(Account.created_at.desc())
        if role:
            q = q.where(Account.role == role)
        if pending_only:
            q = q.where(Account.is_approved.is_(False))
        return list(s.scalars(q))


def approve_account(account_id: int) -> bool:
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is None:
            return False
        row.is_approved = True
        return True


def link_wallet(account_id: int, address: str) -> None:
    """Tautkan dompet yang SUDAH terbukti dimiliki (tanda tangan terverifikasi) ke akun, dan siapkan kuncinya."""
    address = address.lower()
    with session_scope() as s:
        acct = s.get(Account, account_id)
        if acct is None:
            raise ValueError("Akun tidak ditemukan.")
        if acct.wallet_address and acct.wallet_address != address:
            raise ValueError("Akun ini sudah menautkan dompet lain.")
        taken = s.scalars(select(Account).where(Account.wallet_address == address, Account.id != account_id)).first()
        if taken:
            raise ValueError("Alamat dompet ini sudah tertaut ke akun lain.")
        acct.wallet_address = address
        name = acct.full_name or "Pengguna"
        role = acct.role or "patient"
        license_no = acct.license_no
    _ensure_identity(address, name, role, license_no)


# --------------------------------------------------------------------------- OTP, MFA, password, pembatas laju
def set_password(account_id: int, password_hash: str) -> None:
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is None:
            return
        row.password_hash, row.failed_attempts, row.locked_until = password_hash, 0, 0.0


def mark_email_verified(account_id: int) -> None:
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is not None:
            row.email_verified = True


def issue_otp(account_id: int, purpose: str) -> str:
    """Buat kode 6 digit baru (kode lama dibatalkan). Hanya HMAC-nya yang disimpan."""
    code = f"{secrets.randbelow(10**6):06d}"
    salt = secrets.token_hex(8)
    with session_scope() as s:
        for old in s.scalars(select(OtpCode).where(OtpCode.account_id == account_id, OtpCode.purpose == purpose,
                                                  OtpCode.used.is_(False))):
            old.used = True
        s.add(OtpCode(account_id=account_id, purpose=purpose, salt=salt, expires_at=time.time() + config.OTP_TTL_SECONDS,
                      code_hash=fieldcrypt.blind_index(f"{account_id}|{purpose}|{salt}|{code}", "otp")))
    return code


def check_otp(account_id: int, purpose: str, code: str) -> bool:
    with session_scope() as s:
        row = s.scalars(select(OtpCode).where(OtpCode.account_id == account_id, OtpCode.purpose == purpose,
                                              OtpCode.used.is_(False)).order_by(OtpCode.id.desc())).first()
        if row is None or row.expires_at < time.time() or row.attempts >= config.OTP_MAX_ATTEMPTS:
            return False
        row.attempts += 1
        expected = fieldcrypt.blind_index(f"{account_id}|{purpose}|{row.salt}|{(code or '').strip()}", "otp")
        if hmac.compare_digest(expected, row.code_hash):
            row.used = True
            return True
        return False


def rate_limited(key: str, limit: int, window_seconds: int) -> bool:
    """Catat satu percobaan; True bila sudah melewati batas dalam jendela waktu."""
    now = time.time()
    with session_scope() as s:
        row = s.get(RateLimit, key)
        if row is None:
            s.add(RateLimit(key=key[:120], window_start=now, count=1))
            return False
        if now - row.window_start > window_seconds:
            row.window_start, row.count = now, 1
            return False
        row.count += 1
        return row.count > limit


def _recovery_hash(code: str) -> str:
    """Kode pemulihan berentropi 64-bit: SHA-256 berdomain cukup (tidak bergantung master key, aman saat rotasi)."""
    from utils import totp
    return hashlib.sha256(b"stegomed-recovery|" + totp.normalize_recovery(code).encode()).hexdigest()


def enable_mfa(account_id: int, secret: str, recovery_codes: list[str], last_step: int = 0) -> None:
    hashes = [_recovery_hash(c) for c in recovery_codes]
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is None:
            return
        row.totp_secret, row.mfa_enabled, row.totp_last_step = secret, True, last_step
        row.recovery_hashes = json.dumps(hashes)


def disable_mfa(account_id: int) -> None:
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is None:
            return
        row.totp_secret, row.mfa_enabled, row.totp_last_step, row.recovery_hashes = None, False, 0, None


def set_totp_step(account_id: int, step: int) -> None:
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is not None:
            row.totp_last_step = step


def use_recovery_code(account_id: int, code: str) -> bool:
    """Kode pemulihan sekali pakai."""
    h = _recovery_hash(code)
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is None:
            return False
        stored = json.loads(row.recovery_hashes or "[]")
        for known in stored:
            if hmac.compare_digest(known, h):
                stored.remove(known)
                row.recovery_hashes = json.dumps(stored)
                return True
        return False


# --------------------------------------------------------------------------- challenge SIWE (verifikasi dompet)
def issue_challenge() -> dict:
    """Challenge login tanpa alamat: siap dipakai begitu halaman dimuat (alur MetaMask satu klik).

    Nonce sekali pakai, berlaku NONCE_TTL_SECONDS. Alamat baru diketahui setelah pengguna memilih
    akun, lalu server membangun ulang pesan yang diharapkan dan membandingkannya (consume_challenge).
    """
    issued = int(time.time())
    expires = issued + config.NONCE_TTL_SECONDS
    nonce = web3_utils.new_nonce()
    with session_scope() as s:
        s.add(AuthNonce(address="", nonce=nonce, message="", expires_at=float(expires), used=False))
        s.execute(delete(AuthNonce).where(AuthNonce.expires_at < issued - 3600))  # rapikan nonce lama
    return {
        "nonce": nonce, "issued_ts": issued, "expires_ts": expires,
        "template": web3_utils.siwe_template(nonce, issued, expires),
    }


def consume_challenge(address: str, nonce: str, message: str) -> bool:
    """Pesan harus identik dengan rekonstruksi server untuk (alamat, nonce); nonce sekali pakai."""
    with session_scope() as s:
        row = s.scalars(
            select(AuthNonce).where(AuthNonce.nonce == nonce, AuthNonce.address == "", AuthNonce.used.is_(False))
        ).first()
        if row is None or row.expires_at < time.time():
            return False
        expires = int(row.expires_at)
        expected = web3_utils.build_siwe_message(address, nonce, expires - config.NONCE_TTL_SECONDS, expires)
        if message != expected:
            return False
        s.execute(
            update(AuthNonce).where(AuthNonce.id == row.id, AuthNonce.used.is_(False)).values(used=True)
        )
        return True


# --------------------------------------------------------------------------- rekam medis
def add_record(**fields) -> MedicalRecord:
    rec = MedicalRecord(**fields)
    with session_scope() as s:
        s.add(rec)
    return rec


def get_record(record_id: str) -> MedicalRecord | None:
    with session_scope() as s:
        return s.get(MedicalRecord, record_id)


def find_record_by_hash(sha256: str) -> MedicalRecord | None:
    with session_scope() as s:
        return s.scalars(select(MedicalRecord).where(MedicalRecord.sha256 == sha256)).first()


def list_records(patient: str | None = None, doctor: str | None = None, recipient: str | None = None) -> list[MedicalRecord]:
    with session_scope() as s:
        q = select(MedicalRecord).order_by(MedicalRecord.created_at.desc())
        if patient:
            q = q.where(MedicalRecord.patient_address == patient.lower())
        if doctor:
            q = q.where(MedicalRecord.doctor_address == doctor.lower())
        if recipient:
            q = q.where(MedicalRecord.id.in_(select(RecordRecipient.record_id).where(
                RecordRecipient.address == recipient.lower(), RecordRecipient.removed_at.is_(None))))
        return list(s.scalars(q))


def update_record_file(record_id: str, sha256: str, payload_bytes: int) -> None:
    with session_scope() as s:
        row = s.get(MedicalRecord, record_id)
        if row is None:
            return
        row.sha256, row.payload_bytes = sha256, payload_bytes


# --------------------------------------------------------------------------- penerima rekam & persetujuan akses
def add_recipient(record_id: str, address: str, role: str, added_by: str) -> None:
    address = address.lower()
    with session_scope() as s:
        existing = s.scalars(select(RecordRecipient).where(
            RecordRecipient.record_id == record_id, RecordRecipient.address == address)).first()
        if existing is None:
            s.add(RecordRecipient(record_id=record_id, address=address, role=role, added_by=added_by.lower()))
        elif existing.removed_at is not None:
            existing.removed_at, existing.role, existing.added_by = None, role, added_by.lower()


def remove_recipient(record_id: str, address: str) -> None:
    with session_scope() as s:
        row = s.scalars(select(RecordRecipient).where(
            RecordRecipient.record_id == record_id, RecordRecipient.address == address.lower(),
            RecordRecipient.removed_at.is_(None))).first()
        if row is not None:
            row.removed_at = utcnow()


def list_recipients(record_id: str) -> list[RecordRecipient]:
    with session_scope() as s:
        return list(s.scalars(select(RecordRecipient).where(
            RecordRecipient.record_id == record_id, RecordRecipient.removed_at.is_(None))))


def is_recipient(record_id: str, address: str) -> bool:
    return any(r.address == address.lower() for r in list_recipients(record_id))


def _grant(s, patient: str, doctor: str) -> AccessGrant | None:
    return s.scalars(select(AccessGrant).where(AccessGrant.patient_address == patient.lower(),
                                               AccessGrant.doctor_address == doctor.lower())).first()


def request_access(doctor_address: str, patient_address: str) -> str:
    """Dokter meminta akses. Return status akhir: pending | active."""
    with session_scope() as s:
        g = _grant(s, patient_address, doctor_address)
        if g is None:
            s.add(AccessGrant(patient_address=patient_address.lower(), doctor_address=doctor_address.lower(),
                              status="pending", requested_by="doctor"))
            return "pending"
        if g.status in ("revoked", "denied"):
            g.status, g.requested_by, g.updated_at = "pending", "doctor", utcnow()
        return g.status


def grant_access(patient_address: str, doctor_address: str) -> None:
    with session_scope() as s:
        g = _grant(s, patient_address, doctor_address)
        if g is None:
            s.add(AccessGrant(patient_address=patient_address.lower(), doctor_address=doctor_address.lower(),
                              status="active", requested_by="patient"))
        else:
            g.status, g.updated_at = "active", utcnow()


def respond_access(patient_address: str, doctor_address: str, approve: bool) -> bool:
    with session_scope() as s:
        g = _grant(s, patient_address, doctor_address)
        if g is None or g.status != "pending":
            return False
        g.status, g.updated_at = ("active" if approve else "denied"), utcnow()
        return True


def revoke_access(patient_address: str, doctor_address: str) -> bool:
    with session_scope() as s:
        g = _grant(s, patient_address, doctor_address)
        if g is None or g.status != "active":
            return False
        g.status, g.updated_at = "revoked", utcnow()
        return True


def has_active_grant(patient_address: str, doctor_address: str) -> bool:
    with session_scope() as s:
        g = _grant(s, patient_address, doctor_address)
        return g is not None and g.status == "active"


def list_grants(patient: str | None = None, doctor: str | None = None, status: str | None = None) -> list[AccessGrant]:
    with session_scope() as s:
        q = select(AccessGrant).order_by(AccessGrant.updated_at.desc())
        if patient:
            q = q.where(AccessGrant.patient_address == patient.lower())
        if doctor:
            q = q.where(AccessGrant.doctor_address == doctor.lower())
        if status:
            q = q.where(AccessGrant.status == status)
        return list(s.scalars(q))


def list_granted_patients(doctor_address: str) -> list[User]:
    """Pasien (identitas dompet) yang memberi akses aktif kepada dokter ini."""
    addrs = [g.patient_address for g in list_grants(doctor=doctor_address, status="active")]
    with session_scope() as s:
        return list(s.scalars(select(User).where(User.address.in_(addrs)))) if addrs else []


# --------------------------------------------------------------------------- verifikasi dokter oleh admin
def approve_doctor(account_id: int, admin_actor: str, note: str) -> bool:
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is None or row.role != "doctor":
            return False
        row.is_approved, row.verified_by, row.verified_at = True, admin_actor[:64], utcnow()
        row.verification_note, row.rejection_reason = note, None
        return True


def reject_doctor(account_id: int, admin_actor: str, reason: str) -> bool:
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is None or row.role != "doctor":
            return False
        row.is_approved, row.verified_by, row.verified_at = False, admin_actor[:64], utcnow()
        row.rejection_reason = reason
        return True


def lock_account(account_id: int, lock_until: float | None = None) -> bool:
    """Kunci akun: set failed_attempts tinggi dan locked_until."""
    import time
    if lock_until is None:
        lock_until = time.time() + 86400  # 24 jam
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is None:
            return False
        row.failed_attempts = 999
        row.locked_until = lock_until
        return True


def unlock_account(account_id: int) -> bool:
    """Buka kunci akun."""
    with session_scope() as s:
        row = s.get(Account, account_id)
        if row is None:
            return False
        row.failed_attempts = 0
        row.locked_until = 0.0
        return True


def counts() -> dict:
    with session_scope() as s:
        by_role = dict(s.execute(select(Account.role, func.count()).group_by(Account.role)).all())
        return {
            "patients": by_role.get("patient", 0),
            "doctors": by_role.get("doctor", 0),
            "records": s.scalar(select(func.count()).select_from(MedicalRecord)) or 0,
            "audit": s.scalar(select(func.count()).select_from(AuditLog)) or 0,
        }


# --------------------------------------------------------------------------- audit trail
def _entry_hash(prev: str, ts: str, actor: str, action: str, target: str, detail: str) -> str:
    return hashlib.sha256("|".join([prev, ts, actor, action, target, detail]).encode()).hexdigest()


AUDIT_LOG = logging.getLogger("stegomed.audit")


def log_event(actor: str, action: str, target: str = "", detail: str = "") -> None:
    actor = (actor or "-").lower()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with session_scope() as s:
        last = s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).first()
        prev = last.entry_hash if last else "0" * 64
        entry = AuditLog(
            ts=ts, actor=actor, action=action, target=target, detail=detail, prev_hash=prev,
            entry_hash=_entry_hash(prev, ts, actor, action, target, detail),
        )
        s.add(entry)
        s.flush()
        line = {"id": entry.id, "ts": ts, "actor": actor, "action": action, "target": target,
                "detail": detail, "hash": entry.entry_hash}
    AUDIT_LOG.info(json.dumps(line, ensure_ascii=False))   # salinan di luar database (stdout -> SIEM/penyimpanan terpusat)


def list_logs(limit: int = 500) -> list[AuditLog]:
    with session_scope() as s:
        return list(s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)))


def verify_audit_chain() -> tuple[bool, int | None, int]:
    """Return (valid, id_entri_pertama_yang_rusak, jumlah_entri)."""
    with session_scope() as s:
        prev, total = "0" * 64, 0
        for row in s.scalars(select(AuditLog).order_by(AuditLog.id)):
            total += 1
            expected = _entry_hash(prev, row.ts, row.actor, row.action, row.target, row.detail)
            if row.prev_hash != prev or row.entry_hash != expected:
                return False, row.id, total
            prev = row.entry_hash
        return True, None, total


def audit_checkpoint() -> dict:
    """Checkpoint bertanda tangan HMAC dari kepala rantai audit. Simpan di luar database (mis. penyimpanan WORM):
    pemangkasan atau penulisan ulang rantai setelah checkpoint akan terdeteksi saat verify_checkpoint()."""
    with session_scope() as s:
        head = s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).first()
        count = s.scalar(select(func.count()).select_from(AuditLog)) or 0
    body = {"count": count, "head_id": head.id if head else 0, "head_hash": head.entry_hash if head else "0" * 64,
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    return {**body, "sig": fieldcrypt.blind_index(json.dumps(body, sort_keys=True), "audit-checkpoint")}


def verify_checkpoint(cp: dict) -> tuple[bool, str]:
    try:
        body = {k: cp[k] for k in ("count", "head_id", "head_hash", "ts")}
        sig = cp["sig"]
    except (KeyError, TypeError):
        return False, "Format checkpoint tidak valid."
    if not any(hmac.compare_digest(sig, fieldcrypt.blind_index(json.dumps(body, sort_keys=True), "audit-checkpoint", m))
               for m in config.master_keys()):
        return False, "Tanda tangan checkpoint tidak valid (bukan dari sistem ini atau diubah)."
    ok, bad_id, total = verify_audit_chain()
    if not ok:
        return False, f"Rantai audit rusak mulai entri #{bad_id}."
    if body["head_id"] == 0:
        return True, "Checkpoint kosong; rantai utuh."
    with session_scope() as s:
        row = s.get(AuditLog, body["head_id"])
        if row is None or total < body["count"]:
            return False, f"Entri audit hilang: checkpoint mencatat {body['count']} entri, kini {total}."
        if row.entry_hash != body["head_hash"]:
            return False, f"Entri #{body['head_id']} berbeda dari checkpoint (rantai ditulis ulang)."
    return True, f"Rantai utuh dan konsisten dengan checkpoint ({body['count']} entri saat dibuat, {total} kini)."


def list_logs_for_patient(address: str, record_ids: list[str], limit: int = 500) -> list[AuditLog]:
    """Jejak akses terkait rekam milik pasien: aksi pada rekam-rekam itu, serta aksi pasien sendiri."""
    from sqlalchemy import or_
    with session_scope() as s:
        cond = AuditLog.actor == address.lower()
        if record_ids:
            cond = or_(cond, AuditLog.target.in_(record_ids))
        return list(s.scalars(select(AuditLog).where(cond).order_by(AuditLog.id.desc()).limit(limit)))


# --------------------------------------------------------------------------- fitur pasien: profil, resep, tracking, janji temu, reminder
def get_patient_profile(address: str) -> PatientProfile | None:
    with session_scope() as s:
        return s.scalars(select(PatientProfile).where(PatientProfile.patient_address == address.lower())).first()


def save_patient_profile(patient_address: str, **kwargs) -> PatientProfile:
    """Simpan profil pasien. Terima: full_name, mrn, nik, insurance_no, birth_date, gender, blood_type, address, emergency_contact, emergency_phone, allergies, chronic_diseases, height_cm, weight_kg, bmi."""
    with session_scope() as s:
        p = s.scalars(select(PatientProfile).where(PatientProfile.patient_address == patient_address.lower())).first()
        if p is None:
            p = PatientProfile(patient_address=patient_address.lower(), **kwargs)
            s.add(p)
        else:
            for k, v in kwargs.items():
                setattr(p, k, v)
            p.last_updated = utcnow()
        return p


def get_patient_prescriptions(address: str, status: list[str] | None = None) -> list[PrescriptionOrder]:
    with session_scope() as s:
        q = select(PrescriptionOrder).where(PrescriptionOrder.patient_address == address.lower()).order_by(PrescriptionOrder.created_at.desc())
        if status:
            q = q.where(PrescriptionOrder.status.in_(status))
        return list(s.scalars(q))


def create_prescription_order(record_id: str, patient_address: str, doctor_address: str, medications: list, instructions: str | None = None) -> PrescriptionOrder:
    with session_scope() as s:
        order = PrescriptionOrder(
            record_id=record_id,
            patient_address=patient_address.lower(),
            doctor_address=doctor_address.lower(),
            medications=json.dumps(medications),
            instructions=instructions,
            status="pending"
        )
        s.add(order)
        return order


def update_prescription_status(order_id: int, status: str, actor_address: str, notes: str | None = None) -> bool:
    with session_scope() as s:
        order = s.get(PrescriptionOrder, order_id)
        if order is None:
            return False
        order.status = status
        if status in ("dispensed", "completed"):
            order.dispensed_by = actor_address.lower()
            order.dispensed_at = utcnow()
        if notes:
            order.notes = notes
        order.updated_at = utcnow()
        return True


def get_health_tracking(address: str, days: int = 30) -> list[HealthTracking]:
    from datetime import timedelta
    since = utcnow() - timedelta(days=days)
    with session_scope() as s:
        return list(s.scalars(select(HealthTracking).where(
            HealthTracking.patient_address == address.lower(),
            HealthTracking.tracked_date >= since
        ).order_by(HealthTracking.tracked_date.desc())))


def add_health_tracking(patient_address: str, **kwargs) -> HealthTracking:
    with session_scope() as s:
        t = HealthTracking(patient_address=patient_address.lower(), **kwargs)
        s.add(t)
        return t


def get_appointments(patient_address: str, status: str | None = None, upcoming: bool = False, exclude_status: str | None = None) -> list[Appointment]:
    with session_scope() as s:
        q = select(Appointment).where(Appointment.patient_address == patient_address.lower()).order_by(Appointment.appointment_date.asc())
        if status:
            q = q.where(Appointment.status == status)
        if exclude_status:
            q = q.where(Appointment.status != exclude_status)
        if upcoming:
            q = q.where(Appointment.appointment_date >= utcnow())
        return list(s.scalars(q))


def get_appointments_for_doctor(doctor_address: str, status: str | None = None, upcoming: bool = False, exclude_status: str | None = None) -> list[Appointment]:
    with session_scope() as s:
        q = select(Appointment).where(Appointment.doctor_address == doctor_address.lower()).order_by(Appointment.appointment_date.asc())
        if status:
            q = q.where(Appointment.status == status)
        if exclude_status:
            q = q.where(Appointment.status != exclude_status)
        if upcoming:
            q = q.where(Appointment.appointment_date >= utcnow())
        return list(s.scalars(q))


def create_appointment(patient_address: str, doctor_address: str, appointment_date: datetime, purpose: str) -> Appointment:
    with session_scope() as s:
        apt = Appointment(
            patient_address=patient_address.lower(),
            doctor_address=doctor_address.lower(),
            appointment_date=appointment_date,
            purpose=purpose,
            status="scheduled"
        )
        s.add(apt)
        return apt


def update_appointment_status(apt_id: int, status: str) -> bool:
    with session_scope() as s:
        apt = s.get(Appointment, apt_id)
        if apt is None:
            return False
        apt.status = status
        apt.updated_at = utcnow()
        return True


def get_medication_reminders(patient_address: str, active_only: bool = True) -> list[MedicationReminder]:
    with session_scope() as s:
        q = select(MedicationReminder).where(MedicationReminder.patient_address == patient_address.lower()).order_by(MedicationReminder.created_at.desc())
        if active_only:
            q = q.where(MedicationReminder.active.is_(True))
        return list(s.scalars(q))


def create_medication_reminder(patient_address: str, **kwargs) -> MedicationReminder:
    with session_scope() as s:
        rem = MedicationReminder(patient_address=patient_address.lower(), **kwargs)
        s.add(rem)
        return rem


def deactivate_reminder(rem_id: int) -> bool:
    with session_scope() as s:
        rem = s.get(MedicationReminder, rem_id)
        if rem is None:
            return False
        rem.active = False
        return True


def list_granted_doctors(patient_address: str) -> list[User]:
    """Dokter yang diberi akses oleh pasien ini."""
    addrs = [g.doctor_address for g in list_grants(patient=patient_address, status="active")]
    with session_scope() as s:
        return list(s.scalars(select(User).where(User.address.in_(addrs)))) if addrs else []


def get_user_by_address(address: str) -> User | None:
    return get_user(address)


def get_account_by_wallet(address: str) -> Account | None:
    with session_scope() as s:
        return s.scalars(select(Account).where(Account.wallet_address == address.lower())).first()


# --------------------------------------------------------------------------- hak subjek data
def create_subject_request(account_id: int, kind: str, detail: str) -> SubjectRequest:
    if kind not in {"akses", "koreksi", "penghapusan"}:
        raise ValueError("Jenis permintaan tidak valid.")
    req = SubjectRequest(account_id=account_id, kind=kind, detail=detail.strip()[:2000])
    with session_scope() as s:
        s.add(req)
    return req


def list_subject_requests(account_id: int | None = None, status: str | None = None) -> list[SubjectRequest]:
    with session_scope() as s:
        q = select(SubjectRequest).order_by(SubjectRequest.created_at.desc())
        if account_id is not None:
            q = q.where(SubjectRequest.account_id == account_id)
        if status:
            q = q.where(SubjectRequest.status == status)
        return list(s.scalars(q))


def update_subject_request(request_id: int, status: str, response: str, actor: str) -> bool:
    if status not in {"diproses", "selesai", "ditolak"}:
        raise ValueError("Status tidak valid.")
    with session_scope() as s:
        row = s.get(SubjectRequest, request_id)
        if row is None:
            return False
        row.status, row.response, row.handled_by, row.updated_at = status, response.strip()[:2000], actor[:64], utcnow()
        return True


def get_event_log(record_id: str = "", actor: str = "", action: str = "", limit: int = 100) -> list[AuditLog]:
    """Filter audit log berdasarkan record_id, actor, atau action. Gunakan untuk tracking diagnosis metadata."""
    with session_scope() as s:
        q = select(AuditLog).order_by(AuditLog.id.desc())
        if record_id:
            q = q.where(AuditLog.target == record_id)
        if actor:
            q = q.where(AuditLog.actor == actor.lower())
        if action:
            q = q.where(AuditLog.action == action)
        return list(s.scalars(q.limit(limit)))
