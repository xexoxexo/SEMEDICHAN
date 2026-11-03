"""Alat operasional SeMediChain.

Pemakaian:  python -m tools.manage <perintah> [opsi]
Perintah: check-config, create-admin, reset-mfa, unlock, verify-audit, checkpoint, backup, verify-backup, restore,
          rotate-master
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import io
import json
import os
import sqlite3
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path

import config
from utils import auth, crypto_utils, fieldcrypt
from utils import db_helper as db

CLI = "cli"


def _out(msg: str) -> None:
    print(msg)


def _err(msg: str) -> int:
    print(f"GALAT: {msg}", file=sys.stderr)
    return 1


def cmd_check_config(args) -> int:
    """Periksa konfigurasi produksi dan kecocokan master key."""
    try:
        master = config.master_key()
        fp = fieldcrypt.fingerprint(master)
        _out(f"Master fingerprint aktif: {fp}")
        _out(f"DATABASE_URL={config.DATABASE_URL}")
        _out(f"DATA_DIR={config.DATA_DIR}")
        _out(f"STEGO_DIR={config.STEGO_DIR}")
        if not config.DATABASE_URL:
            return _err("DATABASE_URL kosong.")
        return 0
    except Exception as exc:
        return _err(f"Konfigurasi tidak valid: {exc}")


def cmd_diagnose_key(args) -> int:
    """Diagnose & repair master key inkonsistensi."""
    _out("🔍 Mendiagnosa master key dan database...")
    
    db_path = Path(config.DATA_DIR) / "SeMediChain.db"
    key_path = Path(config.DATA_DIR) / ".master_key"
    
    _out(f"\n📋 Status File:")
    _out(f"  Database ada: {db_path.exists()}")
    _out(f"  Master key file ada: {key_path.exists()}")
    _out(f"  MEDICRYPT_MASTER_KEY env: {'SET' if os.getenv('MEDICRYPT_MASTER_KEY') else 'NOT SET'}")
    
    if not db_path.exists():
        _out("\n✅ Database bersih. Jalankan aplikasi untuk membuat DB baru.")
        return 0
    
    _out(f"\n🔐 Master Keys tersedia:")
    for i, m in enumerate(config.master_keys()):
        fp = fieldcrypt.fingerprint(m)
        _out(f"  [{i}] Fingerprint: {fp}")
    
    try:
        _out("\n🧪 Test dekripsi sample data...")
        from sqlalchemy import text
        engine = db.get_engine()
        with engine.connect() as conn:
            # Coba ambil satu record terenkripsi
            result = conn.execute(text("SELECT id, name FROM users LIMIT 1")).first()
            if result:
                _out(f"  ✅ Dekripsi berhasil. Data konsisten dengan master key aktif.")
                return 0
            else:
                _out(f"  ℹ️  Database kosong.")
                return 0
    except Exception as e:
        _out(f"  ❌ Dekripsi gagal: {str(e)[:100]}")
        _out("\n💡 Solusi:")
        _out("  A. Jika master key lama tersedia:")
        _out("     1. Set: MEDICRYPT_MASTER_KEY_OLD=<old_key>")
        _out("     2. Jalankan: python -m tools.manage rotate-master")
        _out("  B. Jika data lama tidak penting (demo/dev):")
        _out("     1. Hapus: rm data/SeMediChain.db data/.master_key")
        _out("     2. Jalankan ulang aplikasi")
        return 1

def cmd_create_admin(args) -> int:
    password = args.password or os.getenv("ADMIN_PASSWORD") or getpass.getpass("Password admin: ")
    error = auth.validate_email(args.email) or auth.validate_password(password, args.email)
    if error:
        return _err(error)
    db.init_db()
    try:
        acct = db.create_admin_account(args.email, args.name, auth.hash_password(password))
    except ValueError as exc:
        return _err(str(exc))
    db.log_event(CLI, "admin_dibuat_cli", f"acct:{acct.id}")
    _out(f"Admin dibuat (id {acct.id}). MFA akan diminta saat login pertama bila diwajibkan.")
    return 0


def cmd_reset_mfa(args) -> int:
    db.init_db()
    acct = db.get_account_by_email(args.email)
    if acct is None:
        return _err("Akun tidak ditemukan.")
    db.disable_mfa(acct.id)
    db.log_event(CLI, "mfa_direset_cli", f"acct:{acct.id}")
    _out("MFA direset. Pengguna akan diminta mendaftarkan ulang saat login berikutnya (jika diwajibkan).")
    return 0


def cmd_unlock(args) -> int:
    db.init_db()
    acct = db.get_account_by_email(args.email)
    if acct is None:
        return _err("Akun tidak ditemukan.")
    db.reset_login_failures(acct.id)
    db.log_event(CLI, "akun_dibuka_cli", f"acct:{acct.id}")
    _out("Kunci akun dibuka.")
    return 0


# --------------------------------------------------------------------------- audit
def cmd_verify_audit(args) -> int:
    db.init_db()
    ok, bad, total = db.verify_audit_chain()
    _out(f"Rantai audit: {'UTUH' if ok else f'RUSAK mulai entri #{bad}'} ({total} entri)")
    if args.checkpoint:
        cp = json.loads(Path(args.checkpoint).read_text(encoding="utf-8"))
        ok2, msg = db.verify_checkpoint(cp)
        _out(f"Checkpoint: {msg}")
        ok = ok and ok2
    return 0 if ok else 1


def cmd_checkpoint(args) -> int:
    db.init_db()
    Path(args.out).write_text(json.dumps(db.audit_checkpoint(), indent=2), encoding="utf-8")
    _out(f"Checkpoint ditulis ke {args.out}. Simpan di luar server.")
    return 0


# --------------------------------------------------------------------------- backup & restore
def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sqlite_path() -> Path | None:
    url = config.DATABASE_URL
    return Path(url.split("sqlite:///", 1)[1]) if url.startswith("sqlite:///") else None


def _sign_manifest(manifest: dict) -> str:
    return fieldcrypt.blind_index(json.dumps(manifest, sort_keys=True), "backup-manifest")


def cmd_backup(args) -> int:
    db.init_db()
    files: dict[str, bytes] = {}
    sqlite_file = _sqlite_path()
    if sqlite_file:
        mem = sqlite3.connect(":memory:")
        src = sqlite3.connect(str(sqlite_file))
        src.backup(mem)                              # salinan konsisten walau database sedang dipakai
        src.close()
        files["db.sqlite"] = mem.serialize()
        mem.close()
    else:
        _out("Database non-SQLite: jalankan pg_dump terpisah (lihat docs/RUNBOOK-OPERASI.md). Hanya file stego yang dicadangkan di sini.")
    for f in sorted(Path(config.STEGO_DIR).glob("*")):
        if f.is_file() and not f.name.endswith(".tmp"):
            files[f"stego/{f.name}"] = f.read_bytes()
    manifest = {
        "dibuat": datetime.now(timezone.utc).isoformat(timespec="seconds"), "versi": 1,
        "master_fingerprint": fieldcrypt.fingerprint(config.master_key()),
        "files": {n: {"sha256": _sha(b), "bytes": len(b)} for n, b in files.items()},
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out, "w:gz") as tar:
        def add(name: str, data: bytes) -> None:
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), int(time.time())
            tar.addfile(info, io.BytesIO(data))
        for n, b in files.items():
            add(n, b)
        add("manifest.json", json.dumps(manifest, indent=2).encode())
        add("manifest.sig", _sign_manifest(manifest).encode())
    db.log_event(CLI, "backup_dibuat", out.name, f"{len(files)} berkas")
    _out(f"Backup selesai: {out} ({len(files)} berkas). Simpan MEDICRYPT_MASTER_KEY secara terpisah: tanpa kunci, backup tidak dapat dibaca.")
    return 0


def _read_backup(path: str) -> tuple[dict, dict[str, bytes]]:
    with tarfile.open(path, "r:gz") as tar:
        data: dict[str, bytes] = {}
        for member in tar.getmembers():
            if not member.isfile():
                continue
            extracted = tar.extractfile(member)
            if extracted is None:
                raise ValueError(f"Tidak dapat membaca berkas {member.name} pada backup.")
            data[member.name] = extracted.read()
    manifest = json.loads(data["manifest.json"])
    if not any(data["manifest.sig"].decode() == fieldcrypt.blind_index(json.dumps(manifest, sort_keys=True), "backup-manifest", k)
               for k in config.master_keys()):
        raise ValueError("Tanda tangan manifest tidak valid (backup diubah atau berasal dari kunci lain).")
    for name, meta in manifest["files"].items():
        if name not in data or _sha(data[name]) != meta["sha256"]:
            raise ValueError(f"Berkas {name} rusak atau hilang pada backup.")
    return manifest, data


def cmd_verify_backup(args) -> int:
    try:
        manifest, _ = _read_backup(args.file)
    except (ValueError, KeyError, tarfile.TarError, OSError) as exc:
        return _err(str(exc))
    _out(f"Backup VALID: {len(manifest['files'])} berkas, dibuat {manifest['dibuat']}.")
    return 0


def cmd_restore(args) -> int:
    try:
        _, data = _read_backup(args.file)
    except (ValueError, KeyError, tarfile.TarError, OSError) as exc:
        return _err(str(exc))
    target = _sqlite_path()
    if "db.sqlite" in data and target is not None:
        if target.exists() and not args.force:
            return _err(f"{target} sudah ada. Gunakan --force untuk menimpa (buat backup lebih dulu).")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data["db.sqlite"])
    config.ensure_dirs()
    count = 0
    for name, blob in data.items():
        if name.startswith("stego/"):
            dest = Path(config.STEGO_DIR) / Path(name).name
            if dest.exists() and not args.force:
                continue
            dest.write_bytes(blob)
            count += 1
    _out(f"Restore selesai ({count} file stego). Jalankan `python -m tools.manage check-config` untuk memastikan kunci cocok.")
    return 0


# --------------------------------------------------------------------------- rotasi master key
def cmd_rotate_master(args) -> int:
    """Pasang kunci BARU di MEDICRYPT_MASTER_KEY dan kunci LAMA di MEDICRYPT_MASTER_KEY_OLD, lalu jalankan ini."""
    from sqlalchemy.orm.attributes import flag_modified
    from models import Account, MedicalRecord, SubjectRequest, SystemMeta, User

    ring = config.master_keys()
    if len(ring) < 2:
        return _err("Isi MEDICRYPT_MASTER_KEY_OLD dengan kunci lama (dan MEDICRYPT_MASTER_KEY dengan kunci baru).")
    db.get_engine()
    from utils import migrations
    migrations.migrate(db.get_engine())
    sealed_cols = {Account: ["email", "full_name", "license_no", "totp_secret", "verification_note", "rejection_reason"],
                   User: ["name", "license_no"], MedicalRecord: ["title", "cover_name"], SubjectRequest: ["detail", "response"]}
    counts = {"kolom": 0, "kunci_privat": 0, "email_key": 0}
    with db.session_scope() as s:
        for model, cols in sealed_cols.items():
            for row in s.query(model).all():
                for c in cols:
                    if getattr(row, c) is not None:
                        flag_modified(row, c)                      # paksa tulis ulang dengan master key aktif
                        counts["kolom"] += 1
        for acct in s.query(Account).all():
            acct.email_key = fieldcrypt.blind_index(auth.canonical_email(acct.email))
            counts["email_key"] += 1
        for user in s.query(User).all():
            user.enc_priv = crypto_utils.rewrap_private_key(user.address, user.enc_priv)
            counts["kunci_privat"] += 1
        meta = s.get(SystemMeta, "master_fingerprint")
        if meta is None:
            meta = SystemMeta(key="master_fingerprint", value="")
            s.add(meta)
        meta.value = fieldcrypt.fingerprint(config.master_key())
        if args.dry_run:
            s.rollback()
            _out(f"[dry-run] akan memproses: {counts}")
            return 0
    db.log_event(CLI, "master_key_dirotasi", detail=json.dumps(counts))
    _out(f"Rotasi selesai: {counts}.")
    _out("Langkah berikut: hapus MEDICRYPT_MASTER_KEY_OLD setelah backup baru dibuat; buat checkpoint audit baru. "
         "Backup dan checkpoint lama memerlukan kunci lama untuk diverifikasi.")
    return 0


# --------------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tools.manage", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check-config", help="periksa konfigurasi produksi dan kecocokan master key").set_defaults(fn=cmd_check_config)
    sub.add_parser("diagnose-key", help="diagnose & repair master key inkonsistensi").set_defaults(fn=cmd_diagnose_key)
    c = sub.add_parser("create-admin", help="buat akun admin")
    c.add_argument("--email", required=True)
    c.add_argument("--name", required=True)
    c.add_argument("--password")
    c.set_defaults(fn=cmd_create_admin)
    for name, fn, hlp in [("reset-mfa", cmd_reset_mfa, "reset MFA pengguna"), ("unlock", cmd_unlock, "buka kunci akun")]:
        c = sub.add_parser(name, help=hlp)
        c.add_argument("--email", required=True)
        c.set_defaults(fn=fn)
    c = sub.add_parser("verify-audit", help="verifikasi rantai audit (+ checkpoint)")
    c.add_argument("--checkpoint")
    c.set_defaults(fn=cmd_verify_audit)
    c = sub.add_parser("checkpoint", help="tulis checkpoint audit bertanda tangan")
    c.add_argument("--out", required=True)
    c.set_defaults(fn=cmd_checkpoint)
    c = sub.add_parser("backup", help="buat backup terverifikasi (.tar.gz)")
    c.add_argument("--out", required=True)
    c.set_defaults(fn=cmd_backup)
    c = sub.add_parser("verify-backup", help="verifikasi backup")
    c.add_argument("--file", required=True)
    c.set_defaults(fn=cmd_verify_backup)
    c = sub.add_parser("restore", help="pulihkan dari backup")
    c.add_argument("--file", required=True)
    c.add_argument("--force", action="store_true")
    c.set_defaults(fn=cmd_restore)
    c = sub.add_parser("rotate-master", help="rotasi master key (kunci lama di MEDICRYPT_MASTER_KEY_OLD)")
    c.add_argument("--dry-run", action="store_true")
    c.set_defaults(fn=cmd_rotate_master)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
