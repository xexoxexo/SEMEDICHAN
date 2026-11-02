import os
import sys
from pathlib import Path
from datetime import datetime, timedelta

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
import config
from utils import db_helper as db
from utils import auth, crypto_utils

from models import Base

def seed():
    if os.getenv("APP_ENV") != "demo":
        print("ERROR: APP_ENV harus 'demo'.")
        sys.exit(1)
        
    print("Seeding database demo...")
    engine = db.get_engine()
    Base.metadata.create_all(engine)
    
    # 1. Admin
    pw_hash = auth.hash_password("admin123")
    db.create_account("sec@example.test", "Admin Security", "admin_security", pw_hash)
    db.create_account("custom@example.test", "Admin Custom", "admin_custom", pw_hash)
    
    # 2. Dokter
    for i in range(1, 4):
        db.create_account(f"dokter{i}@example.test", f"Dokter {i}", "doctor", pw_hash, license_no=f"STR{i}")
        
    # 3. Pasien
    for i in range(1, 6):
        db.create_account(f"pasien{i}@example.test", f"Pasien {i}", "patient", pw_hash)
        
    # 4. Rekam Medis (sintetis)
    # Catatan: Fungsi add_record di db_helper.py melakukan commit
    for i in range(1, 11):
        db.add_record(
            id=f"rec{i:03d}deadbeefdeadbeefdeadbeef",
            patient_address=f"0x000{i}pasien",
            doctor_address="0x0001dokter",
            title=f"Rekam {i}",
            stego_file=f"file{i}.png",
            stego_format="PNG",
            cover_name="demo.png",
            payload_bytes=100,
            capacity_bytes=1000,
            sha256=f"hash{i}"*16
        )
        
    print("Seed selesai.")

if __name__ == "__main__":
    seed()
