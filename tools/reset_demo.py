import os
import sys
from pathlib import Path

# Load env/config
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
import config

def enforce_demo_env():
    if os.getenv("APP_ENV") != "demo":
        print("ERROR: APP_ENV harus 'demo'. Database demo tidak aman untuk lingkungan lain.")
        sys.exit(1)
    if config.DATABASE_URL and "demo.db" not in config.DATABASE_URL:
        print(f"ERROR: DATABASE_URL tidak mengarah ke demo.db. Konfigurasi: {config.DATABASE_URL}")
        sys.exit(1)

def reset_db():
    enforce_demo_env()
    db_path = config.DATA_DIR / "demo.db"
    if db_path.exists():
        os.remove(db_path)
        print("Database demo dihapus.")
    else:
        print("Tidak ada database demo ditemukan.")

if __name__ == "__main__":
    reset_db()
