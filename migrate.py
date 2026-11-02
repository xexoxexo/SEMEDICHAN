#!/usr/bin/env python3
"""Jalankan migrasi database. Caranya: python migrate.py"""

import sys
import os

# Pastikan folder proyek ada di path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    try:
        from utils.db_helper import get_engine
        from utils.migrations import migrate
        
        print("▶ Running migrations...")
        engine = get_engine()
        applied = migrate(engine)
        
        if applied:
            print(f"✓ Applied migrations: {applied}")
            print("✓ Database schema updated.")
        else:
            print("✓ No pending migrations (already up to date).")
        sys.exit(0)
    except Exception as e:
        print(f"✗ Migration failed: {e}", file=sys.stderr)
        sys.exit(1)
