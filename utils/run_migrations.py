#!/usr/bin/env python3
"""Migration runner: apply pending schema migrations."""

import sys
from utils.db_helper import get_engine
from utils.migrations import migrate

if __name__ == "__main__":
    print("Running migrations...")
    engine = get_engine()
    applied = migrate(engine)
    if applied:
        print(f"Applied migrations: {applied}")
    else:
        print("No pending migrations (already up to date).")
    sys.exit(0)