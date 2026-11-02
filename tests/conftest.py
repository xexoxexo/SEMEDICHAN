import os
import sys
import tempfile
import shutil
from pathlib import Path
import pytest
from unittest.mock import MagicMock

# Isolasi data uji
test_dir = tempfile.mkdtemp(prefix="stegomed_test_")
os.environ["DATA_DIR"] = test_dir
os.environ["DATABASE_URL"] = f"sqlite:///{(Path(test_dir) / 'test.db').as_posix()}"
os.environ["APP_ENV"] = "testing"
os.environ["ALLOW_DEV_WALLET"] = "1"
os.environ["AUTO_APPROVE_DOCTORS"] = "1"

# Injeksi mock global untuk mempercepat test UI
import sys
from unittest.mock import MagicMock

# Mock berat di level modul agar tidak terinisialisasi
sys.modules["utils.crypto_utils"] = MagicMock()
sys.modules["utils.fieldcrypt"] = MagicMock()
sys.modules["utils.disease_classifier"] = MagicMock()
sys.modules["utils.web3_utils"] = MagicMock()

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

@pytest.fixture(scope="session", autouse=True)
def cleanup_test_dir():
    yield
    shutil.rmtree(test_dir, ignore_errors=True)
