import os
import sys
import tempfile
import shutil
from pathlib import Path
import pytest
import unittest.mock as mock

# Isolasi data uji
test_dir = tempfile.mkdtemp(prefix="SeMediChain_test_")
os.environ["DATA_DIR"] = test_dir
os.environ["DATABASE_URL"] = f"sqlite:///{(Path(test_dir) / 'test.db').as_posix()}"
os.environ["APP_ENV"] = "testing"
os.environ["ALLOW_DEV_WALLET"] = "1"
os.environ["AUTO_APPROVE_DOCTORS"] = "1"

# Setelah config diimpor, reload agar env vars aktif
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

@pytest.fixture(scope="session", autouse=True)
def cleanup_test_dir():
    yield
    shutil.rmtree(test_dir, ignore_errors=True)

# Fixture alias untuk pytest-mock compatibility
@pytest.fixture
def patch(mocker):
    """Alias untuk mocker - kompatibilitas test lama."""
    return mocker

@pytest.fixture
def cast(mocker):
    """Alias untuk mocker - kompatibilitas test lama."""
    return mocker
