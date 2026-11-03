"""Smoke test dengan Streamlit AppTest untuk membuka halaman utama setiap peran tanpa crash."""
import pytest
from streamlit.testing.v1 import AppTest
from unittest.mock import patch


def mock_user(address, role):
    """Mock User object dengan atribut minimal."""
    class MockUser:
        address: str
        role: str

    u = MockUser()
    u.address = address
    u.role = role
    return u


@pytest.mark.skipif(True, reason="Memerlukan database terinisialisasi")
def test_login_page():
    """Halaman login."""
    at = AppTest.from_file("app.py")
    at.run()
    assert "SeMediChain" in getattr(at.get("title")[0], "value", "")
    assert len(at.tabs) == 3  # Masuk, Daftar, Lupa password


@pytest.mark.skipif(True, reason="Memerlukan autentikasi lengkap")
def test_patient_dashboard():
    """Halaman dashboard pasien."""
    at = AppTest.from_file("app.py")
    with patch("app.st.session_state") as mock_sess:
        mock_sess.get = lambda k: mock_user("0x" + "a" * 40, "patient") if k == "user" else None
        at.run()
        assert "Beranda" in getattr(at.get("header")[0], "value", "")


@pytest.mark.skipif(True, reason="Memerlukan autentikasi lengkap")
def test_doctor_dashboard():
    """Halaman dashboard dokter."""
    at = AppTest.from_file("app.py")
    with patch("app.st.session_state") as mock_sess:
        mock_sess.get = lambda k: mock_user("0x" + "b" * 40, "doctor") if k == "user" else None
        at.run()
        assert "Pasien saya" in getattr(at.get("header")[0], "value", "")


@pytest.mark.skipif(True, reason="Memerlukan autentikasi lengkap")
def test_admin_dashboard():
    """Halaman dashboard admin."""
    at = AppTest.from_file("app.py")
    with patch("app.st.session_state") as mock_sess:
        mock_sess.get = lambda k: mock_user("0x" + "c" * 40, "admin") if k == "user" else None
        at.run()
        assert "Verifikasi dokter" in getattr(at.get("header")[0], "value", "")


if __name__ == "__main__":
    # Run dengan pytest
    pytest.main([__file__, "-v", "--tb=short"])