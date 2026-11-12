"""Shared test settings."""
import pytest


@pytest.fixture(autouse=True)
def _no_real_encryption(monkeypatch):
    """Tests never mount real encrypted folders (on the Pi gocryptfs is installed). tests/test_vault.py
    swaps in its own backends, and its gocryptfs test asks for the real one explicitly."""
    monkeypatch.setenv("FAMILYBOX_ENCRYPT", "off")
