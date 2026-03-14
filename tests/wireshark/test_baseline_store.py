# tests/wireshark/test_baseline_store.py
"""Tests for baseline storage."""
import pytest
import tempfile
from pathlib import Path


class TestBaselineStore:
    """Test baseline persistence."""

    def test_save_and_load_baseline(self):
        """Should save and load baseline."""
        from src.wireshark.baseline.baseline_store import BaselineStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = BaselineStore(Path(tmpdir))

            baseline = {
                "name": "test_baseline",
                "observed_ports": {"tcp": [80, 443]},
                "observed_ips": ["192.168.1.1"]
            }

            store.save("test_baseline", baseline)
            loaded = store.load("test_baseline")

            assert loaded is not None
            assert loaded["name"] == "test_baseline"
            assert 80 in loaded["observed_ports"]["tcp"]

    def test_list_baselines(self):
        """Should list all saved baselines."""
        from src.wireshark.baseline.baseline_store import BaselineStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = BaselineStore(Path(tmpdir))

            store.save("baseline1", {"name": "baseline1"})
            store.save("baseline2", {"name": "baseline2"})

            baselines = store.list_baselines()

            assert len(baselines) == 2
            assert "baseline1" in baselines
            assert "baseline2" in baselines

    def test_delete_baseline(self):
        """Should delete baseline."""
        from src.wireshark.baseline.baseline_store import BaselineStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = BaselineStore(Path(tmpdir))

            store.save("to_delete", {"name": "to_delete"})
            assert store.load("to_delete") is not None

            store.delete("to_delete")
            assert store.load("to_delete") is None
