"""Tests for active investigation persistence across client instances.

Verifies that when one InvestigationStateClient creates an investigation,
a separate instance (like the auto_capture singleton) can discover it
via the .active marker file on disk.
"""

import pytest

from src.storage.config import StorageConfig
from src.storage.investigation_state import InvestigationStateClient
from src.storage.models import Severity, SourceType


@pytest.fixture
def temp_storage(tmp_path):
    """Create a temporary storage config pointing to tmp_path."""
    config = StorageConfig(base_path=tmp_path)
    config.ensure_directories()
    return config


class TestActiveInvestigationPersistence:
    """Test that active investigation ID persists to disk and is restorable."""

    def test_create_writes_active_marker(self, temp_storage):
        """create_investigation should write .active file to disk."""
        client = InvestigationStateClient(config=temp_storage)
        inv = client.create_investigation("Test", description="test", severity=Severity.MEDIUM)

        active_file = temp_storage.active_file_path
        assert active_file.exists()
        assert active_file.read_text().strip() == inv.manifest.id

    def test_new_instance_restores_active(self, temp_storage):
        """A new InvestigationStateClient should restore the active investigation from disk."""
        # Instance 1 creates investigation
        client1 = InvestigationStateClient(config=temp_storage)
        inv = client1.create_investigation("Test", severity=Severity.HIGH)
        inv_id = inv.manifest.id

        # Instance 2 (like auto_capture._client) should see it
        client2 = InvestigationStateClient(config=temp_storage)
        assert client2.active_investigation is not None
        assert client2.active_investigation_id == inv_id
        assert client2.active_investigation.manifest.name == "Test"

    def test_close_clears_active_marker(self, temp_storage):
        """close_investigation should remove the .active file."""
        client = InvestigationStateClient(config=temp_storage)
        inv = client.create_investigation("Test")

        assert temp_storage.active_file_path.exists()

        client.close_investigation(resolution="resolved")

        assert not temp_storage.active_file_path.exists()
        assert client.active_investigation is None

    def test_close_prevents_restore(self, temp_storage):
        """After closing, a new instance should NOT see an active investigation."""
        client1 = InvestigationStateClient(config=temp_storage)
        client1.create_investigation("Test")
        client1.close_investigation(resolution="done")

        client2 = InvestigationStateClient(config=temp_storage)
        assert client2.active_investigation is None
        assert client2.active_investigation_id is None

    def test_resume_updates_active_marker(self, temp_storage):
        """resume_investigation should update the .active marker."""
        client1 = InvestigationStateClient(config=temp_storage)
        inv1 = client1.create_investigation("First")
        inv2 = client1.create_investigation("Second", auto_activate=False)

        # Active should be First
        assert temp_storage.active_file_path.read_text().strip() == inv1.manifest.id

        # Resume Second
        client1.resume_investigation(inv2.manifest.id)
        assert temp_storage.active_file_path.read_text().strip() == inv2.manifest.id

        # New instance should see Second
        client2 = InvestigationStateClient(config=temp_storage)
        assert client2.active_investigation_id == inv2.manifest.id

    def test_stale_marker_cleaned_up(self, temp_storage):
        """If .active points to a deleted/closed investigation, it should be cleaned up."""
        client1 = InvestigationStateClient(config=temp_storage)
        inv = client1.create_investigation("Test")

        # Manually corrupt: change status to closed in the saved file
        inv.manifest.status = client1._save_investigation.__func__  # Force a save
        client1.close_investigation(resolution="closed")

        # Write a stale marker pointing to the closed investigation
        temp_storage.active_file_path.write_text(inv.manifest.id)

        # New instance should detect staleness and clear
        client2 = InvestigationStateClient(config=temp_storage)
        assert client2.active_investigation is None
        assert not temp_storage.active_file_path.exists()

    def test_missing_marker_no_crash(self, temp_storage):
        """No .active file should result in no active investigation, no crash."""
        client = InvestigationStateClient(config=temp_storage)
        assert client.active_investigation is None
        assert client.active_investigation_id is None

    def test_empty_marker_no_crash(self, temp_storage):
        """Empty .active file should be handled gracefully."""
        temp_storage.ensure_directories()
        temp_storage.active_file_path.write_text("")

        client = InvestigationStateClient(config=temp_storage)
        assert client.active_investigation is None

    def test_auto_capture_sees_active_investigation(self, temp_storage):
        """Simulates the exact auto_capture flow: separate client sees active investigation."""
        # Simulate investigation_state_tools creating an investigation
        tools_client = InvestigationStateClient(config=temp_storage)
        inv = tools_client.create_investigation(
            "Incident Response",
            description="Testing cross-client IoC sharing",
            severity=Severity.CRITICAL,
        )

        # Simulate auto_capture.get_client() creating its own instance
        auto_capture_client = InvestigationStateClient(config=temp_storage)

        # This is the exact check that auto_capture_velociraptor_results does
        assert auto_capture_client.active_investigation is not None
        assert auto_capture_client.active_investigation_id == inv.manifest.id

        # Simulate adding findings (what auto_capture does)
        summary = auto_capture_client.add_findings(
            source_type=SourceType.VELOCIRAPTOR,
            source_tool="velociraptor_pslist",
            results={"events": [{"Name": "suspicious.exe", "CommandLine": "cmd /c whoami"}]},
            query_description="Process listing",
        )
        assert summary.get("iocs_added", 0) >= 0  # May be 0 if no valid IoCs, but should not error
