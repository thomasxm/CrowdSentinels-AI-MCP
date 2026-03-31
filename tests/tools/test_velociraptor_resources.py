"""Tests for the Velociraptor guide MCP resource."""

from src.tools.velociraptor_tools import VELOCIRAPTOR_GUIDE


class TestVelociraptorGuideContent:
    """Test the velociraptor-guide resource content."""

    def test_mentions_all_tool_names(self):
        """Guide should reference all 20 Velociraptor tool names."""
        expected_tools = [
            "velociraptor_client_info",
            "velociraptor_pslist",
            "velociraptor_netstat",
            "velociraptor_users",
            "velociraptor_groups",
            "velociraptor_mounts",
            "velociraptor_scheduled_tasks",
            "velociraptor_services",
            "velociraptor_prefetch",
            "velociraptor_shimcache",
            "velociraptor_amcache",
            "velociraptor_userassist",
            "velociraptor_bam",
            "velociraptor_shellbags",
            "velociraptor_recentdocs",
            "velociraptor_evidence_of_download",
            "velociraptor_ntfs_mft",
            "velociraptor_collect_artifact",
            "velociraptor_get_collection_results",
            "velociraptor_list_artifacts",
        ]
        for tool in expected_tools:
            assert tool in VELOCIRAPTOR_GUIDE, f"Missing tool: {tool}"

    def test_includes_decision_tree(self):
        """Guide should contain the SIEM-to-endpoint decision tree."""
        assert "Decision Tree" in VELOCIRAPTOR_GUIDE

    def test_includes_siem_pivot_patterns(self):
        """Guide should describe SIEM pivot patterns."""
        assert "SIEM Pivot Patterns" in VELOCIRAPTOR_GUIDE
        assert "hunt_for_ioc" in VELOCIRAPTOR_GUIDE

    def test_includes_artifact_tables(self):
        """Guide should have categorized artifact reference tables."""
        for category in [
            "Evidence of Execution",
            "Persistence Mechanisms",
            "Live State",
            "User Activity",
            "Filesystem Forensics",
        ]:
            assert category in VELOCIRAPTOR_GUIDE, f"Missing category: {category}"

    def test_includes_prerequisites(self):
        """Guide should mention prerequisites."""
        assert "VELOCIRAPTOR_API_CONFIG" in VELOCIRAPTOR_GUIDE
        assert "api_client.yaml" in VELOCIRAPTOR_GUIDE

    def test_includes_reliability_ratings(self):
        """Execution evidence table should include reliability ratings."""
        assert "High" in VELOCIRAPTOR_GUIDE
        assert "Medium" in VELOCIRAPTOR_GUIDE

    def test_workflow_starts_with_client_info(self):
        """Guide should emphasize starting with client_info."""
        assert "Always Start with velociraptor_client_info" in VELOCIRAPTOR_GUIDE
