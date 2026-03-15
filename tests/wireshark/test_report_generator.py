# tests/wireshark/test_report_generator.py
"""Tests for NCSC-style report generator."""
from datetime import datetime


class TestReportGenerator:
    """Test NCSC-style report generation."""

    def test_create_report_with_basic_findings(self):
        """Should create report with basic findings."""
        from src.wireshark.reporting.report_generator import ReportGenerator

        generator = ReportGenerator()

        findings = {
            "beaconing": [
                {"src_ip": "192.168.1.100", "dst_ip": "203.0.113.42", "confidence": "high"}
            ],
            "anomalies": [
                {"type": "unusual_port", "port": 4444, "count": 10}
            ]
        }

        report = generator.generate_report(
            pcap_path="/tmp/test.pcap",
            findings=findings,
            investigation_id="INV-20241228-143052"
        )

        assert "INV-20241228-143052" in report
        assert "Executive Summary" in report
        assert "IDENTIFY" in report
        assert "PROTECT" in report
        assert "DETECT" in report
        assert "RESPOND" in report
        assert "RECOVER" in report

    def test_generate_executive_summary(self):
        """Should generate executive summary section."""
        from src.wireshark.reporting.report_generator import ReportGenerator

        generator = ReportGenerator()

        findings = {
            "beaconing": [{"src_ip": "192.168.1.100", "confidence": "high"}],
            "anomalies": [],
            "iocs": [{"type": "ip", "value": "203.0.113.42"}]
        }

        summary = generator.generate_executive_summary(findings)

        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_generate_ioc_table(self):
        """Should generate IoC table in markdown format."""
        from src.wireshark.reporting.report_generator import ReportGenerator

        generator = ReportGenerator()

        iocs = [
            {"type": "ip", "value": "203.0.113.42", "confidence": 8, "first_seen": "2024-12-28T14:30:52"},
            {"type": "domain", "value": "malicious.example.com", "confidence": 7, "first_seen": "2024-12-28T14:31:00"},
        ]

        table = generator.generate_ioc_table(iocs)

        assert "| Type" in table
        assert "| Value" in table
        assert "203.0.113.42" in table
        assert "malicious.example.com" in table

    def test_generate_affected_assets_section(self):
        """Should generate affected assets section."""
        from src.wireshark.reporting.report_generator import ReportGenerator

        generator = ReportGenerator()

        assets = [
            {"ip": "192.168.1.100", "hostname": "WORKSTATION-01", "role": "source"},
            {"ip": "192.168.1.50", "hostname": "SERVER-01", "role": "target"},
        ]

        section = generator.generate_affected_assets(assets)

        assert "192.168.1.100" in section
        assert "WORKSTATION-01" in section

    def test_generate_recommendations(self):
        """Should generate recommended actions."""
        from src.wireshark.reporting.report_generator import ReportGenerator

        generator = ReportGenerator()

        findings = {
            "beaconing": [{"src_ip": "192.168.1.100", "dst_ip": "203.0.113.42"}],
            "lateral_movement": [{"movement_type": "psexec_pattern"}]
        }

        recommendations = generator.generate_recommendations(findings)

        assert isinstance(recommendations, list)
        assert len(recommendations) > 0

    def test_format_timestamp(self):
        """Should format timestamps consistently."""
        from src.wireshark.reporting.report_generator import ReportGenerator

        generator = ReportGenerator()

        dt = datetime(2024, 12, 28, 14, 30, 52)
        formatted = generator.format_timestamp(dt)

        assert "2024-12-28" in formatted
        assert "14:30:52" in formatted

    def test_generate_containment_steps(self):
        """Should generate containment steps based on findings."""
        from src.wireshark.reporting.report_generator import ReportGenerator

        generator = ReportGenerator()

        findings = {
            "beaconing": [{"dst_ip": "203.0.113.42"}],
            "lateral_movement": [{"dst_ip": "192.168.1.50"}]
        }

        steps = generator.generate_containment_steps(findings)

        assert isinstance(steps, list)
        assert len(steps) > 0

    def test_export_to_json(self):
        """Should export report data as JSON."""
        from src.wireshark.reporting.report_generator import ReportGenerator

        generator = ReportGenerator()

        findings = {
            "beaconing": [{"src_ip": "192.168.1.100"}],
            "iocs": [{"type": "ip", "value": "203.0.113.42"}]
        }

        json_export = generator.export_to_json(
            investigation_id="INV-20241228-143052",
            findings=findings
        )

        assert "investigation_id" in json_export
        assert "iocs" in json_export


class TestTimelineVisualizer:
    """Test ASCII timeline visualization."""

    def test_generate_beaconing_timeline(self):
        """Should generate ASCII beaconing timeline."""
        from src.wireshark.reporting.timeline_visualizer import TimelineVisualizer

        visualizer = TimelineVisualizer()

        beacon_events = [
            {"timestamp": 1735400000, "src_ip": "192.168.1.100", "dst_ip": "203.0.113.42"},
            {"timestamp": 1735400060, "src_ip": "192.168.1.100", "dst_ip": "203.0.113.42"},
            {"timestamp": 1735400120, "src_ip": "192.168.1.100", "dst_ip": "203.0.113.42"},
        ]

        timeline = visualizer.generate_beaconing_timeline(beacon_events, "203.0.113.42")

        assert "203.0.113.42" in timeline
        assert "●" in timeline or "-" in timeline  # Event markers

    def test_generate_volume_chart(self):
        """Should generate volume over time chart."""
        from src.wireshark.reporting.timeline_visualizer import TimelineVisualizer

        visualizer = TimelineVisualizer()

        volume_data = [
            {"hour": "00:00", "bytes": 1200000000},
            {"hour": "01:00", "bytes": 600000000},
            {"hour": "02:00", "bytes": 300000000},
        ]

        chart = visualizer.generate_volume_chart(volume_data)

        assert "00:00" in chart
        assert "█" in chart  # Volume bars

    def test_generate_connection_timeline(self):
        """Should generate connection timeline."""
        from src.wireshark.reporting.timeline_visualizer import TimelineVisualizer

        visualizer = TimelineVisualizer()

        connections = [
            {"timestamp": 1735400000, "src_ip": "192.168.1.100", "dst_ip": "192.168.1.50", "event": "smb_connect"},
            {"timestamp": 1735400010, "src_ip": "192.168.1.100", "dst_ip": "192.168.1.51", "event": "smb_connect"},
        ]

        timeline = visualizer.generate_connection_timeline(connections)

        assert "192.168.1.100" in timeline

    def test_format_bytes(self):
        """Should format bytes in human-readable format."""
        from src.wireshark.reporting.timeline_visualizer import TimelineVisualizer

        visualizer = TimelineVisualizer()

        assert visualizer.format_bytes(1024) == "1.0 KB"
        assert visualizer.format_bytes(1048576) == "1.0 MB"
        assert visualizer.format_bytes(1073741824) == "1.0 GB"

    def test_generate_attack_stage_timeline(self):
        """Should generate kill chain stage timeline."""
        from src.wireshark.reporting.timeline_visualizer import TimelineVisualizer

        visualizer = TimelineVisualizer()

        events = [
            {"timestamp": 1735400000, "stage": "reconnaissance", "description": "Port scan"},
            {"timestamp": 1735400100, "stage": "delivery", "description": "Phishing email"},
            {"timestamp": 1735400200, "stage": "installation", "description": "Malware install"},
        ]

        timeline = visualizer.generate_attack_stage_timeline(events)

        assert "RECON" in timeline or "recon" in timeline.lower()
        assert "DELIVER" in timeline or "deliver" in timeline.lower()

