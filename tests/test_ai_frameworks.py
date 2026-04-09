"""Tests for Tier 0 AI Governance frameworks."""

import pytest
from security_controls_mcp.data_loader import SCFData


@pytest.fixture(scope="module")
def scf_data():
    """Load SCF data once for all tests."""
    return SCFData()


class TestAIGovernanceFrameworks:
    """Test AI governance frameworks (Tier 0)."""

    TIER0_FRAMEWORKS = [
        ("iso_42001_2023", "ISO 42001 2023", 100),
        ("nist_ai_100_1_(ai_rmf)_1.0", "NIST AI 100-1 (AI RMF) 1.0", 100),
        ("nist_ai_600_1", "NIST AI 600-1", 100),
        ("emea_eu_ai_act", "EMEA EU AI Act", 50),
        ("emea_eu_cyber_resiliency_act", "EMEA EU Cyber Resiliency Act", 10),
    ]

    @pytest.mark.parametrize("fw_id,fw_name,min_controls", TIER0_FRAMEWORKS)
    def test_ai_framework_exists(self, scf_data, fw_id, fw_name, min_controls):
        """Verify AI framework exists in data."""
        assert fw_id in scf_data.frameworks, f"{fw_id} not found"

    @pytest.mark.parametrize("fw_id,fw_name,min_controls", TIER0_FRAMEWORKS)
    def test_ai_framework_has_minimum_controls(self, scf_data, fw_id, fw_name, min_controls):
        """Verify AI framework has minimum expected controls."""
        fw = scf_data.frameworks[fw_id]
        assert fw["controls_mapped"] >= min_controls, (
            f"{fw_id} has {fw['controls_mapped']} controls, expected >= {min_controls}"
        )

    @pytest.mark.parametrize("fw_id,fw_name,min_controls", TIER0_FRAMEWORKS)
    def test_ai_framework_has_correct_name(self, scf_data, fw_id, fw_name, min_controls):
        """Verify AI framework has correct display name."""
        fw = scf_data.frameworks[fw_id]
        assert fw["name"] == fw_name

    def test_iso_42001_to_nist_ai_rmf_mapping(self, scf_data):
        """Test mapping between ISO 42001 and NIST AI RMF."""
        mappings = scf_data.map_frameworks("iso_42001_2023", "nist_ai_100_1_(ai_rmf)_1.0")
        assert len(mappings) > 50, "Expected significant overlap between ISO 42001 and NIST AI RMF"

        # At least some mappings should have target controls
        has_target = [m for m in mappings if m["target_controls"]]
        assert len(has_target) > 10, "Expected some controls to map to NIST AI RMF"

    def test_eu_ai_act_has_article_references(self, scf_data):
        """Test EU AI Act mappings include article references."""
        controls = scf_data.get_framework_controls("emea_eu_ai_act")
        assert len(controls) > 0

        # Sample control should have EU AI Act clause IDs
        sample = controls[0]
        assert sample["framework_control_ids"], "Expected EU AI Act control IDs"

    def test_search_ai_controls(self, scf_data):
        """Test searching for AI-related controls."""
        results = scf_data.search_controls("artificial intelligence", limit=20)
        assert len(results) > 0, "Expected AI-related controls in search results"

    def test_ai_frameworks_in_categories(self, scf_data):
        """Test AI frameworks are in the ai_governance category."""
        assert "ai_governance" in scf_data.framework_categories
        ai_category = scf_data.framework_categories["ai_governance"]
        assert "iso_42001_2023" in ai_category
        assert "nist_ai_100_1_(ai_rmf)_1.0" in ai_category
        assert "emea_eu_ai_act" in ai_category


class TestNewFrameworkCoverage:
    """Test coverage of frameworks in SCF 2026.1."""

    def test_total_framework_count(self, scf_data):
        """Verify we have 249 frameworks from SCF 2026.1."""
        assert len(scf_data.frameworks) == 249, (
            f"Expected 249 frameworks, got {len(scf_data.frameworks)}"
        )

    def test_cloud_security_frameworks(self, scf_data):
        """Test cloud security frameworks exist."""
        cloud_frameworks = [
            "iso_27017_2015",
            "iso_27018_2025",
            "csa_ccm_4.1.0",
            "emea_germany_c5_2020",
        ]
        for fw_id in cloud_frameworks:
            assert fw_id in scf_data.frameworks, f"Cloud framework {fw_id} not found"

    def test_industrial_ot_frameworks(self, scf_data):
        """Test industrial/OT frameworks exist."""
        ot_frameworks = [
            "iec_62443_4_2_2019",
            "us_nerc_cip_2024",
            "nist_800_82_r3_moderate_ot_overlay",
        ]
        for fw_id in ot_frameworks:
            assert fw_id in scf_data.frameworks, f"OT framework {fw_id} not found"

    def test_privacy_frameworks(self, scf_data):
        """Test privacy frameworks exist."""
        privacy_frameworks = [
            "emea_eu_gdpr",
            "iso_27701_2025",
            "americas_brazil_lgpd",
            "apac_india_dpdpa_2023",
            "us_ca_ccpa_2025",
        ]
        for fw_id in privacy_frameworks:
            assert fw_id in scf_data.frameworks, f"Privacy framework {fw_id} not found"

    def test_automotive_frameworks(self, scf_data):
        """Test automotive frameworks exist."""
        auto_frameworks = [
            "iso_sae_21434_2021",
            "tisax_isa_6.0.3",
            "un_r155",
        ]
        for fw_id in auto_frameworks:
            assert fw_id in scf_data.frameworks, f"Automotive framework {fw_id} not found"
