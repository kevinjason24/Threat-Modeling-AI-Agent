"""Tests for threat scoring utilities."""

import pytest

from app.scoring import (
    calculate_severity,
    get_severity_label,
    score_threat,
    validate_threat_scoring,
    rank_threats_by_severity,
    get_risk_summary,
    format_severity_badge,
    LikelihoodLevel,
    ImpactLevel,
)
from app.schemas import SeverityLabel, Threat, StrideCategory


class TestCalculateSeverity:
    """Tests for severity calculation."""

    def test_minimum_severity(self):
        """Test minimum severity score."""
        assert calculate_severity(1, 1) == 1

    def test_maximum_severity(self):
        """Test maximum severity score."""
        assert calculate_severity(5, 5) == 25

    def test_various_combinations(self):
        """Test various likelihood/impact combinations."""
        assert calculate_severity(2, 3) == 6
        assert calculate_severity(3, 4) == 12
        assert calculate_severity(4, 5) == 20

    def test_invalid_likelihood_low(self):
        """Test that likelihood < 1 raises error."""
        with pytest.raises(ValueError, match="Likelihood must be 1-5"):
            calculate_severity(0, 3)

    def test_invalid_likelihood_high(self):
        """Test that likelihood > 5 raises error."""
        with pytest.raises(ValueError, match="Likelihood must be 1-5"):
            calculate_severity(6, 3)

    def test_invalid_impact_low(self):
        """Test that impact < 1 raises error."""
        with pytest.raises(ValueError, match="Impact must be 1-5"):
            calculate_severity(3, 0)

    def test_invalid_impact_high(self):
        """Test that impact > 5 raises error."""
        with pytest.raises(ValueError, match="Impact must be 1-5"):
            calculate_severity(3, 6)


class TestGetSeverityLabel:
    """Tests for severity label assignment."""

    def test_low_severity_boundaries(self):
        """Test Low severity boundaries (1-6)."""
        assert get_severity_label(1) == SeverityLabel.LOW
        assert get_severity_label(6) == SeverityLabel.LOW

    def test_medium_severity_boundaries(self):
        """Test Medium severity boundaries (7-14)."""
        assert get_severity_label(7) == SeverityLabel.MEDIUM
        assert get_severity_label(14) == SeverityLabel.MEDIUM

    def test_high_severity_boundaries(self):
        """Test High severity boundaries (15-25)."""
        assert get_severity_label(15) == SeverityLabel.HIGH
        assert get_severity_label(25) == SeverityLabel.HIGH

    def test_invalid_severity_low(self):
        """Test that severity < 1 raises error."""
        with pytest.raises(ValueError, match="Severity must be 1-25"):
            get_severity_label(0)

    def test_invalid_severity_high(self):
        """Test that severity > 25 raises error."""
        with pytest.raises(ValueError, match="Severity must be 1-25"):
            get_severity_label(26)


class TestScoreThreat:
    """Tests for the score_threat helper function."""

    def test_returns_tuple(self):
        """Test that score_threat returns a tuple."""
        result = score_threat(3, 4)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_low_threat(self):
        """Test scoring a low severity threat."""
        score, label = score_threat(1, 3)
        assert score == 3
        assert label == SeverityLabel.LOW

    def test_medium_threat(self):
        """Test scoring a medium severity threat."""
        score, label = score_threat(3, 3)
        assert score == 9
        assert label == SeverityLabel.MEDIUM

    def test_high_threat(self):
        """Test scoring a high severity threat."""
        score, label = score_threat(5, 4)
        assert score == 20
        assert label == SeverityLabel.HIGH


class TestValidateThreatScoring:
    """Tests for threat scoring validation."""

    def create_threat(
        self,
        likelihood: int = 3,
        impact: int = 3,
        severity_label: SeverityLabel = SeverityLabel.MEDIUM,
    ) -> Threat:
        """Helper to create a threat for testing."""
        return Threat(
            id="T001",
            stride_category=StrideCategory.SPOOFING,
            affected_element="P_API",
            title="Test Threat",
            description="Test description",
            likelihood=likelihood,
            impact=impact,
            severity_label=severity_label,
        )

    def test_valid_threat_no_errors(self):
        """Test that a valid threat has no errors."""
        threat = self.create_threat(3, 3, SeverityLabel.MEDIUM)
        errors = validate_threat_scoring(threat)
        assert len(errors) == 0

    def test_mismatched_severity_label(self):
        """Test detection of mismatched severity label."""
        # 3 * 3 = 9 = Medium, but we say High
        threat = self.create_threat(3, 3, SeverityLabel.HIGH)
        errors = validate_threat_scoring(threat)
        assert len(errors) == 1
        assert "severity_label should be Medium" in errors[0]

    def test_likelihood_out_of_range(self):
        """Test that Pydantic validates likelihood range at creation."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self.create_threat(6, 3, SeverityLabel.MEDIUM)

    def test_impact_out_of_range(self):
        """Test that Pydantic validates impact range at creation."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self.create_threat(3, 0, SeverityLabel.LOW)


class TestRankThreatsBySeverity:
    """Tests for threat ranking."""

    def create_threat(self, id: str, likelihood: int, impact: int) -> Threat:
        """Helper to create threats for testing."""
        return Threat(
            id=id,
            stride_category=StrideCategory.SPOOFING,
            affected_element="P_API",
            title=f"Threat {id}",
            description="Test",
            likelihood=likelihood,
            impact=impact,
            severity_label=get_severity_label(likelihood * impact),
        )

    def test_ranking_order(self):
        """Test that threats are ranked by severity descending."""
        threats = [
            self.create_threat("T001", 1, 1),  # severity 1
            self.create_threat("T002", 5, 5),  # severity 25
            self.create_threat("T003", 3, 3),  # severity 9
        ]
        ranked = rank_threats_by_severity(threats)
        assert ranked[0].id == "T002"  # Highest first
        assert ranked[1].id == "T003"
        assert ranked[2].id == "T001"  # Lowest last

    def test_empty_list(self):
        """Test ranking empty list."""
        ranked = rank_threats_by_severity([])
        assert ranked == []

    def test_same_severity_uses_impact(self):
        """Test that same severity uses impact as tiebreaker."""
        threats = [
            self.create_threat("T001", 2, 4),  # severity 8, impact 4
            self.create_threat("T002", 4, 2),  # severity 8, impact 2
        ]
        ranked = rank_threats_by_severity(threats)
        assert ranked[0].id == "T001"  # Higher impact first


class TestGetRiskSummary:
    """Tests for risk summary generation."""

    def create_threat(self, severity_label: SeverityLabel) -> Threat:
        """Helper to create threats with specific severity."""
        likelihood = 5 if severity_label == SeverityLabel.HIGH else (3 if severity_label == SeverityLabel.MEDIUM else 1)
        impact = 5 if severity_label == SeverityLabel.HIGH else (3 if severity_label == SeverityLabel.MEDIUM else 1)
        return Threat(
            id="T001",
            stride_category=StrideCategory.SPOOFING,
            affected_element="P_API",
            title="Test",
            description="Test",
            likelihood=likelihood,
            impact=impact,
            severity_label=severity_label,
        )

    def test_summary_counts(self):
        """Test that summary has correct counts."""
        threats = [
            self.create_threat(SeverityLabel.HIGH),
            self.create_threat(SeverityLabel.HIGH),
            self.create_threat(SeverityLabel.MEDIUM),
            self.create_threat(SeverityLabel.LOW),
        ]
        summary = get_risk_summary(threats)
        assert summary["high"] == 2
        assert summary["medium"] == 1
        assert summary["low"] == 1
        assert summary["total"] == 4

    def test_empty_summary(self):
        """Test summary with no threats."""
        summary = get_risk_summary([])
        assert summary["high"] == 0
        assert summary["medium"] == 0
        assert summary["low"] == 0
        assert summary["total"] == 0


class TestFormatSeverityBadge:
    """Tests for severity badge formatting."""

    def test_high_badge(self):
        """Test High severity badge."""
        badge = format_severity_badge(SeverityLabel.HIGH)
        assert "HIGH" in badge
        assert "🔴" in badge

    def test_medium_badge(self):
        """Test Medium severity badge."""
        badge = format_severity_badge(SeverityLabel.MEDIUM)
        assert "MEDIUM" in badge
        assert "🟡" in badge

    def test_low_badge(self):
        """Test Low severity badge."""
        badge = format_severity_badge(SeverityLabel.LOW)
        assert "LOW" in badge
        assert "🟢" in badge


class TestEnumValues:
    """Tests for enum values."""

    def test_likelihood_levels(self):
        """Test LikelihoodLevel enum values."""
        assert LikelihoodLevel.RARE == 1
        assert LikelihoodLevel.UNLIKELY == 2
        assert LikelihoodLevel.POSSIBLE == 3
        assert LikelihoodLevel.LIKELY == 4
        assert LikelihoodLevel.ALMOST_CERTAIN == 5

    def test_impact_levels(self):
        """Test ImpactLevel enum values."""
        assert ImpactLevel.NEGLIGIBLE == 1
        assert ImpactLevel.MINOR == 2
        assert ImpactLevel.MODERATE == 3
        assert ImpactLevel.MAJOR == 4
        assert ImpactLevel.CRITICAL == 5

