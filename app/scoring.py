"""Threat scoring utilities for likelihood × impact calculation."""

from enum import Enum

from .schemas import SeverityLabel, Threat


class LikelihoodLevel(int, Enum):
    """Likelihood levels for threat assessment."""

    RARE = 1  # Unlikely to occur
    UNLIKELY = 2  # Could occur but not expected
    POSSIBLE = 3  # Might occur occasionally
    LIKELY = 4  # Will probably occur
    ALMOST_CERTAIN = 5  # Expected to occur


class ImpactLevel(int, Enum):
    """Impact levels for threat assessment."""

    NEGLIGIBLE = 1  # Minimal impact
    MINOR = 2  # Limited impact, easily recoverable
    MODERATE = 3  # Noticeable impact, recovery needed
    MAJOR = 4  # Significant impact, difficult recovery
    CRITICAL = 5  # Severe impact, may be unrecoverable


def calculate_severity(likelihood: int, impact: int) -> int:
    """Calculate severity score from likelihood and impact.

    Args:
        likelihood: Likelihood score (1-5).
        impact: Impact score (1-5).

    Returns:
        Severity score (1-25).

    Raises:
        ValueError: If likelihood or impact is out of range.
    """
    if not 1 <= likelihood <= 5:
        raise ValueError(f"Likelihood must be 1-5, got {likelihood}")
    if not 1 <= impact <= 5:
        raise ValueError(f"Impact must be 1-5, got {impact}")

    return likelihood * impact


def get_severity_label(severity: int) -> SeverityLabel:
    """Get severity label from severity score.

    Scoring bands:
    - 1-6: Low
    - 7-14: Medium
    - 15-25: High

    Args:
        severity: Severity score (1-25).

    Returns:
        SeverityLabel enum value.

    Raises:
        ValueError: If severity is out of range.
    """
    if not 1 <= severity <= 25:
        raise ValueError(f"Severity must be 1-25, got {severity}")

    if severity <= 6:
        return SeverityLabel.LOW
    elif severity <= 14:
        return SeverityLabel.MEDIUM
    else:
        return SeverityLabel.HIGH


def score_threat(likelihood: int, impact: int) -> tuple[int, SeverityLabel]:
    """Calculate severity and label for a threat.

    Args:
        likelihood: Likelihood score (1-5).
        impact: Impact score (1-5).

    Returns:
        Tuple of (severity_score, severity_label).
    """
    severity = calculate_severity(likelihood, impact)
    label = get_severity_label(severity)
    return severity, label


def validate_threat_scoring(threat: Threat) -> list[str]:
    """Validate that a threat's scoring is consistent.

    Args:
        threat: The threat to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    errors = []

    # Validate ranges
    if not 1 <= threat.likelihood <= 5:
        errors.append(f"Threat {threat.id}: likelihood {threat.likelihood} out of range (1-5)")
    if not 1 <= threat.impact <= 5:
        errors.append(f"Threat {threat.id}: impact {threat.impact} out of range (1-5)")

    # Validate severity label matches calculation
    if 1 <= threat.likelihood <= 5 and 1 <= threat.impact <= 5:
        expected_severity = threat.likelihood * threat.impact
        expected_label = get_severity_label(expected_severity)
        if threat.severity_label != expected_label:
            errors.append(
                f"Threat {threat.id}: severity_label should be {expected_label.value} "
                f"(L={threat.likelihood} × I={threat.impact} = {expected_severity}), "
                f"got {threat.severity_label.value}"
            )

    return errors


def rank_threats_by_severity(threats: list[Threat]) -> list[Threat]:
    """Rank threats by severity (highest first).

    Args:
        threats: List of threats to rank.

    Returns:
        Sorted list of threats (highest severity first).
    """
    return sorted(
        threats,
        key=lambda t: (t.likelihood * t.impact, t.impact, t.likelihood),
        reverse=True,
    )


def get_risk_summary(threats: list[Threat]) -> dict[str, int]:
    """Get summary of threats by severity level.

    Args:
        threats: List of threats.

    Returns:
        Dict with counts by severity level.
    """
    summary = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "total": len(threats),
    }

    for threat in threats:
        if threat.severity_label == SeverityLabel.HIGH:
            summary["high"] += 1
        elif threat.severity_label == SeverityLabel.MEDIUM:
            summary["medium"] += 1
        else:
            summary["low"] += 1

    return summary


def format_severity_badge(severity_label: SeverityLabel) -> str:
    """Format severity label as a badge for markdown.

    Args:
        severity_label: The severity label.

    Returns:
        Markdown-formatted badge.
    """
    badges = {
        SeverityLabel.HIGH: "🔴 **HIGH**",
        SeverityLabel.MEDIUM: "🟡 **MEDIUM**",
        SeverityLabel.LOW: "🟢 **LOW**",
    }
    return badges.get(severity_label, severity_label.value)


# Severity matrix for reference
SEVERITY_MATRIX = """
Severity Matrix (Likelihood × Impact):

         │ Impact                                      │
         │   1        2        3        4        5    │
─────────┼────────────────────────────────────────────┤
L   1    │  1 LOW    2 LOW    3 LOW    4 LOW    5 LOW │
i   2    │  2 LOW    4 LOW    6 LOW    8 MED   10 MED │
k   3    │  3 LOW    6 LOW    9 MED   12 MED   15 HIGH│
e   4    │  4 LOW    8 MED   12 MED   16 HIGH  20 HIGH│
l   5    │  5 LOW   10 MED   15 HIGH  20 HIGH  25 HIGH│
─────────┴────────────────────────────────────────────┘

Severity Bands:
- Low: 1-6
- Medium: 7-14
- High: 15-25
"""



