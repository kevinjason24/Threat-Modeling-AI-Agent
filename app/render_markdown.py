"""Markdown report generator for threat model output."""


from .schemas import (
    AbuseCase,
    DFDModel,
    EngineeringChecklist,
    Inventory,
    NextStep,
    QAResult,
    RiskSummary,
    StrideAnalysis,
    Threat,
    ThreatModelReport,
)
from .scoring import format_severity_badge, get_risk_summary


def render_markdown_report(report: ThreatModelReport) -> str:
    """Render a complete threat model report as Markdown.

    Args:
        report: The threat model report to render.

    Returns:
        Markdown string.
    """
    sections = []

    # Header
    sections.append(_render_header(report))

    # Table of Contents
    sections.append(_render_toc())

    # 1. Overview
    sections.append(_render_overview(report))

    # 2. Assumptions & Unknowns
    sections.append(_render_assumptions_unknowns(report))

    # 3. System Inventory
    sections.append(_render_inventory(report.inventory))

    # 4. Data-Flow Diagram Notes
    sections.append(_render_dfd_notes(report.dfd_model))

    # 5. Mermaid DFD
    sections.append(_render_mermaid_section(report.mermaid_diagram))

    # 6. STRIDE Threat Analysis
    sections.append(_render_stride_analysis(report.stride_analysis))

    # 7. Abuse Cases
    sections.append(_render_abuse_cases(report.abuse_cases))

    # 8. Engineering Checklist
    sections.append(_render_checklist(report.checklist))

    # 9. Top Risks & Mitigations
    sections.append(_render_top_risks(report.top_risks))

    # 10. Next Steps
    sections.append(_render_next_steps(report.next_steps))

    # QA Summary (appendix)
    sections.append(_render_qa_summary(report.qa_result))

    return "\n\n".join(sections)


def _render_header(report: ThreatModelReport) -> str:
    """Render the report header."""
    return f"""# Threat Model Report

**Generated:** {report.generated_at}
**Input Document:** `{report.input_document}`
**Version:** {report.version}

---"""


def _render_toc() -> str:
    """Render table of contents."""
    return """## Table of Contents

1. [Overview](#1-overview)
2. [Assumptions & Unknowns](#2-assumptions--unknowns)
3. [System Inventory](#3-system-inventory)
4. [Data-Flow Diagram Notes](#4-data-flow-diagram-notes)
5. [Mermaid DFD](#5-mermaid-dfd)
6. [STRIDE Threat Analysis](#6-stride-threat-analysis)
7. [Abuse Cases](#7-abuse-cases)
8. [Engineering Checklist](#8-engineering-checklist)
9. [Top Risks & Mitigations](#9-top-risks--mitigations)
10. [Next Steps](#10-next-steps)

---"""


def _render_overview(report: ThreatModelReport) -> str:
    """Render the overview section."""
    risk_summary = get_risk_summary(report.stride_analysis.threats)

    return f"""## 1. Overview

{report.overview}

### Risk Summary

| Severity | Count |
|----------|-------|
| 🔴 High | {risk_summary['high']} |
| 🟡 Medium | {risk_summary['medium']} |
| 🟢 Low | {risk_summary['low']} |
| **Total** | **{risk_summary['total']}** |"""


def _render_assumptions_unknowns(report: ThreatModelReport) -> str:
    """Render assumptions and unknowns section."""
    lines = ["## 2. Assumptions & Unknowns"]

    lines.append("\n### Assumptions\n")
    if report.assumptions:
        for assumption in report.assumptions:
            lines.append(f"- {assumption}")
    else:
        lines.append("_No explicit assumptions documented._")

    lines.append("\n### Unknowns\n")
    if report.unknowns:
        for unknown in report.unknowns:
            lines.append(f"- ⚠️ {unknown}")
    else:
        lines.append("_No unknowns identified._")

    return "\n".join(lines)


def _render_inventory(inventory: Inventory) -> str:
    """Render the system inventory section."""
    lines = ["## 3. System Inventory"]

    # Actors
    lines.append("\n### Actors\n")
    if inventory.actors:
        lines.append("| ID | Name | Type | Description |")
        lines.append("|-----|------|------|-------------|")
        for actor in inventory.actors:
            lines.append(f"| {actor.id} | {actor.name} | {actor.type.value} | {actor.description} |")
    else:
        lines.append("_No actors identified._")

    # Components
    lines.append("\n### Components/Services\n")
    if inventory.components:
        lines.append("| ID | Name | Technology | Responsibilities |")
        lines.append("|-----|------|------------|------------------|")
        for comp in inventory.components:
            responsibilities = ", ".join(comp.responsibilities[:3]) if comp.responsibilities else "-"
            lines.append(f"| {comp.id} | {comp.name} | {comp.technology} | {responsibilities} |")
    else:
        lines.append("_No components identified._")

    # Data Stores
    lines.append("\n### Data Stores\n")
    if inventory.data_stores:
        lines.append("| ID | Name | Type | Data Types | Encrypted |")
        lines.append("|-----|------|------|------------|-----------|")
        for ds in inventory.data_stores:
            data_types = ", ".join([dt.value for dt in ds.data_types[:3]]) if ds.data_types else "-"
            encrypted = "✅" if ds.encryption_at_rest else ("❌" if ds.encryption_at_rest is False else "❓")
            lines.append(f"| {ds.id} | {ds.name} | {ds.type} | {data_types} | {encrypted} |")
    else:
        lines.append("_No data stores identified._")

    # Entry Points
    lines.append("\n### Entry Points\n")
    if inventory.entry_points:
        lines.append("| ID | Name | Protocol | Auth | Exposed To |")
        lines.append("|-----|------|----------|------|------------|")
        for ep in inventory.entry_points:
            lines.append(f"| {ep.id} | {ep.name} | {ep.protocol} | {ep.authentication} | {ep.exposed_to} |")
    else:
        lines.append("_No entry points identified._")

    # Integrations
    lines.append("\n### External Integrations\n")
    if inventory.integrations:
        lines.append("| ID | Name | Type | Direction | Auth |")
        lines.append("|-----|------|------|-----------|------|")
        for integ in inventory.integrations:
            lines.append(f"| {integ.id} | {integ.name} | {integ.type} | {integ.direction} | {integ.authentication} |")
    else:
        lines.append("_No external integrations identified._")

    # Auth Config
    lines.append("\n### Authentication & Authorization\n")
    auth = inventory.auth_config
    lines.append(f"- **AuthN Methods:** {', '.join(auth.authn_methods) if auth.authn_methods else 'Unknown'}")
    lines.append(f"- **AuthZ Model:** {auth.authz_model}")
    lines.append(f"- **Session Management:** {auth.session_management}")
    lines.append(f"- **MFA Enabled:** {'✅' if auth.mfa_enabled else ('❌' if auth.mfa_enabled is False else '❓ Unknown')}")
    if auth.notes:
        lines.append("\n**Notes:**")
        for note in auth.notes:
            lines.append(f"- {note}")

    # Trust Boundaries
    lines.append("\n### Trust Boundaries\n")
    if inventory.trust_boundaries:
        for tb in inventory.trust_boundaries:
            lines.append(f"- **{tb.name}** ({tb.id}): {tb.description}")
            if tb.components_inside:
                lines.append(f"  - Components: {', '.join(tb.components_inside)}")
    else:
        lines.append("_No trust boundaries explicitly defined._")

    return "\n".join(lines)


def _render_dfd_notes(dfd: DFDModel) -> str:
    """Render DFD notes section."""
    lines = ["## 4. Data-Flow Diagram Notes"]

    if dfd.dfd_notes:
        for note in dfd.dfd_notes:
            lines.append(f"- {note}")
    else:
        lines.append("_No additional DFD notes._")

    # Summary stats
    lines.append("\n**Diagram Statistics:**")
    lines.append(f"- Nodes: {len(dfd.nodes)}")
    lines.append(f"- Flows: {len(dfd.flows)}")
    lines.append(f"- Trust Boundaries: {len(dfd.trust_boundaries)}")

    boundary_crossings = sum(1 for f in dfd.flows if f.crosses_boundary)
    lines.append(f"- Flows Crossing Boundaries: {boundary_crossings}")

    return "\n".join(lines)


def _render_mermaid_section(mermaid_diagram: str) -> str:
    """Render the Mermaid DFD section."""
    return f"""## 5. Mermaid DFD

```mermaid
{mermaid_diagram}
```

> **Legend:**
> - 🟣 Stadium shapes = External Entities
> - 🔵 Rectangles = Processes
> - 🟢 Cylinders = Data Stores
> - Thick arrows (==>) = Encrypted flows
> - Dotted arrows (-.->) = Boundary crossings"""


def _render_stride_analysis(analysis: StrideAnalysis) -> str:
    """Render STRIDE threat analysis section."""
    lines = ["## 6. STRIDE Threat Analysis"]

    if analysis.analysis_notes:
        lines.append("\n**Analysis Notes:**")
        for note in analysis.analysis_notes:
            lines.append(f"- {note}")

    # Group threats by category
    categories = {
        "S": "Spoofing",
        "T": "Tampering",
        "R": "Repudiation",
        "I": "Information Disclosure",
        "D": "Denial of Service",
        "E": "Elevation of Privilege",
    }

    for cat_code, cat_name in categories.items():
        cat_threats = [t for t in analysis.threats if t.stride_category.value == cat_code]
        if cat_threats:
            lines.append(f"\n### {cat_code} - {cat_name}\n")
            for threat in cat_threats:
                lines.append(_render_threat(threat))

    if not analysis.threats:
        lines.append("\n_No threats identified._")

    return "\n".join(lines)


def _render_threat(threat: Threat) -> str:
    """Render a single threat."""
    severity_badge = format_severity_badge(threat.severity_label)
    severity_score = threat.likelihood * threat.impact

    lines = [
        f"#### {threat.id}: {threat.title}",
        "",
        f"{severity_badge} (L:{threat.likelihood} × I:{threat.impact} = {severity_score})",
        "",
        f"**Affected Element:** `{threat.affected_element}`",
        "",
        f"{threat.description}",
    ]

    if threat.preconditions:
        lines.append("\n**Preconditions:**")
        for pre in threat.preconditions:
            lines.append(f"- {pre}")

    if threat.exploit_steps:
        lines.append("\n**Exploit Steps:**")
        for step in threat.exploit_steps:
            lines.append(f"- {step}")

    if threat.detection_signals:
        lines.append("\n**Detection Signals:**")
        for signal in threat.detection_signals:
            lines.append(f"- 🔍 {signal}")

    if threat.mitigations:
        lines.append("\n**Mitigations:**")
        for mitigation in threat.mitigations:
            lines.append(f"- ✅ {mitigation}")

    if threat.references:
        lines.append("\n**References:** " + ", ".join(threat.references))

    lines.append("\n---\n")

    return "\n".join(lines)


def _render_abuse_cases(abuse_cases: list[AbuseCase]) -> str:
    """Render abuse cases section."""
    lines = ["## 7. Abuse Cases"]

    if not abuse_cases:
        lines.append("\n_No abuse cases documented._")
        return "\n".join(lines)

    for ac in abuse_cases:
        lines.append(f"\n### {ac.id}: {ac.title}\n")
        lines.append(f"**Attacker Goal:** {ac.attacker_goal}")
        lines.append(f"\n**Attacker Profile:** {ac.attacker_profile}")

        lines.append("\n**Attack Steps:**")
        for i, step in enumerate(ac.steps, 1):
            lines.append(f"{i}. {step}")

        if ac.impacted_assets:
            lines.append(f"\n**Impacted Assets:** {', '.join(ac.impacted_assets)}")

        if ac.recommended_controls:
            lines.append("\n**Recommended Controls:**")
            for control in ac.recommended_controls:
                lines.append(f"- {control}")

        if ac.related_threats:
            lines.append(f"\n**Related Threats:** {', '.join(ac.related_threats)}")

        lines.append("\n---")

    return "\n".join(lines)


def _render_checklist(checklist: EngineeringChecklist) -> str:
    """Render engineering checklist section."""
    lines = ["## 8. Engineering Checklist"]

    if not checklist.categories:
        lines.append("\n_No checklist items generated._")
        return "\n".join(lines)

    for category in checklist.categories:
        lines.append(f"\n### {category.category}\n")

        if category.items:
            for item in category.items:
                priority_icon = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(item.priority, "⚪")
                lines.append(f"- [ ] {priority_icon} **{item.id}**: {item.description}")
                if item.related_threats:
                    lines.append(f"  - _Related: {', '.join(item.related_threats)}_")
        else:
            lines.append("_No items in this category._")

    return "\n".join(lines)


def _render_top_risks(risks: list[RiskSummary]) -> str:
    """Render top risks section."""
    lines = ["## 9. Top Risks & Mitigations"]

    if not risks:
        lines.append("\n_No top risks summarized._")
        return "\n".join(lines)

    for i, risk in enumerate(risks, 1):
        severity_badge = format_severity_badge(risk.aggregated_severity)
        lines.append(f"\n### Risk {i}: {risk.risk_description}\n")
        lines.append(f"{severity_badge}")
        lines.append(f"\n**Related Threats:** {', '.join(risk.threat_ids)}")
        lines.append("\n**Key Mitigations:**")
        for mitigation in risk.key_mitigations:
            lines.append(f"- {mitigation}")

    return "\n".join(lines)


def _render_next_steps(next_steps: list[NextStep]) -> str:
    """Render next steps section."""
    lines = ["## 10. Next Steps"]

    if not next_steps:
        lines.append("\n_No next steps defined._")
        return "\n".join(lines)

    lines.append("")
    lines.append("| Priority | Action | Rationale | Suggested Owner |")
    lines.append("|----------|--------|-----------|-----------------|")

    for step in sorted(next_steps, key=lambda s: s.priority):
        lines.append(f"| {step.priority} | {step.action} | {step.rationale} | {step.owner_suggestion} |")

    return "\n".join(lines)


def _render_qa_summary(qa: QAResult) -> str:
    """Render QA summary as appendix."""
    status = "✅ PASSED" if qa.passed else "❌ FAILED"

    lines = [
        "---",
        "",
        "## Appendix: QA Summary",
        "",
        f"**Status:** {status}",
        f"**Completeness Score:** {qa.completeness_score:.0%}",
        f"**Consistency Score:** {qa.consistency_score:.0%}",
        f"**Assumptions Labeled:** {'✅' if qa.assumptions_labeled else '❌'}",
        "",
        f"**Summary:** {qa.summary}",
    ]

    if qa.issues:
        lines.append("\n### Issues Found\n")
        for issue in qa.issues:
            icon = {"error": "🔴", "warning": "🟡", "info": "🔵"}.get(issue.severity, "⚪")
            lines.append(f"- {icon} **[{issue.category}]** {issue.message}")
            lines.append(f"  - Section: {issue.affected_section}")
            if issue.suggested_fix:
                lines.append(f"  - Fix: {issue.suggested_fix}")

    return "\n".join(lines)



