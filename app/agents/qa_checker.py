"""QA Checker Agent - Validates completeness and consistency of threat model."""

import logging
from typing import TYPE_CHECKING

from ..prompts import QA_CHECKER_SYSTEM, QA_CHECKER_USER
from ..schemas import (
    AbuseCasesOutput,
    DFDModel,
    EngineeringChecklist,
    Inventory,
    QAIssue,
    QAResult,
    StrideAnalysis,
)

if TYPE_CHECKING:
    from ..llm import LLMClient

logger = logging.getLogger(__name__)


class QACheckerAgent:
    """Validates threat model for completeness, consistency, and clarity.

    Checks:
    - Completeness: All sections present, no empty required fields
    - Consistency: ID references valid, no orphans
    - Clarity: Assumptions labeled, unknowns documented
    - Actionability: Mitigations specific, checklists testable
    """

    def __init__(self, llm_client: "LLMClient"):
        self.llm = llm_client

    def run(
        self,
        inventory: Inventory,
        dfd: DFDModel,
        stride_analysis: StrideAnalysis,
        abuse_cases: AbuseCasesOutput,
        checklist: EngineeringChecklist,
    ) -> QAResult:
        """Run the QA checker agent.

        Args:
            inventory: System inventory.
            dfd: Data flow diagram.
            stride_analysis: STRIDE analysis.
            abuse_cases: Abuse cases.
            checklist: Engineering checklist.

        Returns:
            QAResult with issues and scores.
        """
        logger.info("Running QA Checker Agent...")

        # Run programmatic checks first
        issues = self._run_programmatic_checks(
            inventory, dfd, stride_analysis, abuse_cases, checklist
        )

        # Calculate scores
        completeness_score = self._calculate_completeness(
            inventory, dfd, stride_analysis, abuse_cases, checklist
        )
        consistency_score = self._calculate_consistency(issues)
        assumptions_labeled = len(inventory.assumptions) > 0 or len(inventory.unknowns) > 0

        # Optionally run LLM-based checks for deeper analysis
        if completeness_score > 0.5:  # Only if we have enough content
            llm_issues = self._run_llm_checks(
                inventory, dfd, stride_analysis, abuse_cases, checklist
            )
            issues.extend(llm_issues)

        # Determine pass/fail
        error_count = sum(1 for i in issues if i.severity == "error")
        passed = error_count == 0 and completeness_score >= 0.7

        # Generate summary
        summary = self._generate_summary(
            passed, issues, completeness_score, consistency_score
        )

        result = QAResult(
            passed=passed,
            issues=issues,
            completeness_score=completeness_score,
            consistency_score=consistency_score,
            assumptions_labeled=assumptions_labeled,
            summary=summary,
        )

        logger.info(f"QA Check: {'PASSED' if passed else 'FAILED'}")
        logger.info(f"Completeness: {completeness_score:.0%}, Consistency: {consistency_score:.0%}")

        return result

    def _run_programmatic_checks(
        self,
        inventory: Inventory,
        dfd: DFDModel,
        stride_analysis: StrideAnalysis,
        abuse_cases: AbuseCasesOutput,
        checklist: EngineeringChecklist,
    ) -> list[QAIssue]:
        """Run programmatic validation checks."""
        issues = []

        # Check inventory completeness
        if not inventory.actors:
            issues.append(QAIssue(
                severity="warning",
                category="completeness",
                message="No actors identified in inventory",
                affected_section="System Inventory",
                suggested_fix="Add at least one actor (user, admin, service, or 3rd-party)",
            ))

        if not inventory.components:
            issues.append(QAIssue(
                severity="error",
                category="completeness",
                message="No components identified in inventory",
                affected_section="System Inventory",
                suggested_fix="Add system components/services from the design document",
            ))

        if not inventory.entry_points:
            issues.append(QAIssue(
                severity="warning",
                category="completeness",
                message="No entry points identified",
                affected_section="System Inventory",
                suggested_fix="Identify APIs, UIs, or other entry points into the system",
            ))

        # Check DFD
        if not dfd.nodes:
            issues.append(QAIssue(
                severity="error",
                category="completeness",
                message="DFD has no nodes",
                affected_section="Data-Flow Diagram",
                suggested_fix="Add nodes representing system components",
            ))

        if not dfd.flows:
            issues.append(QAIssue(
                severity="error",
                category="completeness",
                message="DFD has no data flows",
                affected_section="Data-Flow Diagram",
                suggested_fix="Add flows showing data movement between nodes",
            ))

        # Check flow references
        valid_node_ids = {n.id for n in dfd.nodes}
        for flow in dfd.flows:
            if flow.src not in valid_node_ids:
                issues.append(QAIssue(
                    severity="error",
                    category="consistency",
                    message=f"Flow {flow.id} references non-existent source node: {flow.src}",
                    affected_section="Data-Flow Diagram",
                    suggested_fix=f"Add node {flow.src} or fix the reference",
                ))
            if flow.dst not in valid_node_ids:
                issues.append(QAIssue(
                    severity="error",
                    category="consistency",
                    message=f"Flow {flow.id} references non-existent destination node: {flow.dst}",
                    affected_section="Data-Flow Diagram",
                    suggested_fix=f"Add node {flow.dst} or fix the reference",
                ))

        # Check STRIDE analysis
        if not stride_analysis.threats:
            issues.append(QAIssue(
                severity="error",
                category="completeness",
                message="No threats identified in STRIDE analysis",
                affected_section="STRIDE Threat Analysis",
                suggested_fix="Analyze system for STRIDE threats",
            ))

        # Check threat references
        valid_elements = valid_node_ids | {f.id for f in dfd.flows}
        for threat in stride_analysis.threats:
            if threat.affected_element not in valid_elements:
                issues.append(QAIssue(
                    severity="warning",
                    category="consistency",
                    message=f"Threat {threat.id} references unknown element: {threat.affected_element}",
                    affected_section="STRIDE Threat Analysis",
                    suggested_fix="Update affected_element to a valid node or flow ID",
                ))

            if not threat.mitigations:
                issues.append(QAIssue(
                    severity="warning",
                    category="completeness",
                    message=f"Threat {threat.id} has no mitigations",
                    affected_section="STRIDE Threat Analysis",
                    suggested_fix="Add actionable mitigations for this threat",
                ))

        # Check abuse cases
        if not abuse_cases.abuse_cases:
            issues.append(QAIssue(
                severity="warning",
                category="completeness",
                message="No abuse cases documented",
                affected_section="Abuse Cases",
                suggested_fix="Add abuse cases for top threats",
            ))

        # Check checklist
        if not checklist.categories:
            issues.append(QAIssue(
                severity="error",
                category="completeness",
                message="Engineering checklist is empty",
                affected_section="Engineering Checklist",
                suggested_fix="Generate checklist items for security categories",
            ))

        empty_categories = [c.category for c in checklist.categories if not c.items]
        if empty_categories:
            issues.append(QAIssue(
                severity="warning",
                category="completeness",
                message=f"Empty checklist categories: {', '.join(empty_categories)}",
                affected_section="Engineering Checklist",
                suggested_fix="Add items to empty categories or remove them",
            ))

        # Check assumptions/unknowns
        if not inventory.assumptions and not inventory.unknowns:
            issues.append(QAIssue(
                severity="info",
                category="clarity",
                message="No assumptions or unknowns documented",
                affected_section="Assumptions & Unknowns",
                suggested_fix="Document assumptions made and unknown details",
            ))

        return issues

    def _run_llm_checks(
        self,
        inventory: Inventory,
        dfd: DFDModel,
        stride_analysis: StrideAnalysis,
        abuse_cases: AbuseCasesOutput,
        checklist: EngineeringChecklist,
    ) -> list[QAIssue]:
        """Run LLM-based quality checks for deeper analysis."""
        try:
            # Build summary for LLM review
            report_summary = {
                "inventory": {
                    "actors": len(inventory.actors),
                    "components": len(inventory.components),
                    "data_stores": len(inventory.data_stores),
                    "entry_points": len(inventory.entry_points),
                    "assumptions": inventory.assumptions[:5],
                    "unknowns": inventory.unknowns[:5],
                },
                "dfd": {
                    "nodes": len(dfd.nodes),
                    "flows": len(dfd.flows),
                    "trust_boundaries": len(dfd.trust_boundaries),
                },
                "stride": {
                    "threat_count": len(stride_analysis.threats),
                    "sample_threats": [
                        {"id": t.id, "title": t.title, "severity": t.severity_label.value}
                        for t in stride_analysis.threats[:3]
                    ],
                },
                "abuse_cases": len(abuse_cases.abuse_cases),
                "checklist_categories": len(checklist.categories),
            }

            import json
            report_json = json.dumps(report_summary, indent=2)

            user_prompt = QA_CHECKER_USER.format(report_json=report_json)

            result = self.llm.complete_json(
                system_prompt=QA_CHECKER_SYSTEM,
                user_prompt=user_prompt,
                response_model=QAResult,
                max_tokens=2048,
            )

            return result.issues

        except Exception as e:
            logger.warning(f"LLM-based QA check failed: {e}")
            return []

    def _calculate_completeness(
        self,
        inventory: Inventory,
        dfd: DFDModel,
        stride_analysis: StrideAnalysis,
        abuse_cases: AbuseCasesOutput,
        checklist: EngineeringChecklist,
    ) -> float:
        """Calculate completeness score (0-1)."""
        checks = [
            len(inventory.actors) > 0,
            len(inventory.components) > 0,
            len(inventory.entry_points) > 0,
            len(dfd.nodes) > 0,
            len(dfd.flows) > 0,
            len(stride_analysis.threats) > 0,
            len(abuse_cases.abuse_cases) > 0,
            len(checklist.categories) > 0,
            any(len(c.items) > 0 for c in checklist.categories),
            len(inventory.assumptions) > 0 or len(inventory.unknowns) > 0,
        ]

        return sum(checks) / len(checks)

    def _calculate_consistency(self, issues: list[QAIssue]) -> float:
        """Calculate consistency score based on issues found."""
        consistency_issues = [i for i in issues if i.category == "consistency"]
        error_count = sum(1 for i in consistency_issues if i.severity == "error")
        warning_count = sum(1 for i in consistency_issues if i.severity == "warning")

        # Penalize errors more than warnings
        penalty = (error_count * 0.15) + (warning_count * 0.05)
        return max(0.0, 1.0 - penalty)

    def _generate_summary(
        self,
        passed: bool,
        issues: list[QAIssue],
        completeness: float,
        consistency: float,
    ) -> str:
        """Generate human-readable summary."""
        error_count = sum(1 for i in issues if i.severity == "error")
        warning_count = sum(1 for i in issues if i.severity == "warning")

        if passed:
            if warning_count > 0:
                return f"Threat model passed QA with {warning_count} warning(s). Completeness: {completeness:.0%}, Consistency: {consistency:.0%}."
            else:
                return f"Threat model passed QA. Completeness: {completeness:.0%}, Consistency: {consistency:.0%}."
        else:
            return f"Threat model failed QA with {error_count} error(s) and {warning_count} warning(s). Address errors before finalizing."



