"""STRIDE Analyst Agent - Performs threat analysis using STRIDE methodology."""

import logging
from typing import TYPE_CHECKING

from ..prompts import STRIDE_ANALYST_SYSTEM, STRIDE_ANALYST_USER
from ..schemas import DFDModel, Inventory, StrideAnalysis, Threat
from ..scoring import get_severity_label, validate_threat_scoring

if TYPE_CHECKING:
    from ..llm import LLMClient

logger = logging.getLogger(__name__)


class StrideAnalystAgent:
    """Performs STRIDE threat analysis on the system.

    Analyzes each DFD element for:
    - S (Spoofing): Identity impersonation
    - T (Tampering): Data/code modification
    - R (Repudiation): Action denial
    - I (Information Disclosure): Data exposure
    - D (Denial of Service): Availability attacks
    - E (Elevation of Privilege): Unauthorized access
    """

    def __init__(self, llm_client: "LLMClient"):
        self.llm = llm_client

    def run(self, dfd: DFDModel, inventory: Inventory) -> StrideAnalysis:
        """Run the STRIDE analyst agent.

        Args:
            dfd: Data flow diagram model.
            inventory: System inventory.

        Returns:
            StrideAnalysis with identified threats.
        """
        logger.info("Running STRIDE Analyst Agent...")

        # Convert to JSON for prompt
        dfd_json = dfd.model_dump_json(indent=2)
        inventory_json = inventory.model_dump_json(indent=2)

        # Format the user prompt
        user_prompt = STRIDE_ANALYST_USER.format(
            dfd_json=dfd_json,
            inventory_json=inventory_json,
        )

        # Get LLM response
        result = self.llm.complete_json(
            system_prompt=STRIDE_ANALYST_SYSTEM,
            user_prompt=user_prompt,
            response_model=StrideAnalysis,
            max_tokens=8192,
        )

        # Validate and fix threat scoring
        result = self._validate_analysis(result, dfd)

        logger.info(f"Identified {len(result.threats)} threats")
        self._log_threat_summary(result)

        return result

    def _validate_analysis(self, analysis: StrideAnalysis, dfd: DFDModel) -> StrideAnalysis:
        """Validate and fix the STRIDE analysis."""
        valid_element_ids = {node.id for node in dfd.nodes}
        valid_element_ids.update(flow.id for flow in dfd.flows)

        validated_threats = []
        for threat in analysis.threats:
            # Fix severity label if incorrect
            threat = self._fix_severity_label(threat)

            # Validate affected element exists
            if threat.affected_element not in valid_element_ids:
                # Try to find a close match
                matched = False
                for elem_id in valid_element_ids:
                    if threat.affected_element.lower() in elem_id.lower() or elem_id.lower() in threat.affected_element.lower():
                        logger.debug(f"Remapped threat {threat.id} element: {threat.affected_element} -> {elem_id}")
                        threat.affected_element = elem_id
                        matched = True
                        break

                if not matched:
                    logger.warning(f"Threat {threat.id} references unknown element {threat.affected_element}")
                    analysis.analysis_notes.append(
                        f"Note: Threat {threat.id} references element '{threat.affected_element}' not in DFD"
                    )

            # Validate scoring ranges
            scoring_errors = validate_threat_scoring(threat)
            if scoring_errors:
                for error in scoring_errors:
                    logger.warning(error)

            validated_threats.append(threat)

        analysis.threats = validated_threats

        # Ensure threat IDs are unique
        self._ensure_unique_threat_ids(analysis)

        return analysis

    def _fix_severity_label(self, threat: Threat) -> Threat:
        """Fix the severity label based on likelihood and impact."""
        # Clamp values to valid range
        threat.likelihood = max(1, min(5, threat.likelihood))
        threat.impact = max(1, min(5, threat.impact))

        # Calculate correct severity label
        expected_label = get_severity_label(threat.likelihood * threat.impact)
        if threat.severity_label != expected_label:
            logger.debug(
                f"Fixed threat {threat.id} severity: {threat.severity_label} -> {expected_label}"
            )
            threat.severity_label = expected_label

        return threat

    def _ensure_unique_threat_ids(self, analysis: StrideAnalysis) -> None:
        """Ensure all threat IDs are unique."""
        seen_ids: set[str] = set()
        counter = 1

        for threat in analysis.threats:
            if threat.id in seen_ids:
                new_id = f"T{counter:03d}"
                while new_id in seen_ids:
                    counter += 1
                    new_id = f"T{counter:03d}"
                logger.debug(f"Renamed duplicate threat ID: {threat.id} -> {new_id}")
                threat.id = new_id

            seen_ids.add(threat.id)
            counter += 1

    def _log_threat_summary(self, analysis: StrideAnalysis) -> None:
        """Log a summary of threats by category and severity."""
        by_category: dict[str, int] = {}
        by_severity: dict[str, int] = {"High": 0, "Medium": 0, "Low": 0}

        for threat in analysis.threats:
            cat = threat.stride_category.value
            by_category[cat] = by_category.get(cat, 0) + 1
            by_severity[threat.severity_label.value] += 1

        logger.info(f"Threats by category: {by_category}")
        logger.info(f"Threats by severity: {by_severity}")



