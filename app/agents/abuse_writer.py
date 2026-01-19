"""Abuse Case Writer Agent - Creates attack scenarios from threats."""

import logging
from typing import TYPE_CHECKING

from ..prompts import ABUSE_WRITER_SYSTEM, ABUSE_WRITER_USER
from ..schemas import AbuseCasesOutput, Inventory, StrideAnalysis, Threat
from ..scoring import rank_threats_by_severity

if TYPE_CHECKING:
    from ..llm import LLMClient

logger = logging.getLogger(__name__)


class AbuseWriterAgent:
    """Writes abuse cases describing attack scenarios.

    Creates realistic attack narratives based on:
    - Top threats from STRIDE analysis
    - System inventory and entry points
    - Attacker profiles and goals
    """

    def __init__(self, llm_client: "LLMClient"):
        self.llm = llm_client

    def run(self, inventory: Inventory, stride_analysis: StrideAnalysis) -> AbuseCasesOutput:
        """Run the abuse case writer agent.

        Args:
            inventory: System inventory.
            stride_analysis: STRIDE analysis with threats.

        Returns:
            AbuseCasesOutput with abuse cases.
        """
        logger.info("Running Abuse Case Writer Agent...")

        # Get top threats (prioritize high severity)
        top_threats = self._select_top_threats(stride_analysis.threats, max_threats=10)

        # Convert to JSON for prompt
        inventory_json = inventory.model_dump_json(indent=2)
        threats_json = self._threats_to_json(top_threats)

        # Format the user prompt
        user_prompt = ABUSE_WRITER_USER.format(
            inventory_json=inventory_json,
            threats_json=threats_json,
        )

        # Get LLM response
        result = self.llm.complete_json(
            system_prompt=ABUSE_WRITER_SYSTEM,
            user_prompt=user_prompt,
            response_model=AbuseCasesOutput,
            max_tokens=4096,
        )

        # Validate abuse cases
        result = self._validate_abuse_cases(result, stride_analysis)

        logger.info(f"Created {len(result.abuse_cases)} abuse cases")

        return result

    def _select_top_threats(self, threats: list[Threat], max_threats: int = 10) -> list[Threat]:
        """Select top threats for abuse case generation.

        Prioritizes:
        1. High severity threats
        2. Threats affecting entry points
        3. Diverse STRIDE categories
        """
        if not threats:
            return []

        # Rank by severity
        ranked = rank_threats_by_severity(threats)

        # Ensure category diversity
        selected: list[Threat] = []
        categories_covered: set[str] = set()

        # First pass: one threat per category
        for threat in ranked:
            if threat.stride_category.value not in categories_covered:
                selected.append(threat)
                categories_covered.add(threat.stride_category.value)
                if len(selected) >= max_threats:
                    break

        # Second pass: fill remaining slots with highest severity
        if len(selected) < max_threats:
            for threat in ranked:
                if threat not in selected:
                    selected.append(threat)
                    if len(selected) >= max_threats:
                        break

        return selected

    def _threats_to_json(self, threats: list[Threat]) -> str:
        """Convert threats to JSON string."""
        import json
        return json.dumps(
            [t.model_dump() for t in threats],
            indent=2,
            default=str,
        )

    def _validate_abuse_cases(
        self, result: AbuseCasesOutput, stride_analysis: StrideAnalysis
    ) -> AbuseCasesOutput:
        """Validate abuse cases."""
        valid_threat_ids = {t.id for t in stride_analysis.threats}

        for ac in result.abuse_cases:
            # Validate related threats exist
            valid_refs = []
            for threat_id in ac.related_threats:
                if threat_id in valid_threat_ids:
                    valid_refs.append(threat_id)
                else:
                    logger.warning(f"Abuse case {ac.id} references unknown threat {threat_id}")
            ac.related_threats = valid_refs

            # Ensure steps are within bounds (3-7)
            if len(ac.steps) < 3:
                logger.warning(f"Abuse case {ac.id} has only {len(ac.steps)} steps, padding")
                while len(ac.steps) < 3:
                    ac.steps.append("Additional exploitation step (details needed)")

            if len(ac.steps) > 7:
                logger.warning(f"Abuse case {ac.id} has {len(ac.steps)} steps, truncating")
                ac.steps = ac.steps[:7]

        # Ensure unique IDs
        self._ensure_unique_ids(result)

        return result

    def _ensure_unique_ids(self, result: AbuseCasesOutput) -> None:
        """Ensure all abuse case IDs are unique."""
        seen_ids: set[str] = set()
        counter = 1

        for ac in result.abuse_cases:
            if ac.id in seen_ids:
                new_id = f"AC{counter:03d}"
                while new_id in seen_ids:
                    counter += 1
                    new_id = f"AC{counter:03d}"
                logger.debug(f"Renamed duplicate abuse case ID: {ac.id} -> {new_id}")
                ac.id = new_id

            seen_ids.add(ac.id)
            counter += 1



