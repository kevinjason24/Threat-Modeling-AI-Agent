"""Checklist Writer Agent - Generates security engineering checklists."""

import logging
from typing import TYPE_CHECKING

from ..prompts import CHECKLIST_WRITER_SYSTEM, CHECKLIST_WRITER_USER
from ..schemas import ChecklistCategory, EngineeringChecklist, Inventory, StrideAnalysis

if TYPE_CHECKING:
    from ..llm import LLMClient

logger = logging.getLogger(__name__)


class ChecklistWriterAgent:
    """Generates security engineering checklists.

    Creates testable, actionable checklists in categories:
    - AuthN/AuthZ
    - Input Validation
    - Secrets & Key Management
    - Data Protection
    - Logging/Monitoring
    - Rate Limiting/DoS
    - Supply Chain
    - Infra/Cloud
    """

    REQUIRED_CATEGORIES = [
        "AuthN/AuthZ",
        "Input Validation",
        "Secrets & Key Management",
        "Data Protection",
        "Logging/Monitoring",
        "Rate Limiting/DoS",
        "Supply Chain",
        "Infra/Cloud",
    ]

    def __init__(self, llm_client: "LLMClient"):
        self.llm = llm_client

    def run(self, inventory: Inventory, stride_analysis: StrideAnalysis) -> EngineeringChecklist:
        """Run the checklist writer agent.

        Args:
            inventory: System inventory.
            stride_analysis: STRIDE analysis with threats.

        Returns:
            EngineeringChecklist with categorized items.
        """
        logger.info("Running Checklist Writer Agent...")

        # Convert to JSON for prompt
        inventory_json = inventory.model_dump_json(indent=2)
        threats_json = self._threats_summary_json(stride_analysis)

        # Format the user prompt
        user_prompt = CHECKLIST_WRITER_USER.format(
            inventory_json=inventory_json,
            threats_json=threats_json,
        )

        # Get LLM response
        result = self.llm.complete_json(
            system_prompt=CHECKLIST_WRITER_SYSTEM,
            user_prompt=user_prompt,
            response_model=EngineeringChecklist,
            max_tokens=4096,
        )

        # Validate and ensure all categories present
        result = self._validate_checklist(result, stride_analysis)

        total_items = sum(len(cat.items) for cat in result.categories)
        logger.info(f"Generated checklist with {len(result.categories)} categories, {total_items} items")

        return result

    def _threats_summary_json(self, stride_analysis: StrideAnalysis) -> str:
        """Create a summary of threats for the prompt."""
        import json

        summary = []
        for threat in stride_analysis.threats:
            summary.append({
                "id": threat.id,
                "category": threat.stride_category.value,
                "title": threat.title,
                "severity": threat.severity_label.value,
                "mitigations": threat.mitigations[:3],  # Top 3 mitigations
            })

        return json.dumps(summary, indent=2)

    def _validate_checklist(
        self, checklist: EngineeringChecklist, stride_analysis: StrideAnalysis
    ) -> EngineeringChecklist:
        """Validate and ensure checklist has all required categories."""
        valid_threat_ids = {t.id for t in stride_analysis.threats}

        # Check existing categories
        existing_categories = {cat.category for cat in checklist.categories}

        # Add missing categories
        for required_cat in self.REQUIRED_CATEGORIES:
            if required_cat not in existing_categories:
                logger.warning(f"Adding missing checklist category: {required_cat}")
                checklist.categories.append(ChecklistCategory(
                    category=required_cat,
                    items=[],
                ))

        # Validate threat references and ensure unique IDs
        seen_ids: set[str] = set()
        item_counter = 1

        for category in checklist.categories:
            for item in category.items:
                # Validate threat references
                valid_refs = []
                for threat_id in item.related_threats:
                    if threat_id in valid_threat_ids:
                        valid_refs.append(threat_id)
                item.related_threats = valid_refs

                # Ensure unique ID
                if item.id in seen_ids or not item.id:
                    cat_prefix = self._get_category_prefix(category.category)
                    new_id = f"CHK-{cat_prefix}-{item_counter:03d}"
                    while new_id in seen_ids:
                        item_counter += 1
                        new_id = f"CHK-{cat_prefix}-{item_counter:03d}"
                    item.id = new_id

                seen_ids.add(item.id)
                item_counter += 1

                # Validate priority
                if item.priority not in ["High", "Medium", "Low"]:
                    item.priority = "Medium"

        # Sort categories by required order
        category_order = {cat: i for i, cat in enumerate(self.REQUIRED_CATEGORIES)}
        checklist.categories.sort(
            key=lambda c: category_order.get(c.category, len(self.REQUIRED_CATEGORIES))
        )

        return checklist

    def _get_category_prefix(self, category: str) -> str:
        """Get a short prefix for checklist item IDs."""
        prefixes = {
            "AuthN/AuthZ": "AUTH",
            "Input Validation": "INPUT",
            "Secrets & Key Management": "SECRET",
            "Data Protection": "DATA",
            "Logging/Monitoring": "LOG",
            "Rate Limiting/DoS": "DOS",
            "Supply Chain": "SUPPLY",
            "Infra/Cloud": "INFRA",
        }
        return prefixes.get(category, "GEN")



