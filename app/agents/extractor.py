"""Extractor Agent - Extracts system inventory from design documents."""

import logging
from typing import TYPE_CHECKING

from ..prompts import EXTRACTOR_SYSTEM, EXTRACTOR_USER
from ..schemas import Inventory, PlannerOutput

if TYPE_CHECKING:
    from ..llm import LLMClient

logger = logging.getLogger(__name__)


class ExtractorAgent:
    """Extracts structured system inventory from design documents.

    The Extractor Agent identifies:
    - Actors (users, admins, services, third-parties)
    - Components and services
    - Data stores
    - Entry points
    - External integrations
    - Authentication/authorization configuration
    - Trust boundaries
    - Assumptions and unknowns
    """

    def __init__(self, llm_client: "LLMClient"):
        self.llm = llm_client

    def run(self, document: str, planner_output: PlannerOutput) -> Inventory:
        """Run the extractor agent.

        Args:
            document: The raw design document text.
            planner_output: Output from the planner agent.

        Returns:
            Inventory with all extracted system components.
        """
        logger.info("Running Extractor Agent...")

        # Format the user prompt
        user_prompt = EXTRACTOR_USER.format(
            doc_summary=planner_output.doc_summary,
            document=document,
        )

        # Get LLM response
        result = self.llm.complete_json(
            system_prompt=EXTRACTOR_SYSTEM,
            user_prompt=user_prompt,
            response_model=Inventory,
            max_tokens=4096,
        )

        # Merge unknowns from planner
        all_unknowns = set(result.unknowns)
        all_unknowns.update(planner_output.key_unknowns)
        result.unknowns = list(all_unknowns)

        # Validate and enhance the inventory
        result = self._validate_inventory(result)

        logger.info(f"Extracted {len(result.actors)} actors")
        logger.info(f"Extracted {len(result.components)} components")
        logger.info(f"Extracted {len(result.data_stores)} data stores")
        logger.info(f"Extracted {len(result.entry_points)} entry points")
        logger.info(f"Identified {len(result.unknowns)} unknowns")

        return result

    def _validate_inventory(self, inventory: Inventory) -> Inventory:
        """Validate and enhance the extracted inventory."""
        # Ensure all items have unique IDs
        self._ensure_unique_ids(inventory)

        # Add default unknowns if critical info is missing
        self._add_default_unknowns(inventory)

        # Ensure trust boundaries reference valid components
        self._validate_trust_boundaries(inventory)

        return inventory

    def _ensure_unique_ids(self, inventory: Inventory) -> None:
        """Ensure all items have unique IDs, fixing duplicates if found."""
        seen_ids: set[str] = set()

        for collection_name in ["actors", "components", "data_stores", "entry_points", "integrations"]:
            collection = getattr(inventory, collection_name)
            for i, item in enumerate(collection):
                if item.id in seen_ids:
                    # Generate a new unique ID
                    prefix = item.id.split("_")[0] if "_" in item.id else item.id[:2]
                    new_id = f"{prefix}_{collection_name}_{i:03d}"
                    logger.warning(f"Duplicate ID {item.id} renamed to {new_id}")
                    item.id = new_id
                seen_ids.add(item.id)

    def _add_default_unknowns(self, inventory: Inventory) -> None:
        """Add unknowns for missing critical information."""
        unknowns_to_add = []

        # Check for missing auth info
        if not inventory.auth_config.authn_methods:
            unknowns_to_add.append("Unknown: Authentication methods not specified")

        if inventory.auth_config.authz_model == "Unknown":
            unknowns_to_add.append("Unknown: Authorization model not specified")

        if inventory.auth_config.mfa_enabled is None:
            unknowns_to_add.append("Unknown: MFA status not specified")

        # Check for data stores without encryption info
        for ds in inventory.data_stores:
            if ds.encryption_at_rest is None:
                unknowns_to_add.append(f"Unknown: Encryption at rest for {ds.name} not specified")

        # Check for entry points without auth
        for ep in inventory.entry_points:
            if ep.authentication == "Unknown":
                unknowns_to_add.append(f"Unknown: Authentication for entry point {ep.name} not specified")

        # Deduplicate and add
        existing = set(inventory.unknowns)
        for unknown in unknowns_to_add:
            if unknown not in existing:
                inventory.unknowns.append(unknown)

    def _validate_trust_boundaries(self, inventory: Inventory) -> None:
        """Validate that trust boundaries reference valid components."""
        valid_component_ids = {c.id for c in inventory.components}
        valid_component_ids.update(ds.id for ds in inventory.data_stores)

        for tb in inventory.trust_boundaries:
            valid_refs = []
            for comp_id in tb.components_inside:
                if comp_id in valid_component_ids:
                    valid_refs.append(comp_id)
                else:
                    logger.warning(f"Trust boundary {tb.id} references unknown component {comp_id}")
            tb.components_inside = valid_refs



