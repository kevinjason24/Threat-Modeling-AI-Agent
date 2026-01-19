"""DFD Builder Agent - Creates Data Flow Diagrams from system inventory."""

import logging
from typing import TYPE_CHECKING

from ..prompts import DFD_BUILDER_SYSTEM, DFD_BUILDER_USER
from ..schemas import DFDModel, DFDNode, Inventory, NodeType

if TYPE_CHECKING:
    from ..llm import LLMClient

logger = logging.getLogger(__name__)


class DFDBuilderAgent:
    """Builds Data Flow Diagram models from system inventory.

    Creates:
    - DFD nodes (External Entities, Processes, Data Stores)
    - Data flows between nodes
    - Trust boundary mappings
    - DFD notes and caveats
    """

    def __init__(self, llm_client: "LLMClient"):
        self.llm = llm_client

    def run(self, inventory: Inventory) -> DFDModel:
        """Run the DFD builder agent.

        Args:
            inventory: System inventory from extractor agent.

        Returns:
            DFDModel with nodes, flows, and boundaries.
        """
        logger.info("Running DFD Builder Agent...")

        # Convert inventory to JSON for prompt
        inventory_json = inventory.model_dump_json(indent=2)

        # Format the user prompt
        user_prompt = DFD_BUILDER_USER.format(inventory_json=inventory_json)

        # Get LLM response
        result = self.llm.complete_json(
            system_prompt=DFD_BUILDER_SYSTEM,
            user_prompt=user_prompt,
            response_model=DFDModel,
            max_tokens=4096,
        )

        # Validate and fix the DFD
        result = self._validate_dfd(result, inventory)

        logger.info(f"Created DFD with {len(result.nodes)} nodes and {len(result.flows)} flows")

        return result

    def _validate_dfd(self, dfd: DFDModel, inventory: Inventory) -> DFDModel:
        """Validate and fix the DFD model."""
        # Ensure node ID prefixes are correct
        self._fix_node_prefixes(dfd)

        # Ensure all flows reference valid nodes
        self._validate_flows(dfd)

        # Ensure trust boundaries are consistent
        self._sync_trust_boundaries(dfd, inventory)

        # Add missing nodes for actors/components not represented
        self._ensure_complete_nodes(dfd, inventory)

        return dfd

    def _fix_node_prefixes(self, dfd: DFDModel) -> None:
        """Ensure node IDs have correct prefixes based on type."""
        prefix_map = {
            NodeType.EXTERNAL_ENTITY: "EE_",
            NodeType.PROCESS: "P_",
            NodeType.DATA_STORE: "DS_",
        }

        for node in dfd.nodes:
            expected_prefix = prefix_map.get(node.type, "")
            if expected_prefix and not node.id.startswith(expected_prefix):
                old_id = node.id
                # Generate new ID with correct prefix
                base_name = node.id.split("_", 1)[-1] if "_" in node.id else node.id
                node.id = f"{expected_prefix}{base_name}"

                # Update references in flows
                for flow in dfd.flows:
                    if flow.src == old_id:
                        flow.src = node.id
                    if flow.dst == old_id:
                        flow.dst = node.id

                logger.debug(f"Fixed node prefix: {old_id} -> {node.id}")

    def _validate_flows(self, dfd: DFDModel) -> None:
        """Validate that all flows reference existing nodes."""
        valid_node_ids = {node.id for node in dfd.nodes}
        valid_flows = []

        for flow in dfd.flows:
            if flow.src in valid_node_ids and flow.dst in valid_node_ids:
                valid_flows.append(flow)
            else:
                missing = []
                if flow.src not in valid_node_ids:
                    missing.append(f"src={flow.src}")
                if flow.dst not in valid_node_ids:
                    missing.append(f"dst={flow.dst}")
                logger.warning(f"Removing flow {flow.id}: missing nodes {missing}")

        dfd.flows = valid_flows

    def _sync_trust_boundaries(self, dfd: DFDModel, inventory: Inventory) -> None:
        """Sync trust boundaries between DFD and inventory."""
        # If DFD has no trust boundaries but inventory does, copy them
        if not dfd.trust_boundaries and inventory.trust_boundaries:
            dfd.trust_boundaries = inventory.trust_boundaries.copy()

        # Update node trust_boundary references
        boundary_components: dict[str, set[str]] = {}
        for tb in dfd.trust_boundaries:
            boundary_components[tb.id] = set(tb.components_inside)

        # Map component IDs to node IDs (approximate matching)
        for node in dfd.nodes:
            for tb_id, components in boundary_components.items():
                # Check if node label or ID matches any component
                for comp_id in components:
                    if comp_id in node.id or comp_id.lower() in node.label.lower():
                        node.trust_boundary = tb_id
                        break

    def _ensure_complete_nodes(self, dfd: DFDModel, inventory: Inventory) -> None:
        """Ensure all inventory items are represented as nodes."""
        existing_labels = {node.label.lower() for node in dfd.nodes}
        existing_ids = {node.id for node in dfd.nodes}

        nodes_to_add = []

        # Check actors -> External Entities
        for actor in inventory.actors:
            if actor.name.lower() not in existing_labels:
                node_id = f"EE_{actor.id}"
                if node_id not in existing_ids:
                    nodes_to_add.append(DFDNode(
                        id=node_id,
                        label=actor.name,
                        type=NodeType.EXTERNAL_ENTITY,
                        trust_boundary=None,
                    ))

        # Check components -> Processes
        for comp in inventory.components:
            if comp.name.lower() not in existing_labels:
                node_id = f"P_{comp.id}"
                if node_id not in existing_ids:
                    nodes_to_add.append(DFDNode(
                        id=node_id,
                        label=comp.name,
                        type=NodeType.PROCESS,
                        trust_boundary=None,
                    ))

        # Check data stores
        for ds in inventory.data_stores:
            if ds.name.lower() not in existing_labels:
                node_id = f"DS_{ds.id}"
                if node_id not in existing_ids:
                    nodes_to_add.append(DFDNode(
                        id=node_id,
                        label=ds.name,
                        type=NodeType.DATA_STORE,
                        trust_boundary=None,
                    ))

        if nodes_to_add:
            logger.info(f"Adding {len(nodes_to_add)} missing nodes to DFD")
            dfd.nodes.extend(nodes_to_add)
            dfd.dfd_notes.append(
                f"Note: {len(nodes_to_add)} nodes added automatically from inventory"
            )



