"""Planner Agent - Analyzes design docs and creates threat modeling plan."""

import logging
from typing import TYPE_CHECKING

from ..prompts import PLANNER_SYSTEM, PLANNER_USER
from ..schemas import PlannerOutput, PlanStep

if TYPE_CHECKING:
    from ..llm import LLMClient

logger = logging.getLogger(__name__)


class PlannerAgent:
    """Analyzes design documents and creates a structured threat modeling plan.

    The Planner Agent is the first step in the pipeline. It:
    1. Summarizes the design document
    2. Identifies missing details (unknowns)
    3. Creates a step-by-step plan for subsequent agents
    """

    def __init__(self, llm_client: "LLMClient"):
        self.llm = llm_client

    def run(self, document: str) -> PlannerOutput:
        """Run the planner agent on a design document.

        Args:
            document: The raw design document text.

        Returns:
            PlannerOutput with summary, unknowns, and execution plan.
        """
        logger.info("Running Planner Agent...")

        # Handle empty or very short documents
        if not document or len(document.strip()) < 50:
            logger.warning("Document is empty or too short, creating minimal plan")
            return self._create_minimal_plan(document)

        # Format the user prompt
        user_prompt = PLANNER_USER.format(document=document)

        # Get LLM response
        result = self.llm.complete_json(
            system_prompt=PLANNER_SYSTEM,
            user_prompt=user_prompt,
            response_model=PlannerOutput,
            max_tokens=2048,
        )

        logger.info(f"Planner identified {len(result.key_unknowns)} unknowns")
        logger.info(f"Planner created {len(result.plan)} step plan")

        # Ensure all required agents are in the plan
        result = self._ensure_complete_plan(result)

        return result

    def _create_minimal_plan(self, document: str) -> PlannerOutput:
        """Create a minimal plan for empty or short documents."""
        return PlannerOutput(
            doc_summary="Insufficient document content provided for analysis.",
            key_unknowns=[
                "Document content is missing or too short",
                "System architecture unknown",
                "Components and services unknown",
                "Data flows unknown",
                "Authentication mechanisms unknown",
            ],
            plan=self._get_default_plan(),
        )

    def _get_default_plan(self) -> list[PlanStep]:
        """Get the default execution plan."""
        return [
            PlanStep(
                step_number=1,
                agent="ExtractorAgent",
                description="Extract system inventory from document",
                inputs=["raw document", "planner summary"],
                outputs=["actors", "components", "data stores", "entry points", "integrations"],
            ),
            PlanStep(
                step_number=2,
                agent="DFDBuilderAgent",
                description="Build data flow diagram from inventory",
                inputs=["inventory"],
                outputs=["DFD nodes", "DFD flows", "trust boundaries"],
            ),
            PlanStep(
                step_number=3,
                agent="StrideAnalystAgent",
                description="Perform STRIDE threat analysis",
                inputs=["DFD model", "inventory"],
                outputs=["threats with scoring"],
            ),
            PlanStep(
                step_number=4,
                agent="AbuseWriterAgent",
                description="Write abuse cases for top threats",
                inputs=["inventory", "top threats"],
                outputs=["abuse cases"],
            ),
            PlanStep(
                step_number=5,
                agent="ChecklistWriterAgent",
                description="Generate security engineering checklist",
                inputs=["inventory", "threats"],
                outputs=["categorized checklist"],
            ),
            PlanStep(
                step_number=6,
                agent="QACheckerAgent",
                description="Validate completeness and consistency",
                inputs=["complete threat model"],
                outputs=["QA result", "issues"],
            ),
        ]

    def _ensure_complete_plan(self, plan: PlannerOutput) -> PlannerOutput:
        """Ensure all required agents are included in the plan."""
        required_agents = {
            "ExtractorAgent",
            "DFDBuilderAgent",
            "StrideAnalystAgent",
            "AbuseWriterAgent",
            "ChecklistWriterAgent",
            "QACheckerAgent",
        }

        existing_agents = {step.agent for step in plan.plan}
        missing_agents = required_agents - existing_agents

        if missing_agents:
            logger.warning(f"Plan missing agents: {missing_agents}, adding defaults")
            # Replace with complete default plan to ensure correct ordering
            plan.plan = self._get_default_plan()

        return plan



