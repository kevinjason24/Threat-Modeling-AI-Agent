"""Pipeline orchestrator - runs sub-agents in sequence."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Callable

from .agents import (
    AbuseWriterAgent,
    ChecklistWriterAgent,
    DFDBuilderAgent,
    ExtractorAgent,
    PlannerAgent,
    QACheckerAgent,
    StrideAnalystAgent,
)
from .llm import LLMClient, get_llm_client
from .redact import redact_text
from .render_markdown import render_markdown_report
from .render_mermaid import render_mermaid_dfd
from .schemas import (
    NextStep,
    PipelineState,
    RiskSummary,
    SeverityLabel,
    StrideAnalysis,
    ThreatModelReport,
)
from .scoring import rank_threats_by_severity

logger = logging.getLogger(__name__)


class ThreatModelPipeline:
    """Orchestrates the threat modeling pipeline.

    Pipeline stages:
    1. Planner: Analyze document, create plan
    2. Extractor: Extract system inventory
    3. DFD Builder: Create data flow diagram
    4. STRIDE Analyst: Identify threats
    5. Abuse Writer: Create abuse cases
    6. Checklist Writer: Generate security checklist
    7. QA Checker: Validate completeness and consistency
    8. Report Assembly: Generate final output
    """

    def __init__(
        self,
        llm_client: LLMClient | None = None,
        on_stage_complete: Callable[[str, str], None] | None = None,
    ):
        """Initialize the pipeline.

        Args:
            llm_client: LLM client instance. If None, creates default.
            on_stage_complete: Callback when a stage completes (stage_name, status).
        """
        self.llm = llm_client or get_llm_client()
        self.on_stage_complete = on_stage_complete or (lambda s, m: None)

        # Initialize agents
        self.planner = PlannerAgent(self.llm)
        self.extractor = ExtractorAgent(self.llm)
        self.dfd_builder = DFDBuilderAgent(self.llm)
        self.stride_analyst = StrideAnalystAgent(self.llm)
        self.abuse_writer = AbuseWriterAgent(self.llm)
        self.checklist_writer = ChecklistWriterAgent(self.llm)
        self.qa_checker = QACheckerAgent(self.llm)

    def run(
        self,
        input_text: str,
        input_path: str | None = None,
        redact: bool = False,
    ) -> ThreatModelReport:
        """Run the complete threat modeling pipeline.

        Args:
            input_text: The design document text.
            input_path: Optional path to the input file.
            redact: Whether to redact secrets before processing.

        Returns:
            Complete ThreatModelReport.
        """
        logger.info("Starting threat modeling pipeline")

        # Initialize state
        state = PipelineState(
            raw_input=input_text,
            input_path=input_path,
        )

        # Redact secrets if requested
        if redact:
            logger.info("Redacting secrets from input")
            redacted_text, summary = redact_text(input_text)
            logger.info(summary)
            state.raw_input = redacted_text

        try:
            # Stage 1: Planner
            self._notify("Planner", "running")
            state.planner_output = self.planner.run(state.raw_input)
            self._notify("Planner", "complete")

            # Stage 2: Extractor
            self._notify("Extractor", "running")
            state.inventory = self.extractor.run(state.raw_input, state.planner_output)
            self._notify("Extractor", "complete")

            # Stage 3: DFD Builder
            self._notify("DFD Builder", "running")
            state.dfd_model = self.dfd_builder.run(state.inventory)
            self._notify("DFD Builder", "complete")

            # Stage 4: STRIDE Analyst
            self._notify("STRIDE Analyst", "running")
            state.stride_analysis = self.stride_analyst.run(state.dfd_model, state.inventory)
            self._notify("STRIDE Analyst", "complete")

            # Stage 5: Abuse Writer
            self._notify("Abuse Writer", "running")
            state.abuse_cases = self.abuse_writer.run(state.inventory, state.stride_analysis)
            self._notify("Abuse Writer", "complete")

            # Stage 6: Checklist Writer
            self._notify("Checklist Writer", "running")
            state.checklist = self.checklist_writer.run(state.inventory, state.stride_analysis)
            self._notify("Checklist Writer", "complete")

            # Stage 7: QA Checker
            self._notify("QA Checker", "running")
            state.qa_result = self.qa_checker.run(
                state.inventory,
                state.dfd_model,
                state.stride_analysis,
                state.abuse_cases,
                state.checklist,
            )
            self._notify("QA Checker", "complete")

            # Stage 8: Assemble Report
            self._notify("Report Assembly", "running")
            report = self._assemble_report(state)
            self._notify("Report Assembly", "complete")

            logger.info("Pipeline completed successfully")
            return report

        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            state.errors.append(str(e))
            raise

    def _notify(self, stage: str, status: str) -> None:
        """Notify callback of stage progress."""
        logger.info(f"Stage '{stage}': {status}")
        self.on_stage_complete(stage, status)

    def _assemble_report(self, state: PipelineState) -> ThreatModelReport:
        """Assemble the final threat model report."""
        assert state.planner_output is not None
        assert state.inventory is not None
        assert state.dfd_model is not None
        assert state.stride_analysis is not None
        assert state.abuse_cases is not None
        assert state.checklist is not None
        assert state.qa_result is not None

        # Generate Mermaid diagram
        mermaid_diagram = render_mermaid_dfd(state.dfd_model)

        # Generate overview
        overview = self._generate_overview(state)

        # Combine assumptions and unknowns
        assumptions = list(state.inventory.assumptions)
        unknowns = list(state.inventory.unknowns)
        unknowns.extend(state.planner_output.key_unknowns)
        unknowns = list(set(unknowns))  # Deduplicate

        # Generate top risks
        top_risks = self._generate_top_risks(state.stride_analysis)

        # Generate next steps
        next_steps = self._generate_next_steps(state)

        return ThreatModelReport(
            generated_at=datetime.now().isoformat(),
            input_document=state.input_path or "stdin",
            version="1.0",
            overview=overview,
            assumptions=assumptions,
            unknowns=unknowns,
            inventory=state.inventory,
            dfd_model=state.dfd_model,
            mermaid_diagram=mermaid_diagram,
            stride_analysis=state.stride_analysis,
            abuse_cases=state.abuse_cases.abuse_cases,
            checklist=state.checklist,
            top_risks=top_risks,
            next_steps=next_steps,
            qa_result=state.qa_result,
        )

    def _generate_overview(self, state: PipelineState) -> str:
        """Generate the overview section."""
        assert state.planner_output is not None
        assert state.inventory is not None
        assert state.stride_analysis is not None

        # Count threats by severity
        high_count = sum(
            1 for t in state.stride_analysis.threats
            if t.severity_label == SeverityLabel.HIGH
        )
        medium_count = sum(
            1 for t in state.stride_analysis.threats
            if t.severity_label == SeverityLabel.MEDIUM
        )

        overview = f"""{state.planner_output.doc_summary}

This threat model analyzes a system with {len(state.inventory.components)} components, \
{len(state.inventory.entry_points)} entry points, and {len(state.inventory.data_stores)} data stores. \
The analysis identified {len(state.stride_analysis.threats)} potential threats, \
including {high_count} high-severity and {medium_count} medium-severity issues.

Key security considerations include authentication/authorization mechanisms, \
data protection requirements, and external integration security."""

        return overview

    def _generate_top_risks(self, stride_analysis: StrideAnalysis) -> list[RiskSummary]:
        """Generate top risk summaries."""
        # Group high-severity threats
        high_threats = [
            t for t in stride_analysis.threats
            if t.severity_label == SeverityLabel.HIGH
        ]

        if not high_threats:
            # Fall back to medium severity if no high
            high_threats = [
                t for t in stride_analysis.threats
                if t.severity_label == SeverityLabel.MEDIUM
            ][:5]

        # Rank and take top 5
        ranked = rank_threats_by_severity(high_threats)[:5]

        risks = []
        for i, threat in enumerate(ranked, 1):
            risks.append(RiskSummary(
                risk_id=f"R{i:03d}",
                threat_ids=[threat.id],
                risk_description=threat.title,
                aggregated_severity=threat.severity_label,
                key_mitigations=threat.mitigations[:3],
            ))

        return risks

    def _generate_next_steps(self, state: PipelineState) -> list[NextStep]:
        """Generate prioritized next steps."""
        assert state.stride_analysis is not None
        assert state.checklist is not None

        steps = []
        priority = 1

        # High severity threats -> immediate action
        high_threats = [
            t for t in state.stride_analysis.threats
            if t.severity_label == SeverityLabel.HIGH
        ]

        for threat in high_threats[:3]:
            if threat.mitigations:
                steps.append(NextStep(
                    priority=priority,
                    action=threat.mitigations[0],
                    rationale=f"Addresses high-severity threat: {threat.title}",
                    owner_suggestion="Security Team + Dev Team",
                ))
                priority += 1

        # High priority checklist items
        for category in state.checklist.categories:
            for item in category.items:
                if item.priority == "High" and priority <= 7:
                    steps.append(NextStep(
                        priority=priority,
                        action=item.description,
                        rationale=f"High-priority item from {category.category}",
                        owner_suggestion="Dev Team",
                    ))
                    priority += 1
                    break  # One per category

        # Ensure we have at least 5 steps
        if len(steps) < 5:
            default_steps = [
                ("Review and validate identified assumptions", "Engineering Lead"),
                ("Address unknowns through architecture review", "Security Team"),
                ("Implement monitoring for detection signals", "Platform Team"),
                ("Schedule security review before deployment", "Security Team"),
                ("Document security decisions and rationale", "Engineering Lead"),
            ]

            for action, owner in default_steps:
                if len(steps) >= 7:
                    break
                steps.append(NextStep(
                    priority=priority,
                    action=action,
                    rationale="Standard security practice",
                    owner_suggestion=owner,
                ))
                priority += 1

        return steps[:7]


def run_pipeline(
    input_text: str,
    input_path: str | None = None,
    output_md: str | None = None,
    output_json: str | None = None,
    redact: bool = False,
    verbose: bool = False,
) -> ThreatModelReport:
    """Convenience function to run the pipeline and save outputs.

    Args:
        input_text: Design document text.
        input_path: Path to input file (for reference).
        output_md: Path to save Markdown report.
        output_json: Path to save JSON output.
        redact: Whether to redact secrets.
        verbose: Enable verbose logging.

    Returns:
        The generated ThreatModelReport.
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Run pipeline
    pipeline = ThreatModelPipeline()
    report = pipeline.run(input_text, input_path, redact)

    # Save Markdown report
    if output_md:
        md_content = render_markdown_report(report)
        Path(output_md).parent.mkdir(parents=True, exist_ok=True)
        Path(output_md).write_text(md_content)
        logger.info(f"Saved Markdown report to {output_md}")

    # Save JSON output
    if output_json:
        json_content = report.model_dump_json(indent=2)
        Path(output_json).parent.mkdir(parents=True, exist_ok=True)
        Path(output_json).write_text(json_content)
        logger.info(f"Saved JSON output to {output_json}")

    return report



