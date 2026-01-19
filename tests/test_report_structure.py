"""Tests for report structure and schema validation."""

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from app.schemas import (
    # Enums
    ActorType,
    NodeType,
    StrideCategory,
    SeverityLabel,
    DataSensitivity,
    # Models
    Actor,
    Component,
    DataStore,
    TrustBoundary,
    Inventory,
    DFDNode,
    DFDFlow,
    DFDModel,
    Threat,
    StrideAnalysis,
    AbuseCase,
    ChecklistItem,
    ChecklistCategory,
    EngineeringChecklist,
    QAIssue,
    QAResult,
    RiskSummary,
    NextStep,
    ThreatModelReport,
    PipelineState,
    PlannerOutput,
    PlanStep,
)
from app.render_markdown import render_markdown_report


class TestEnums:
    """Tests for enum values."""

    def test_actor_types(self):
        """Test ActorType enum values."""
        assert ActorType.USER.value == "user"
        assert ActorType.ADMIN.value == "admin"
        assert ActorType.SERVICE.value == "service"
        assert ActorType.THIRD_PARTY.value == "3rd-party"

    def test_node_types(self):
        """Test NodeType enum values."""
        assert NodeType.EXTERNAL_ENTITY.value == "EE"
        assert NodeType.PROCESS.value == "P"
        assert NodeType.DATA_STORE.value == "DS"

    def test_stride_categories(self):
        """Test StrideCategory enum values."""
        assert StrideCategory.SPOOFING.value == "S"
        assert StrideCategory.TAMPERING.value == "T"
        assert StrideCategory.REPUDIATION.value == "R"
        assert StrideCategory.INFO_DISCLOSURE.value == "I"
        assert StrideCategory.DENIAL_OF_SERVICE.value == "D"
        assert StrideCategory.ELEVATION_OF_PRIVILEGE.value == "E"

    def test_severity_labels(self):
        """Test SeverityLabel enum values."""
        assert SeverityLabel.LOW.value == "Low"
        assert SeverityLabel.MEDIUM.value == "Medium"
        assert SeverityLabel.HIGH.value == "High"


class TestInventoryModels:
    """Tests for inventory-related models."""

    def test_actor_creation(self):
        """Test Actor model creation."""
        actor = Actor(
            id="A001",
            name="Admin User",
            type=ActorType.ADMIN,
            description="System administrator",
            privileges=["read", "write", "delete"],
        )
        assert actor.id == "A001"
        assert actor.type == ActorType.ADMIN

    def test_component_defaults(self):
        """Test Component model defaults."""
        comp = Component(id="C001", name="API Gateway")
        assert comp.technology == "Unknown"
        assert comp.exposed_ports == []
        assert comp.responsibilities == []

    def test_data_store_with_sensitivity(self):
        """Test DataStore with data sensitivity."""
        ds = DataStore(
            id="DS001",
            name="User DB",
            type="PostgreSQL",
            data_types=[DataSensitivity.PII, DataSensitivity.CREDENTIALS],
        )
        assert DataSensitivity.PII in ds.data_types

    def test_inventory_aggregation(self):
        """Test Inventory model aggregation."""
        inventory = Inventory(
            actors=[Actor(id="A001", name="User", type=ActorType.USER)],
            components=[Component(id="C001", name="API")],
            data_stores=[DataStore(id="DS001", name="DB", type="Postgres")],
            assumptions=["System uses HTTPS"],
            unknowns=["MFA configuration unknown"],
        )
        assert len(inventory.actors) == 1
        assert len(inventory.assumptions) == 1


class TestDFDModels:
    """Tests for DFD-related models."""

    def test_dfd_node_prefix_convention(self):
        """Test that node IDs follow prefix convention."""
        ee = DFDNode(id="EE_User", label="User", type=NodeType.EXTERNAL_ENTITY)
        proc = DFDNode(id="P_API", label="API", type=NodeType.PROCESS)
        ds = DFDNode(id="DS_DB", label="Database", type=NodeType.DATA_STORE)

        assert ee.id.startswith("EE_")
        assert proc.id.startswith("P_")
        assert ds.id.startswith("DS_")

    def test_dfd_flow_boundary_crossing(self):
        """Test DFDFlow with boundary crossing."""
        flow = DFDFlow(
            id="F001",
            src="EE_User",
            dst="P_API",
            data="HTTP Request",
            crosses_boundary=True,
            boundary_crossed="Internet/DMZ",
        )
        assert flow.crosses_boundary is True
        assert flow.boundary_crossed == "Internet/DMZ"

    def test_dfd_model_complete(self):
        """Test complete DFD model."""
        dfd = DFDModel(
            nodes=[
                DFDNode(id="EE_User", label="User", type=NodeType.EXTERNAL_ENTITY),
                DFDNode(id="P_API", label="API", type=NodeType.PROCESS),
            ],
            flows=[
                DFDFlow(id="F001", src="EE_User", dst="P_API", data="Request"),
            ],
            trust_boundaries=[
                TrustBoundary(id="TB001", name="DMZ"),
            ],
            dfd_notes=["Note: Simplified diagram"],
        )
        assert len(dfd.nodes) == 2
        assert len(dfd.flows) == 1


class TestThreatModels:
    """Tests for threat-related models."""

    def test_threat_required_fields(self):
        """Test Threat model required fields."""
        threat = Threat(
            id="T001",
            stride_category=StrideCategory.SPOOFING,
            affected_element="P_API",
            title="JWT Spoofing",
            description="Attacker forges JWT tokens",
            likelihood=3,
            impact=4,
            severity_label=SeverityLabel.MEDIUM,
        )
        assert threat.id == "T001"
        assert threat.stride_category == StrideCategory.SPOOFING

    def test_threat_likelihood_range(self):
        """Test Threat likelihood must be 1-5."""
        with pytest.raises(ValidationError):
            Threat(
                id="T001",
                stride_category=StrideCategory.SPOOFING,
                affected_element="P_API",
                title="Test",
                description="Test",
                likelihood=6,  # Invalid
                impact=3,
                severity_label=SeverityLabel.MEDIUM,
            )

    def test_threat_impact_range(self):
        """Test Threat impact must be 1-5."""
        with pytest.raises(ValidationError):
            Threat(
                id="T001",
                stride_category=StrideCategory.SPOOFING,
                affected_element="P_API",
                title="Test",
                description="Test",
                likelihood=3,
                impact=0,  # Invalid
                severity_label=SeverityLabel.LOW,
            )

    def test_stride_analysis(self):
        """Test StrideAnalysis model."""
        analysis = StrideAnalysis(
            threats=[
                Threat(
                    id="T001",
                    stride_category=StrideCategory.SPOOFING,
                    affected_element="P_API",
                    title="Test",
                    description="Test",
                    likelihood=3,
                    impact=3,
                    severity_label=SeverityLabel.MEDIUM,
                )
            ],
            analysis_notes=["Focused on external threats"],
        )
        assert len(analysis.threats) == 1


class TestAbuseCaseModels:
    """Tests for abuse case models."""

    def test_abuse_case_step_count(self):
        """Test AbuseCase step count constraints."""
        # Valid: 3-7 steps
        ac = AbuseCase(
            id="AC001",
            title="Account Takeover",
            attacker_goal="Gain access",
            steps=["Step 1", "Step 2", "Step 3"],
            impacted_assets=["User accounts"],
        )
        assert len(ac.steps) == 3

    def test_abuse_case_too_few_steps(self):
        """Test AbuseCase rejects too few steps."""
        with pytest.raises(ValidationError):
            AbuseCase(
                id="AC001",
                title="Test",
                attacker_goal="Test",
                steps=["Step 1", "Step 2"],  # Too few
            )

    def test_abuse_case_too_many_steps(self):
        """Test AbuseCase rejects too many steps."""
        with pytest.raises(ValidationError):
            AbuseCase(
                id="AC001",
                title="Test",
                attacker_goal="Test",
                steps=["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"],  # Too many
            )


class TestChecklistModels:
    """Tests for checklist models."""

    def test_checklist_item(self):
        """Test ChecklistItem model."""
        item = ChecklistItem(
            id="CHK-AUTH-001",
            description="Verify JWT signature validation",
            priority="High",
            related_threats=["T001", "T002"],
        )
        assert item.priority == "High"

    def test_checklist_category(self):
        """Test ChecklistCategory model."""
        category = ChecklistCategory(
            category="AuthN/AuthZ",
            items=[
                ChecklistItem(id="CHK-001", description="Test item"),
            ],
        )
        assert category.category == "AuthN/AuthZ"

    def test_default_categories(self):
        """Test EngineeringChecklist default categories."""
        categories = EngineeringChecklist.get_default_categories()
        assert "AuthN/AuthZ" in categories
        assert "Input Validation" in categories
        assert "Secrets & Key Management" in categories


class TestQAModels:
    """Tests for QA models."""

    def test_qa_issue(self):
        """Test QAIssue model."""
        issue = QAIssue(
            severity="warning",
            category="consistency",
            message="Threat references unknown node",
            affected_section="STRIDE Analysis",
            suggested_fix="Update node reference",
        )
        assert issue.severity == "warning"

    def test_qa_result_scores(self):
        """Test QAResult score constraints."""
        result = QAResult(
            passed=True,
            issues=[],
            completeness_score=0.95,
            consistency_score=0.90,
            assumptions_labeled=True,
            summary="All checks passed",
        )
        assert 0 <= result.completeness_score <= 1
        assert 0 <= result.consistency_score <= 1

    def test_qa_result_invalid_scores(self):
        """Test QAResult rejects invalid scores."""
        with pytest.raises(ValidationError):
            QAResult(
                passed=True,
                issues=[],
                completeness_score=1.5,  # Invalid
                consistency_score=0.9,
                summary="Test",
            )


class TestReportModel:
    """Tests for the complete ThreatModelReport."""

    def create_minimal_report(self) -> ThreatModelReport:
        """Create a minimal valid report for testing."""
        return ThreatModelReport(
            generated_at=datetime.now().isoformat(),
            input_document="test.md",
            overview="Test system overview",
            inventory=Inventory(),
            dfd_model=DFDModel(),
            mermaid_diagram="graph TD\n    A-->B",
            stride_analysis=StrideAnalysis(),
            checklist=EngineeringChecklist(),
            qa_result=QAResult(
                passed=True,
                issues=[],
                completeness_score=1.0,
                consistency_score=1.0,
                summary="OK",
            ),
        )

    def test_report_required_fields(self):
        """Test ThreatModelReport has all required fields."""
        report = self.create_minimal_report()
        assert report.generated_at is not None
        assert report.input_document is not None
        assert report.overview is not None

    def test_report_serialization(self):
        """Test ThreatModelReport can be serialized to JSON."""
        report = self.create_minimal_report()
        json_str = report.model_dump_json()
        assert json_str is not None

        # Verify it can be parsed back
        data = json.loads(json_str)
        assert "generated_at" in data
        assert "overview" in data

    def test_report_deserialization(self):
        """Test ThreatModelReport can be deserialized from JSON."""
        report = self.create_minimal_report()
        json_str = report.model_dump_json()

        # Parse back
        data = json.loads(json_str)
        restored = ThreatModelReport.model_validate(data)
        assert restored.input_document == report.input_document


class TestMarkdownRendering:
    """Tests for Markdown report rendering."""

    def create_test_report(self) -> ThreatModelReport:
        """Create a test report with content."""
        return ThreatModelReport(
            generated_at="2024-01-15T10:00:00",
            input_document="test.md",
            overview="This is a test system.",
            assumptions=["Uses HTTPS"],
            unknowns=["MFA status unknown"],
            inventory=Inventory(
                actors=[Actor(id="A001", name="User", type=ActorType.USER)],
                components=[Component(id="C001", name="API")],
            ),
            dfd_model=DFDModel(
                nodes=[DFDNode(id="P_API", label="API", type=NodeType.PROCESS)],
            ),
            mermaid_diagram="graph TD\n    A-->B",
            stride_analysis=StrideAnalysis(
                threats=[
                    Threat(
                        id="T001",
                        stride_category=StrideCategory.SPOOFING,
                        affected_element="P_API",
                        title="Test Threat",
                        description="Test description",
                        likelihood=3,
                        impact=4,
                        severity_label=SeverityLabel.MEDIUM,
                        mitigations=["Mitigation 1"],
                    )
                ]
            ),
            abuse_cases=[
                AbuseCase(
                    id="AC001",
                    title="Test Abuse",
                    attacker_goal="Test goal",
                    steps=["Step 1", "Step 2", "Step 3"],
                )
            ],
            checklist=EngineeringChecklist(
                categories=[
                    ChecklistCategory(
                        category="AuthN/AuthZ",
                        items=[ChecklistItem(id="CHK-001", description="Test item")],
                    )
                ]
            ),
            top_risks=[
                RiskSummary(
                    risk_id="R001",
                    threat_ids=["T001"],
                    risk_description="Test risk",
                    aggregated_severity=SeverityLabel.MEDIUM,
                    key_mitigations=["Fix it"],
                )
            ],
            next_steps=[
                NextStep(priority=1, action="Do something", rationale="Because")
            ],
            qa_result=QAResult(
                passed=True,
                issues=[],
                completeness_score=0.95,
                consistency_score=0.90,
                summary="Passed",
            ),
        )

    def test_markdown_has_all_sections(self):
        """Test that rendered markdown has all 10 sections."""
        report = self.create_test_report()
        md = render_markdown_report(report)

        assert "## 1. Overview" in md
        assert "## 2. Assumptions & Unknowns" in md
        assert "## 3. System Inventory" in md
        assert "## 4. Data-Flow Diagram Notes" in md
        assert "## 5. Mermaid DFD" in md
        assert "## 6. STRIDE Threat Analysis" in md
        assert "## 7. Abuse Cases" in md
        assert "## 8. Engineering Checklist" in md
        assert "## 9. Top Risks & Mitigations" in md
        assert "## 10. Next Steps" in md

    def test_markdown_contains_mermaid(self):
        """Test that markdown contains mermaid code block."""
        report = self.create_test_report()
        md = render_markdown_report(report)

        assert "```mermaid" in md
        assert "graph TD" in md

    def test_markdown_contains_threats(self):
        """Test that markdown contains threat details."""
        report = self.create_test_report()
        md = render_markdown_report(report)

        assert "T001" in md
        assert "Test Threat" in md
        assert "MEDIUM" in md

    def test_markdown_contains_toc(self):
        """Test that markdown contains table of contents."""
        report = self.create_test_report()
        md = render_markdown_report(report)

        assert "## Table of Contents" in md
        assert "[Overview]" in md


class TestPlannerModels:
    """Tests for planner-related models."""

    def test_plan_step(self):
        """Test PlanStep model."""
        step = PlanStep(
            step_number=1,
            agent="ExtractorAgent",
            description="Extract inventory",
            inputs=["document"],
            outputs=["inventory"],
        )
        assert step.step_number >= 1
        assert step.agent == "ExtractorAgent"

    def test_planner_output(self):
        """Test PlannerOutput model."""
        output = PlannerOutput(
            doc_summary="Test summary",
            key_unknowns=["Unknown 1"],
            plan=[
                PlanStep(
                    step_number=1,
                    agent="ExtractorAgent",
                    description="Test",
                    inputs=[],
                    outputs=[],
                )
            ],
        )
        assert len(output.plan) == 1


class TestPipelineState:
    """Tests for pipeline state model."""

    def test_pipeline_state_initial(self):
        """Test PipelineState initial state."""
        state = PipelineState(raw_input="Test input")
        assert state.raw_input == "Test input"
        assert state.planner_output is None
        assert state.inventory is None
        assert state.errors == []

    def test_pipeline_state_with_errors(self):
        """Test PipelineState with errors."""
        state = PipelineState(
            raw_input="Test",
            errors=["Error 1", "Error 2"],
        )
        assert len(state.errors) == 2



