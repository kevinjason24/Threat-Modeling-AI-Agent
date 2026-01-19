"""Pydantic models for structured JSON validation across all sub-agents."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

# =============================================================================
# ENUMS
# =============================================================================


class ActorType(str, Enum):
    USER = "user"
    ADMIN = "admin"
    SERVICE = "service"
    THIRD_PARTY = "3rd-party"


class NodeType(str, Enum):
    EXTERNAL_ENTITY = "EE"
    PROCESS = "P"
    DATA_STORE = "DS"


class StrideCategory(str, Enum):
    SPOOFING = "S"
    TAMPERING = "T"
    REPUDIATION = "R"
    INFO_DISCLOSURE = "I"
    DENIAL_OF_SERVICE = "D"
    ELEVATION_OF_PRIVILEGE = "E"


class SeverityLabel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class DataSensitivity(str, Enum):
    PII = "PII"
    TOKENS = "tokens"
    PAYMENT = "payment"
    SECRETS = "secrets"
    CREDENTIALS = "credentials"
    HEALTH = "health"
    FINANCIAL = "financial"
    PUBLIC = "public"
    INTERNAL = "internal"


# =============================================================================
# PLANNER AGENT MODELS
# =============================================================================


class PlanStep(BaseModel):
    """A single step in the threat modeling plan."""

    step_number: int = Field(..., ge=1)
    agent: str = Field(..., description="Name of the sub-agent to execute")
    description: str = Field(..., description="What this step will produce")
    inputs: list[str] = Field(default_factory=list, description="Required inputs")
    outputs: list[str] = Field(default_factory=list, description="Expected outputs")


class PlannerOutput(BaseModel):
    """Output from the Planner Agent."""

    doc_summary: str = Field(..., description="Brief summary of the design document")
    key_unknowns: list[str] = Field(
        default_factory=list, description="Missing details marked as unknowns"
    )
    plan: list[PlanStep] = Field(..., description="Ordered list of steps to execute")


# =============================================================================
# EXTRACTOR AGENT MODELS
# =============================================================================


class Actor(BaseModel):
    """An actor in the system."""

    id: str = Field(..., description="Unique identifier")
    name: str
    type: ActorType
    description: str = ""
    privileges: list[str] = Field(default_factory=list)


class Component(BaseModel):
    """A system component or service."""

    id: str = Field(..., description="Unique identifier")
    name: str
    description: str = ""
    technology: str = Field(default="Unknown", description="Tech stack if known")
    exposed_ports: list[str] = Field(default_factory=list)
    responsibilities: list[str] = Field(default_factory=list)


class DataStore(BaseModel):
    """A data storage system."""

    id: str = Field(..., description="Unique identifier")
    name: str
    type: str = Field(default="Unknown", description="e.g., PostgreSQL, Redis, S3")
    data_types: list[DataSensitivity] = Field(default_factory=list)
    encryption_at_rest: Optional[bool] = None
    backup_enabled: Optional[bool] = None


class EntryPoint(BaseModel):
    """An entry point into the system."""

    id: str = Field(..., description="Unique identifier")
    name: str
    protocol: str = Field(default="Unknown", description="HTTP, gRPC, WebSocket, etc.")
    authentication: str = Field(default="Unknown")
    exposed_to: str = Field(default="Unknown", description="internet/internal/VPN")
    description: str = ""


class Integration(BaseModel):
    """An external integration."""

    id: str = Field(..., description="Unique identifier")
    name: str
    type: str = Field(default="Unknown", description="API, webhook, SDK, etc.")
    direction: str = Field(default="Unknown", description="inbound/outbound/bidirectional")
    authentication: str = Field(default="Unknown")
    data_exchanged: list[str] = Field(default_factory=list)


class AuthConfig(BaseModel):
    """Authentication and authorization configuration."""

    authn_methods: list[str] = Field(default_factory=list, description="e.g., JWT, OAuth2, SAML")
    authz_model: str = Field(default="Unknown", description="RBAC, ABAC, ACL, etc.")
    session_management: str = Field(default="Unknown")
    mfa_enabled: Optional[bool] = None
    notes: list[str] = Field(default_factory=list)


class TrustBoundary(BaseModel):
    """A trust boundary in the system."""

    id: str
    name: str
    description: str = ""
    components_inside: list[str] = Field(default_factory=list, description="Component IDs")


class Inventory(BaseModel):
    """Complete system inventory extracted from the design document."""

    actors: list[Actor] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    data_stores: list[DataStore] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    integrations: list[Integration] = Field(default_factory=list)
    auth_config: AuthConfig = Field(default_factory=AuthConfig)
    data_types_present: list[DataSensitivity] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)


# =============================================================================
# DFD BUILDER AGENT MODELS
# =============================================================================


class DFDNode(BaseModel):
    """A node in the Data Flow Diagram."""

    id: str = Field(..., description="Unique ID with prefix: EE_, P_, DS_")
    label: str
    type: NodeType
    trust_boundary: Optional[str] = Field(None, description="Trust boundary ID if applicable")


class DFDFlow(BaseModel):
    """A data flow between nodes."""

    id: str = Field(..., description="Unique flow identifier")
    src: str = Field(..., description="Source node ID")
    dst: str = Field(..., description="Destination node ID")
    data: str = Field(..., description="What data flows")
    protocol: str = Field(default="Unknown")
    auth: str = Field(default="Unknown")
    encrypted: Optional[bool] = None
    crosses_boundary: bool = Field(default=False)
    boundary_crossed: Optional[str] = Field(None, description="Boundary name if crosses")


class DFDModel(BaseModel):
    """Complete Data Flow Diagram model."""

    nodes: list[DFDNode] = Field(default_factory=list)
    flows: list[DFDFlow] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    dfd_notes: list[str] = Field(default_factory=list, description="Diagram notes/caveats")


# =============================================================================
# STRIDE ANALYST AGENT MODELS
# =============================================================================


class Threat(BaseModel):
    """A STRIDE threat identified in the system."""

    id: str = Field(..., description="Unique threat ID, e.g., T001")
    stride_category: StrideCategory
    affected_element: str = Field(..., description="Node ID or flow ID")
    title: str = Field(..., description="Short threat title")
    description: str = Field(..., description="Detailed threat description")
    preconditions: list[str] = Field(default_factory=list)
    exploit_steps: list[str] = Field(default_factory=list, description="High-level attack steps")
    detection_signals: list[str] = Field(default_factory=list, description="Logs/alerts to detect")
    mitigations: list[str] = Field(default_factory=list, description="Actionable mitigations")
    likelihood: int = Field(..., ge=1, le=5)
    impact: int = Field(..., ge=1, le=5)
    severity_label: SeverityLabel
    references: list[str] = Field(default_factory=list, description="OWASP refs, no URLs needed")


class StrideAnalysis(BaseModel):
    """Complete STRIDE analysis output."""

    threats: list[Threat] = Field(default_factory=list)
    analysis_notes: list[str] = Field(default_factory=list)


# =============================================================================
# ABUSE CASE WRITER AGENT MODELS
# =============================================================================


class AbuseCase(BaseModel):
    """An abuse case describing an attack scenario."""

    id: str = Field(..., description="Unique abuse case ID, e.g., AC001")
    title: str
    attacker_goal: str
    attacker_profile: str = Field(default="Unknown", description="e.g., external, insider")
    steps: list[str] = Field(..., min_length=3, max_length=7)
    impacted_assets: list[str] = Field(default_factory=list)
    recommended_controls: list[str] = Field(default_factory=list)
    related_threats: list[str] = Field(default_factory=list, description="Threat IDs")


class AbuseCasesOutput(BaseModel):
    """Output from the Abuse Case Writer Agent."""

    abuse_cases: list[AbuseCase] = Field(default_factory=list)


# =============================================================================
# CHECKLIST WRITER AGENT MODELS
# =============================================================================


class ChecklistItem(BaseModel):
    """A single checklist item."""

    id: str
    description: str = Field(..., description="Testable, actionable item")
    priority: str = Field(default="Medium", description="High/Medium/Low")
    related_threats: list[str] = Field(default_factory=list)


class ChecklistCategory(BaseModel):
    """A category of checklist items."""

    category: str
    items: list[ChecklistItem] = Field(default_factory=list)


class EngineeringChecklist(BaseModel):
    """Complete engineering security checklist."""

    categories: list[ChecklistCategory] = Field(default_factory=list)

    @classmethod
    def get_default_categories(cls) -> list[str]:
        return [
            "AuthN/AuthZ",
            "Input Validation",
            "Secrets & Key Management",
            "Data Protection",
            "Logging/Monitoring",
            "Rate Limiting/DoS",
            "Supply Chain",
            "Infra/Cloud",
        ]


# =============================================================================
# QA CHECKER AGENT MODELS
# =============================================================================


class QAIssue(BaseModel):
    """A quality assurance issue found."""

    severity: str = Field(..., description="error/warning/info")
    category: str = Field(..., description="completeness/consistency/clarity")
    message: str
    affected_section: str
    suggested_fix: Optional[str] = None


class QAResult(BaseModel):
    """Output from the QA Checker Agent."""

    passed: bool
    issues: list[QAIssue] = Field(default_factory=list)
    completeness_score: float = Field(..., ge=0, le=1, description="0-1 completeness score")
    consistency_score: float = Field(..., ge=0, le=1, description="0-1 consistency score")
    assumptions_labeled: bool = Field(default=False, description="All assumptions explicit?")
    summary: str


# =============================================================================
# REPORT MODELS
# =============================================================================


class RiskSummary(BaseModel):
    """Summary of top risks and mitigations."""

    risk_id: str
    threat_ids: list[str]
    risk_description: str
    aggregated_severity: SeverityLabel
    key_mitigations: list[str]


class NextStep(BaseModel):
    """A recommended next step."""

    priority: int = Field(..., ge=1)
    action: str
    rationale: str
    owner_suggestion: str = Field(default="Security Team")


class ThreatModelReport(BaseModel):
    """Complete threat model report combining all agent outputs."""

    # Metadata
    generated_at: str
    input_document: str
    version: str = "1.0"

    # Section 1: Overview
    overview: str

    # Section 2: Assumptions & Unknowns
    assumptions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)

    # Section 3: System Inventory
    inventory: Inventory

    # Section 4-5: DFD
    dfd_model: DFDModel
    mermaid_diagram: str

    # Section 6: STRIDE Analysis
    stride_analysis: StrideAnalysis

    # Section 7: Abuse Cases
    abuse_cases: list[AbuseCase] = Field(default_factory=list)

    # Section 8: Engineering Checklist
    checklist: EngineeringChecklist

    # Section 9: Top Risks
    top_risks: list[RiskSummary] = Field(default_factory=list)

    # Section 10: Next Steps
    next_steps: list[NextStep] = Field(default_factory=list)

    # QA
    qa_result: QAResult


# =============================================================================
# PIPELINE STATE
# =============================================================================


class PipelineState(BaseModel):
    """State passed through the pipeline."""

    raw_input: str
    input_path: Optional[str] = None
    planner_output: Optional[PlannerOutput] = None
    inventory: Optional[Inventory] = None
    dfd_model: Optional[DFDModel] = None
    stride_analysis: Optional[StrideAnalysis] = None
    abuse_cases: Optional[AbuseCasesOutput] = None
    checklist: Optional[EngineeringChecklist] = None
    qa_result: Optional[QAResult] = None
    final_report: Optional[ThreatModelReport] = None
    errors: list[str] = Field(default_factory=list)



