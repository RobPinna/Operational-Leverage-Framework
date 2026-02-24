from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, index=True)
    company_name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    sector = Column(String(255), default="Unknown", nullable=False)
    regions = Column(String(255), default="", nullable=False)
    demo_mode = Column(Boolean, default=False, nullable=False)
    status = Column(String(32), default="draft", nullable=False)
    wizard_step = Column(Integer, default=1, nullable=False)
    selected_sources_json = Column(Text, default="[]", nullable=False)
    collect_log_json = Column(Text, default="[]", nullable=False)
    assumptions_json = Column(Text, default="[]", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    evidences = relationship("Evidence", back_populates="assessment", cascade="all, delete-orphan")
    nodes = relationship("Node", back_populates="assessment", cascade="all, delete-orphan")
    edges = relationship("Edge", back_populates="assessment", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")
    mitigations = relationship("Mitigation", back_populates="assessment", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="assessment", cascade="all, delete-orphan")
    examination_logs = relationship("ExaminationLog", back_populates="assessment", cascade="all, delete-orphan")
    documents = relationship("Document", back_populates="assessment", cascade="all, delete-orphan")
    hypotheses = relationship("Hypothesis", back_populates="assessment", cascade="all, delete-orphan")
    gaps = relationship("Gap", back_populates="assessment", cascade="all, delete-orphan")
    correlations = relationship("CrossSignalCorrelation", back_populates="assessment", cascade="all, delete-orphan")
    workflow_nodes = relationship("WorkflowNode", back_populates="assessment", cascade="all, delete-orphan")
    social_trust_nodes = relationship("SocialTrustNode", back_populates="assessment", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidences"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    connector = Column(String(64), nullable=False, index=True)
    category = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    snippet = Column(Text, nullable=False)
    source_url = Column(String(512), default="", nullable=False)
    observed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    confidence = Column(Integer, default=50, nullable=False)
    evidence_kind = Column(String(32), default="UNKNOWN", nullable=False, index=True)
    quality_tier = Column(String(16), default="LOW", nullable=False, index=True)
    quality_weight = Column(Float, default=0.5, nullable=False)
    is_boilerplate = Column(Boolean, default=False, nullable=False, index=True)
    rationale = Column(String(255), default="", nullable=False)
    raw_json = Column(Text, default="{}", nullable=False)

    assessment = relationship("Assessment", back_populates="evidences")


class Document(Base):
    __tablename__ = "documents"
    __table_args__ = (Index("ix_documents_assessment_content_hash", "assessment_id", "content_hash"),)

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    url = Column(String(1024), default="", nullable=False, index=True)
    doc_type = Column(String(32), default="html", nullable=False, index=True)
    title = Column(String(255), default="", nullable=False)
    extracted_text = Column(Text, default="", nullable=False)
    language = Column(String(16), default="unknown", nullable=False)
    content_hash = Column(String(128), default="", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    assessment = relationship("Assessment", back_populates="documents")


class Node(Base):
    __tablename__ = "nodes"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    label = Column(String(255), nullable=False)
    type = Column(String(64), nullable=False, index=True)
    confidence = Column(Integer, default=60, nullable=False)
    meta_json = Column(Text, default="{}", nullable=False)

    assessment = relationship("Assessment", back_populates="nodes")


class Edge(Base):
    __tablename__ = "edges"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    from_node_id = Column(Integer, ForeignKey("nodes.id"), nullable=False)
    to_node_id = Column(Integer, ForeignKey("nodes.id"), nullable=False)
    relation_type = Column(String(64), nullable=False)
    weight = Column(Float, default=1.0, nullable=False)
    meta_json = Column(Text, default="{}", nullable=False)

    assessment = relationship("Assessment", back_populates="edges")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    type = Column(String(32), nullable=False, index=True)
    severity = Column(Integer, default=3, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    confidence = Column(Integer, default=60, nullable=False)
    evidence_refs_json = Column(Text, default="[]", nullable=False)

    assessment = relationship("Assessment", back_populates="findings")


class Mitigation(Base):
    __tablename__ = "mitigations"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    priority = Column(Integer, default=3, nullable=False)
    effort = Column(String(1), default="M", nullable=False)
    owner = Column(String(64), default="Security", nullable=False)
    description = Column(Text, nullable=False)
    linked_findings_json = Column(Text, default="[]", nullable=False)

    assessment = relationship("Assessment", back_populates="mitigations")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    pdf_path = Column(String(512), nullable=False)
    json_path = Column(String(512), default="", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    assessment = relationship("Assessment", back_populates="reports")


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    query_id = Column(String(16), default="", nullable=False, index=True)
    risk_type = Column(String(64), default="other", nullable=False, index=True)
    # Risk-first typing (stakeholder-facing). Deterministically assigned from signals/workflow cues.
    primary_risk_type = Column(String(64), default="Channel ambiguity exploitation", nullable=False, index=True)
    risk_vector_summary = Column(Text, default="", nullable=False)
    baseline_tag = Column(Boolean, default=False, nullable=False, index=True)
    # Deterministic status for risk triage bucket.
    status = Column(String(16), default="WATCHLIST", nullable=False, index=True)
    plausibility_score = Column(Integer, default=0, nullable=False, index=True)
    potential_impact_score = Column(Integer, default=0, nullable=False, index=True)
    integrity_flags_json = Column(Text, default="{}", nullable=False)
    severity = Column(Integer, default=3, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, default="", nullable=False)
    likelihood = Column(String(16), default="med", nullable=False, index=True)
    likelihood_rationale = Column(Text, default="", nullable=False)
    impact = Column(String(32), default="ops", nullable=False, index=True)
    impact_rationale = Column(Text, default="", nullable=False)
    evidence_refs_json = Column(Text, default="[]", nullable=False)
    assumptions_json = Column(Text, default="[]", nullable=False)
    gaps_to_verify_json = Column(Text, default="[]", nullable=False)
    defensive_actions_json = Column(Text, default="[]", nullable=False)
    # Evidence quality metadata (defensive-only, heuristic).
    confidence = Column(Integer, default=0, nullable=False, index=True)
    signal_diversity = Column(Integer, default=0, nullable=False)
    signal_counts_json = Column(Text, default="{}", nullable=False)
    missing_signals_json = Column(Text, default="[]", nullable=False)
    timeline_json = Column(Text, default="[]", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    assessment = relationship("Assessment", back_populates="hypotheses")


class WorkflowNode(Base):
    __tablename__ = "workflow_nodes"
    __table_args__ = (Index("ix_workflow_nodes_assessment_kind", "assessment_id", "workflow_kind"),)

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    workflow_kind = Column(String(64), default="", nullable=False, index=True)
    title = Column(String(255), default="", nullable=False)
    sensitivity_level = Column(String(8), default="MED", nullable=False, index=True)  # LOW/MED/HIGH
    channel_type = Column(String(16), default="unknown", nullable=False, index=True)  # email/chat/form/portal/unknown
    requires_trust = Column(Boolean, default=True, nullable=False)
    trust_friction_score = Column(Integer, default=0, nullable=False, index=True)  # 0-100

    evidence_refs_json = Column(Text, default="[]", nullable=False)
    confirm_json = Column(Text, default="[]", nullable=False)
    deny_json = Column(Text, default="[]", nullable=False)
    flags_json = Column(Text, default="{}", nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    assessment = relationship("Assessment", back_populates="workflow_nodes")


class SocialTrustNode(Base):
    __tablename__ = "social_trust_nodes"
    __table_args__ = (Index("ix_social_trust_nodes_assessment_platform", "assessment_id", "platform"),)

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)

    platform = Column(String(32), default="", nullable=False, index=True)
    handle = Column(String(255), default="", nullable=False, index=True)
    profile_url = Column(String(1024), default="", nullable=False, index=True)
    document_id = Column(Integer, nullable=True, index=True)

    verified_status = Column(Boolean, nullable=True)
    bio_text = Column(Text, default="", nullable=False)
    business_category = Column(String(255), default="", nullable=False)
    follower_count = Column(Integer, nullable=True)

    has_email_in_bio = Column(Boolean, default=False, nullable=False)
    has_phone_in_bio = Column(Boolean, default=False, nullable=False)
    link_in_bio = Column(String(1024), default="", nullable=False)
    mentions_booking = Column(Boolean, default=False, nullable=False)
    mentions_dm_contact = Column(Boolean, default=False, nullable=False)

    # Derived signals for controlled integration (defensive only).
    signals_json = Column(Text, default="[]", nullable=False)
    trust_friction_score = Column(Integer, default=0, nullable=False, index=True)  # 0-100
    evidence_refs_json = Column(Text, default="[]", nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    assessment = relationship("Assessment", back_populates="social_trust_nodes")


class Gap(Base):
    __tablename__ = "gaps"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    query_id = Column(String(16), default="", nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, default="", nullable=False)
    evidence_count = Column(Integer, default=0, nullable=False)
    avg_confidence = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    assessment = relationship("Assessment", back_populates="gaps")


class CrossSignalCorrelation(Base):
    __tablename__ = "cross_signal_correlations"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    correlation_key = Column(String(128), default="", nullable=False, index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, default="", nullable=False)
    risk_level = Column(Integer, default=3, nullable=False, index=True)
    signals_json = Column(Text, default="[]", nullable=False)
    evidence_refs_json = Column(Text, default="[]", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    assessment = relationship("Assessment", back_populates="correlations")


class RiskBrief(Base):
    __tablename__ = "risk_briefs"
    __table_args__ = (
        Index("ix_risk_briefs_assessment_risk", "assessment_id", "risk_kind", "risk_id"),
        Index("ix_risk_briefs_assessment_input_hash", "assessment_id", "input_hash"),
    )

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    risk_kind = Column(String(32), default="", nullable=False, index=True)  # scenario/finding/correlation
    risk_id = Column(Integer, nullable=False, index=True)
    input_hash = Column(String(128), default="", nullable=False, index=True)
    model = Column(String(64), default="LOCAL", nullable=False)
    brief = Column(Text, default="", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    assessment = relationship("Assessment")


class ConnectorSetting(Base):
    __tablename__ = "connector_settings"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), unique=True, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    api_key_obfuscated = Column(Text, default="", nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class ExaminationLog(Base):
    __tablename__ = "examination_logs"
    __table_args__ = (Index("ix_examination_logs_assessment_content_hash", "assessment_id", "content_hash"),)

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    url = Column(String(1024), default="", nullable=False, index=True)
    source_type = Column(String(32), default="manual", nullable=False, index=True)
    status = Column(String(32), default="fetched", nullable=False, index=True)
    http_status = Column(Integer, nullable=True)
    content_hash = Column(String(128), default="", nullable=False)
    bytes = Column(Integer, nullable=True)
    discovered_from = Column(String(128), default="", nullable=False)
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    fetched_at = Column(DateTime, nullable=True)
    was_rendered = Column(Boolean, nullable=True)
    extracted_chars = Column(Integer, nullable=True)
    pdf_pages = Column(Integer, nullable=True)
    pdf_text_chars = Column(Integer, nullable=True)
    parse_summary = Column(Text, default="", nullable=False)
    error_message = Column(Text, default="", nullable=False)

    assessment = relationship("Assessment", back_populates="examination_logs")
