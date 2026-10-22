"""ORM models: Project, Scan, Finding, Component, CryptoAsset, FeedCache.

Columns that the UI filters or sorts on are stored as real columns; the full
record produced by the scanners is kept in a JSON ``data`` column so the
exporters can rebuild an identical report from the database.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    """Timezone-aware UTC now."""
    return datetime.now(UTC)


class Project(Base):
    """A scanned target (repository URL, upload name or local path)."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(300))
    source: Mapped[str] = mapped_column(String(1000), unique=True, index=True)
    source_type: Mapped[str] = mapped_column(String(20))  # url | zip | path
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scans: Mapped[list[Scan]] = relationship(back_populates="project", cascade="all, delete-orphan", order_by="Scan.id")


class Scan(Base):
    """One execution of the scan pipeline against a project."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|done|error
    stage: Mapped[str] = mapped_column(String(40), default="Queued")
    stages: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(200), nullable=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    grade: Mapped[str | None] = mapped_column(String(2), nullable=True)
    gate_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    fail_on: Mapped[str] = mapped_column(String(4), default="p0")
    gate_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    intel_partial: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    components: Mapped[list[Component]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    crypto_assets: Mapped[list[CryptoAsset]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    """A single security finding. Secret values are never stored, only fingerprints."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    module: Mapped[str] = mapped_column(String(20), index=True)
    rule_id: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(400))
    severity: Mapped[str] = mapped_column(String(10))
    priority: Mapped[str] = mapped_column(String(2), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    file: Mapped[str] = mapped_column(String(1000), default="")
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="open")  # open|false_positive|accepted_risk|suppressed
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Component(Base):
    """A software component discovered in a manifest or lockfile (SBOM entry)."""

    __tablename__ = "components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(300))
    version: Mapped[str] = mapped_column(String(100), default="")
    ecosystem: Mapped[str] = mapped_column(String(30))
    purl: Mapped[str] = mapped_column(String(600))
    direct: Mapped[bool] = mapped_column(Boolean, default=True)
    vuln_count: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="components")


class CryptoAsset(Base):
    """One occurrence of a cryptographic algorithm/protocol (CBOM entry)."""

    __tablename__ = "crypto_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    primitive: Mapped[str] = mapped_column(String(40))
    classification: Mapped[str] = mapped_column(String(20))  # approved|weak|broken
    quantum_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    file: Mapped[str] = mapped_column(String(1000))
    line: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="crypto_assets")


class FeedCache(Base):
    """Cached response from a threat-intelligence feed, with an expiry time."""

    __tablename__ = "feed_cache"

    key: Mapped[str] = mapped_column(String(300), primary_key=True)
    source: Mapped[str] = mapped_column(String(20), index=True)  # osv|epss|kev|github
    payload: Mapped[str] = mapped_column(Text)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
