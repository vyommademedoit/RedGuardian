"""Relational schema (FR-11). SQLAlchemy Core: same tables on MySQL and SQLite.

Initial tables only; Phase 3/4 add document and memory behaviour on top.
Chunks and embeddings live in ChromaDB (see docs/architecture.md), keyed by
``documents.doc_id``.
"""

from __future__ import annotations

from datetime import UTC

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    TypeDecorator,
    UniqueConstraint,
)


class UTCDateTime(TypeDecorator):
    """Stores naive UTC; returns aware UTC. MySQL DATETIME and SQLite drop tzinfo."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            raise ValueError("naive datetime: use harness.models.utcnow()")
        return value.astimezone(UTC).replace(tzinfo=None) if value is not None else None

    def process_result_value(self, value, dialect):
        return value.replace(tzinfo=UTC) if value is not None else None


metadata = MetaData()

ID = String(36)  # uuid4 text

experiments = Table(
    "experiments",
    metadata,
    Column("experiment_id", ID, primary_key=True),
    Column("name", String(200), nullable=False),
    Column("objective", Text),
    Column("config", JSON, nullable=False),
    Column("created_at", UTCDateTime(), nullable=False),
)

runs = Table(
    "runs",
    metadata,
    Column("run_id", ID, primary_key=True),
    Column("experiment_id", ID, ForeignKey("experiments.experiment_id")),
    Column("kind", String(16), nullable=False),
    Column("attack_id", String(32), nullable=False, index=True),
    Column("attack_version", String(32), nullable=False),
    Column("attack_sha256", String(64), nullable=False),
    Column("adapter", String(64), nullable=False),
    Column("model", String(128)),
    Column("model_params", JSON, nullable=False),
    Column("defense_profile", String(64), nullable=False, index=True),
    Column("defense_config", JSON, nullable=False),
    Column("seed", Integer),
    Column("corpus_state_id", String(64)),
    Column("memory_state_id", String(64)),
    Column("status", String(16), nullable=False),
    Column("error", Text),
    Column("started_at", UTCDateTime(), nullable=False),
    Column("finished_at", UTCDateTime()),
)

events = Table(
    "events",
    metadata,
    Column("event_id", ID, primary_key=True),
    Column("run_id", ID, ForeignKey("runs.run_id"), nullable=False),
    Column("seq", Integer, nullable=False),
    Column("timestamp", UTCDateTime(), nullable=False),
    Column("event_type", String(32), nullable=False, index=True),
    Column("attack_id", String(32)),
    Column("stage", Integer),
    Column("source_type", String(16)),
    Column("source_id", String(128)),
    Column("destination", String(128)),
    Column("canary_id", String(64)),
    Column("decision", String(16)),
    Column("defense_id", String(64)),
    Column("reason", Text),
    Column("payload", JSON, nullable=False),
    UniqueConstraint("run_id", "seq"),  # append-only ordering guarantee
)

evaluations = Table(
    "evaluations",
    metadata,
    Column("run_id", ID, ForeignKey("runs.run_id"), primary_key=True),
    Column("evaluator_version", String(32), primary_key=True),
    Column("result", JSON, nullable=False),  # RunEvaluation.model_dump(mode="json")
    Column("evaluated_at", UTCDateTime(), nullable=False),
)

metric_results = Table(
    "metric_results",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("experiment_id", ID, ForeignKey("experiments.experiment_id"), nullable=False),
    Column("scope", String(128), nullable=False),
    Column("name", String(64), nullable=False),
    Column("numerator", Integer, nullable=False),
    Column("denominator", Integer, nullable=False),
    Column("value", Float),  # NULL when denominator == 0
)

documents = Table(
    "documents",
    metadata,
    Column("doc_id", String(64), primary_key=True),
    Column("corpus_id", String(64), nullable=False, index=True),
    Column("title", String(256)),
    Column("source", String(256), nullable=False),
    Column("trust", String(16), nullable=False),
    Column("poisoned", Boolean, nullable=False),  # ground truth; never shown to defenses
    Column("attack_id", String(32)),
    Column("sha256", String(64), nullable=False),
)

memory_entries = Table(
    "memory_entries",
    metadata,
    Column("memory_id", ID, primary_key=True),
    Column("namespace", String(64), nullable=False, index=True),
    Column("content", Text, nullable=False),
    Column("source_type", String(16), nullable=False),
    Column("source_id", String(128), nullable=False),
    Column("trust", String(16), nullable=False),
    Column("run_id", ID),
    Column("session_id", String(64)),
    Column("contains_canary", Boolean, nullable=False),
    Column("status", String(16), nullable=False),  # active | quarantined | deleted
    Column("created_at", UTCDateTime(), nullable=False),
)
