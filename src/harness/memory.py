"""Persistent agent memory (FR-03 D) on the ``memory_entries`` table.

A namespace is one memory lineage. Each run gets its own by default
(namespace = run_id); a recovery run deliberately reuses a poisoned run's
namespace. Statuses: ``active`` (visible to read_memory), ``quarantined``
(kept for audit, hidden), ``deleted`` (soft-deleted). ``reset`` hard-deletes.
"""

from __future__ import annotations

from sqlalchemy import Engine, delete, insert, select, update

from harness.models import new_id, utcnow
from harness.storage import memory_entries as T


class MemoryStore:
    def __init__(self, engine: Engine, namespace: str):
        self.engine, self.namespace = engine, namespace

    def append(self, content: str, *, source_type: str, source_id: str, trust: str, run_id: str,
               session_id: str, contains_canary: bool) -> str:
        memory_id = new_id()
        with self.engine.begin() as c:
            c.execute(insert(T), {
                "memory_id": memory_id, "namespace": self.namespace, "content": content,
                "source_type": source_type, "source_id": source_id[:128], "trust": trust, "run_id": run_id,
                "session_id": session_id, "contains_canary": contains_canary, "status": "active",
                "created_at": utcnow()})
        return memory_id

    def retrieve(self, status: str = "active") -> list:
        with self.engine.connect() as c:
            return list(c.execute(select(T).where(T.c.namespace == self.namespace, T.c.status == status)
                                  .order_by(T.c.created_at, T.c.memory_id)))

    def quarantine(self, **match) -> int:
        """e.g. ``quarantine(run_id=compromised_run)`` or ``quarantine(trust="untrusted")``."""
        return self._set_status("quarantined", match)

    def delete(self, **match) -> int:
        return self._set_status("deleted", match)

    def reset(self) -> int:
        with self.engine.begin() as c:
            return c.execute(delete(T).where(T.c.namespace == self.namespace)).rowcount

    def _set_status(self, status: str, match: dict) -> int:
        q = update(T).where(T.c.namespace == self.namespace, T.c.status != "deleted")
        for column, value in match.items():
            q = q.where(T.c[column] == value)  # KeyError on an unknown column: fail loudly
        with self.engine.begin() as c:
            return c.execute(q.values(status=status)).rowcount
