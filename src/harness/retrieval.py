"""Retrieval surface (FR-03 B): per-run ChromaDB collection over fixture documents.

We always pass our own embeddings, so Chroma never downloads its default model
(D-005). Each run gets a fresh collection that is dropped when the run ends, so
a poisoned corpus can never leak into the next run.
"""

from __future__ import annotations

import json
import math
import os
import re
import urllib.request
import zlib
from collections.abc import Callable

import chromadb
from chromadb.config import Settings

from harness.models import RetrievedChunk, Trust

Embedder = Callable[[list[str]], list[list[float]]]

# shortcut: in-memory store, fine for per-run corpora; use PersistentClient(.data/chroma) once corpora are reused across runs
_client = chromadb.EphemeralClient(settings=Settings(anonymized_telemetry=False))


def hash_embedder(texts: list[str], dim: int = 256) -> list[list[float]]:
    """Deterministic bag-of-words vectors: offline, no model, stable across processes."""
    out = []
    for t in texts:
        v = [0.0] * dim
        for tok in re.findall(r"[a-z0-9]+", t.lower()):
            v[zlib.crc32(tok.encode()) % dim] += 1.0
        n = math.sqrt(sum(x * x for x in v)) or 1.0
        out.append([x / n for x in v])
    return out


def ollama_embedder(texts: list[str]) -> list[list[float]]:
    """Local Ollama embeddings (nomic-embed-text by default). Raises if Ollama is down."""
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    model = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
    req = urllib.request.Request(f"{host}/api/embed", data=json.dumps({"model": model, "input": texts}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:  # first call may cold-load the model onto the GPU
        return json.load(r)["embeddings"]


EMBEDDERS: dict[str, Embedder] = {"hash": hash_embedder, "ollama": ollama_embedder}


def chunk(text: str) -> list[str]:
    """One chunk per paragraph (blank-line separated)."""
    return [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]


class Corpus:
    def __init__(self, corpus_id: str, documents: dict[str, dict], embed: Embedder):
        self.corpus_id, self.embed = corpus_id, embed
        self.col = _client.create_collection(f"corpus_{corpus_id}", embedding_function=None,
                                             configuration={"hnsw": {"space": "cosine"}})
        ids, texts, metas = [], [], []
        for doc_id, d in documents.items():
            for i, c in enumerate(chunk(d["text"])):
                ids.append(f"{doc_id}#{i}")
                texts.append(c)
                # ground-truth "poisoned" is deliberately NOT stored here (D-018)
                metas.append({"doc_id": doc_id, "trust": d["trust"], "source": d["source"]})
        self.col.add(ids=ids, documents=texts, metadatas=metas, embeddings=embed(texts))

    def search(self, query: str, k: int = 3) -> list[RetrievedChunk]:
        r = self.col.query(query_embeddings=self.embed([query]), n_results=k,
                           include=["documents", "metadatas", "distances"])
        return [RetrievedChunk(chunk_id=cid, doc_id=m["doc_id"], rank=i + 1, score=round(1 - d, 4),
                               trust=Trust(m["trust"]), source=m["source"], text=t)
                for i, (cid, t, m, d) in enumerate(zip(r["ids"][0], r["documents"][0], r["metadatas"][0], r["distances"][0]))]

    def drop(self) -> None:
        _client.delete_collection(self.col.name)


def format_chunks(chunks: list[RetrievedChunk]) -> str:
    return "\n\n".join(f"[{c.doc_id}] {c.text}" for c in chunks) or "No matching documents."
