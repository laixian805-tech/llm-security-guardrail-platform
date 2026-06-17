from __future__ import annotations

import json
import math
import re
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.security import RAGAuditRecord


class ChunkStrategy(str, Enum):
    FIXED = "fixed"
    SENTENCE = "sentence"


class DocumentChunk(BaseModel):
    chunk_id: str
    document_id: str
    text: str
    allowed_roles: list[str] = Field(default_factory=lambda: ["public"])
    metadata: dict[str, Any] = Field(default_factory=dict)


class RetrievedChunk(DocumentChunk):
    score: float


class RetrievalResult(BaseModel):
    chunks: list[RetrievedChunk]
    audit: RAGAuditRecord


class InMemoryRAGService:
    def __init__(self) -> None:
        self._chunks: list[DocumentChunk] = []

    def ingest_text(
        self,
        *,
        document_id: str,
        text: str,
        allowed_roles: list[str],
        chunk_strategy: ChunkStrategy = ChunkStrategy.SENTENCE,
    ) -> list[DocumentChunk]:
        chunks = self._chunk_text(text, chunk_strategy)
        indexed: list[DocumentChunk] = []
        for index, chunk_text in enumerate(chunks):
            chunk = DocumentChunk(
                chunk_id=f"{document_id}:{len(self._chunks) + index}",
                document_id=document_id,
                text=chunk_text,
                allowed_roles=allowed_roles,
                metadata={"chunk_strategy": chunk_strategy.value},
            )
            indexed.append(chunk)
        self._chunks.extend(indexed)
        return indexed

    def query(self, query: str, caller_role: str, limit: int = 5) -> RetrievalResult:
        if self._is_bulk_dump_query(query):
            return RetrievalResult(
                chunks=[],
                audit=RAGAuditRecord(
                    query=query,
                    chunks_returned=0,
                    total_available=len(self._visible_chunks(caller_role)),
                    guard_triggered=True,
                    guard_reason="Blocked bulk knowledge-base dump query.",
                    action="block",
                ),
            )

        visible_chunks = self._visible_chunks(caller_role)
        scored_chunks = [
            self._score_chunk(query, chunk)
            for chunk in visible_chunks
        ]
        scored_chunks.sort(key=lambda chunk: chunk.score, reverse=True)
        returned = [chunk for chunk in scored_chunks if chunk.score > 0][: max(1, min(limit, 5))]
        scores = [chunk.score for chunk in returned]
        return RetrievalResult(
            chunks=returned,
            audit=RAGAuditRecord(
                query=query,
                chunks_returned=len(returned),
                total_available=len(visible_chunks),
                similarity_scores=scores,
                guard_triggered=False,
                action="allow",
            ),
        )

    def _score_chunk(self, query: str, chunk: DocumentChunk) -> RetrievedChunk:
        score = self._score(query, chunk.text)
        metadata = dict(chunk.metadata)
        metadata.update(
            {
                "retrieval_mode": "overlap",
                "keyword_score": score,
                "dense_score": score,
            }
        )
        return RetrievedChunk(
            **chunk.model_dump(exclude={"metadata"}),
            metadata=metadata,
            score=score,
        )

    def _visible_chunks(self, caller_role: str) -> list[DocumentChunk]:
        if caller_role == "admin":
            return list(self._chunks)
        if caller_role == "internal":
            return [
                chunk
                for chunk in self._chunks
                if any(role in {"public", "internal"} for role in chunk.allowed_roles)
            ]
        return [chunk for chunk in self._chunks if "public" in chunk.allowed_roles]

    @staticmethod
    def _chunk_text(text: str, chunk_strategy: ChunkStrategy) -> list[str]:
        cleaned = " ".join(text.split())
        if not cleaned:
            return []
        if chunk_strategy == ChunkStrategy.FIXED:
            return [cleaned[index : index + 500] for index in range(0, len(cleaned), 500)]
        sentence_chunks = [
            sentence.strip()
            for sentence in re.split(r"(?<=[.!?。！？])\s+", cleaned)
            if sentence.strip()
        ]
        return sentence_chunks or [cleaned]

    @staticmethod
    def _score(query: str, text: str) -> float:
        query_terms = set(_tokens(query))
        if not query_terms:
            return 0.0
        text_terms = set(_tokens(text))
        overlap = query_terms.intersection(text_terms)
        return len(overlap) / len(query_terms)

    @staticmethod
    def _is_bulk_dump_query(query: str) -> bool:
        return bool(
            re.search(r"\*:\*", query)
            or re.search(
                r"\b(dump|print|show|output|export)\b.*\b(entire|all|whole)\b.*\b(knowledge\s+base|documents?|context)\b",
                query,
                re.I,
            )
        )


class PersistentHybridRAGService(InMemoryRAGService):
    def __init__(self, store_path: str | Path) -> None:
        self.store_path = Path(store_path)
        super().__init__()
        self._load()

    def ingest_text(
        self,
        *,
        document_id: str,
        text: str,
        allowed_roles: list[str],
        chunk_strategy: ChunkStrategy = ChunkStrategy.SENTENCE,
    ) -> list[DocumentChunk]:
        chunks = super().ingest_text(
            document_id=document_id,
            text=text,
            allowed_roles=allowed_roles,
            chunk_strategy=chunk_strategy,
        )
        self._save()
        return chunks

    def _score_chunk(self, query: str, chunk: DocumentChunk) -> RetrievedChunk:
        keyword_score = self._keyword_score(query, chunk.text)
        dense_score = self._dense_overlap_score(query, chunk.text)
        score = (0.65 * keyword_score) + (0.35 * dense_score)
        metadata = dict(chunk.metadata)
        metadata.update(
            {
                "retrieval_mode": "hybrid",
                "keyword_score": keyword_score,
                "dense_score": dense_score,
            }
        )
        return RetrievedChunk(
            **chunk.model_dump(exclude={"metadata"}),
            metadata=metadata,
            score=score,
        )

    def _keyword_score(self, query: str, text: str) -> float:
        query_terms = _tokens(query)
        text_terms = _tokens(text)
        if not query_terms or not text_terms:
            return 0.0

        text_term_set = set(text_terms)
        document_count = max(1, len(self._chunks))
        score = 0.0
        for term in set(query_terms):
            if term not in text_term_set:
                continue
            containing_docs = sum(
                1 for chunk in self._chunks if term in set(_tokens(chunk.text))
            )
            idf = math.log((document_count + 1) / (containing_docs + 0.5)) + 1
            term_frequency = text_terms.count(term) / len(text_terms)
            score += idf * term_frequency
        return min(1.0, score)

    @staticmethod
    def _dense_overlap_score(query: str, text: str) -> float:
        query_terms = set(_tokens(query))
        text_terms = set(_tokens(text))
        if not query_terms or not text_terms:
            return 0.0
        return len(query_terms.intersection(text_terms)) / len(query_terms.union(text_terms))

    def _load(self) -> None:
        if not self.store_path.exists():
            return
        payload = json.loads(self.store_path.read_text(encoding="utf-8"))
        self._chunks = [
            DocumentChunk.model_validate(chunk)
            for chunk in payload.get("chunks", [])
        ]

    def _save(self) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"chunks": [chunk.model_dump(mode="json") for chunk in self._chunks]}
        self.store_path.write_text(
            json.dumps(payload, ensure_ascii=True, indent=2),
            encoding="utf-8",
        )


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z0-9_]+", text.lower())
