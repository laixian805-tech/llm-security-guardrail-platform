from app.rag.service import PersistentHybridRAGService


def test_persistent_hybrid_rag_reloads_indexed_chunks(tmp_path) -> None:
    store_path = tmp_path / "rag-store.json"
    service = PersistentHybridRAGService(store_path=store_path)
    service.ingest_text(
        document_id="handbook",
        text="Vacation requests are submitted through the HR portal.",
        allowed_roles=["public"],
    )

    reloaded = PersistentHybridRAGService(store_path=store_path)
    result = reloaded.query("vacation requests", caller_role="public")

    assert result.audit.action == "allow"
    assert result.chunks[0].document_id == "handbook"
    assert "vacation" in result.chunks[0].text.lower()


def test_hybrid_rag_ranks_keyword_dense_overlap_higher(tmp_path) -> None:
    service = PersistentHybridRAGService(store_path=tmp_path / "rag-store.json")
    service.ingest_text(
        document_id="security-policy",
        text="Prompt injection defense requires guardrails and red team evaluation.",
        allowed_roles=["public"],
    )
    service.ingest_text(
        document_id="travel-policy",
        text="Travel reimbursement requires receipts and manager approval.",
        allowed_roles=["public"],
    )

    result = service.query("prompt injection guardrails", caller_role="public", limit=2)

    assert result.chunks[0].document_id == "security-policy"
    assert result.chunks[0].metadata["retrieval_mode"] == "hybrid"
    assert result.chunks[0].metadata["keyword_score"] > 0
    assert result.chunks[0].metadata["dense_score"] > 0
