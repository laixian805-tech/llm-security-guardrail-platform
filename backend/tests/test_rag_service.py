from app.rag.service import InMemoryRAGService


def test_rag_query_filters_chunks_by_caller_role() -> None:
    service = InMemoryRAGService()
    service.ingest_text(
        document_id="public-handbook",
        text="Employees may request vacation through the HR portal.",
        allowed_roles=["public", "internal"],
    )
    service.ingest_text(
        document_id="internal-finance",
        text="Finance audit escalation uses internal approval code ZX-91.",
        allowed_roles=["internal"],
    )

    result = service.query("finance audit approval code", caller_role="public")

    assert result.audit.action == "allow"
    assert all(chunk.document_id != "internal-finance" for chunk in result.chunks)


def test_rag_blocks_bulk_dump_query() -> None:
    service = InMemoryRAGService()
    service.ingest_text(
        document_id="handbook",
        text="First policy. Second policy. Third policy.",
        allowed_roles=["public"],
    )

    result = service.query("*:*", caller_role="public")

    assert result.chunks == []
    assert result.audit.guard_triggered is True
    assert result.audit.action == "block"
    assert "bulk" in result.audit.guard_reason.lower()
