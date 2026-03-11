"""Shared rendering helpers for bundled public and purchased standards."""

from __future__ import annotations

from typing import Iterable, List

from .providers import SearchResult, StandardMetadata

QUERYABLE_STANDARD_TYPES = {"public", "paid"}


def get_queryable_standard_ids(standards: Iterable[dict]) -> List[str]:
    """Return all queryable standard identifiers."""
    return [
        standard["standard_id"]
        for standard in standards
        if standard.get("type") in QUERYABLE_STANDARD_TYPES
    ]


def render_standard_not_found(standards: Iterable[dict], standard_id: str) -> str:
    """Render a consistent error for missing standards."""
    available = get_queryable_standard_ids(standards)
    if available:
        return f"Standard '{standard_id}' not found. Available: {', '.join(available)}"
    return "No bundled public or purchased standards are available."


def render_standard_list(standards: list[dict], has_paid_standards: bool) -> str:
    """Render list_available_standards output."""
    text = f"**Available Standards ({len(standards)} total)**\n\n"

    for standard in standards:
        standard_type = standard["type"]
        if standard_type == "built-in":
            text += f"### {standard['title']} (Built-in Mapping Dataset)\n"
            text += f"- **License:** {standard['license']}\n"
            text += f"- **Coverage:** {standard['controls']}\n\n"
            continue

        if standard_type == "public":
            text += f"### {standard['title']} (Bundled Public Profile)\n"
            text += f"- **ID:** `{standard['standard_id']}`\n"
            text += f"- **Version:** {standard['version']}\n"
            text += f"- **Issuer:** {standard.get('issuer', 'Unknown')}\n"
            text += f"- **Jurisdiction:** {standard.get('jurisdiction', 'Unknown')}\n"
            if standard.get("summary"):
                text += f"- **Coverage:** {standard['summary']}\n"
            source_documents = standard.get("source_documents") or []
            if source_documents:
                text += f"- **Primary source:** {source_documents[0].get('url', 'n/a')}\n"
            text += "\n"
            continue

        text += f"### {standard['title']} (Purchased)\n"
        text += f"- **ID:** `{standard['standard_id']}`\n"
        text += f"- **Version:** {standard['version']}\n"
        text += f"- **License:** {standard['license']}\n"
        text += f"- **Purchased from:** {standard['purchased_from']}\n"
        text += f"- **Purchase date:** {standard['purchase_date']}\n\n"

    if has_paid_standards:
        return text

    text += (
        "*Bundled public profiles are ready to query immediately. "
        "Import a purchased standard (for example ISO 27001 from ISO.org) "
        "when you need official proprietary clause text.*\n"
    )
    return text


def render_source_block(metadata: StandardMetadata, include_purchase_date: bool = False) -> str:
    """Render attribution and usage notes for a standard."""
    if metadata.access == "public":
        lines = [f"**Source:** {metadata.title} (bundled public framework profile)"]
        if metadata.issuer:
            lines.append(f"**Issuer:** {metadata.issuer}")
        if metadata.jurisdiction:
            lines.append(f"**Jurisdiction:** {metadata.jurisdiction}")
        urls = [document.get("url") for document in metadata.source_documents if document.get("url")]
        if urls:
            lines.append(f"**Official sources:** {', '.join(urls[:2])}")
        lines.append(
            "**Note:** Curated summary profile. Verify exact wording against the official source."
        )
        return "\n".join(lines)

    purchase_detail = ""
    if include_purchase_date and metadata.purchase_date:
        purchase_detail = f", purchased {metadata.purchase_date}"

    lines = [f"**Source:** {metadata.title} (your licensed copy{purchase_detail})"]
    if metadata.license:
        lines.append(f"**License:** {metadata.license}")
    lines.append("**Notice:** Licensed content. Do not share or redistribute.")
    return "\n".join(lines)


def render_excerpt_footer(metadata: StandardMetadata) -> str:
    """Render a short source footer for embedded excerpts."""
    if metadata.access == "public":
        return (
            f"**Source:** {metadata.title} (bundled public framework profile)\n"
            "**Note:** Curated summary profile. Verify against the official source.\n\n"
        )

    return (
        f"**Source:** {metadata.title} (your licensed copy)\n"
        "⚠️ Licensed content - do not redistribute\n\n"
    )


def render_standard_search_results(
    metadata: StandardMetadata, query: str, results: list[SearchResult]
) -> str:
    """Render query_standard output."""
    text = f"**{metadata.title} - Search Results for '{query}'**\n\n"
    text += f"Found {len(results)} result(s)\n\n"

    for result in results:
        text += f"### {result.clause_id}: {result.title}\n"
        if result.section_type:
            text += f"*{result.section_type}*\n"
        snippet = result.content[:300]
        if len(result.content) > 300:
            snippet += "..."
        text += f"{snippet}\n"
        if result.page:
            text += f"Page {result.page}\n"
        text += "\n"

    text += render_source_block(metadata)
    text += "\n"
    return text


def render_standard_clause(metadata: StandardMetadata, result: SearchResult) -> str:
    """Render get_clause output."""
    text = f"**{metadata.title}**\n\n"
    text += f"## {result.clause_id}: {result.title}\n\n"
    if result.section_type:
        text += f"*{result.section_type}*\n\n"
    text += f"{result.content}\n\n"
    if result.page:
        text += f"📄 **Page:** {result.page}\n\n"
    text += render_source_block(metadata, include_purchase_date=True)
    text += "\n"
    return text
