"""
Citation metadata for the deterministic citation pipeline.

Provides structured identifiers (canonical_ref, display_text, aliases)
that the platform's entity linker uses to match references in agent
responses to MCP tool results -- without relying on LLM formatting.

This is the Python equivalent of citation-universal.ts.
See: docs/guides/law-mcp-golden-standard.md Section 4.9c
"""

from typing import Optional


def build_citation(
    canonical_ref: str,
    display_text: str,
    tool_name: str,
    tool_args: dict[str, str],
    source_url: Optional[str] = None,
    aliases: Optional[list[str]] = None,
) -> dict:
    """Build citation metadata for any retrieval tool response.

    Args:
        canonical_ref: Primary reference the entity linker matches against
                       (e.g., "ISO27001:A.5.1", "CVE-2024-1234")
        display_text: How the reference appears in prose
        tool_name: The MCP tool name (e.g., "get_control", "get_cve_details")
        tool_args: The tool arguments for verification lookup
        source_url: Official portal URL (optional)
        aliases: Alternative names the LLM might use (optional)
    """
    result: dict = {
        "canonical_ref": canonical_ref,
        "display_text": display_text,
    }
    if aliases:
        result["aliases"] = aliases
    if source_url:
        result["source_url"] = source_url
    result["lookup"] = {
        "tool": tool_name,
        "args": tool_args,
    }
    return result
