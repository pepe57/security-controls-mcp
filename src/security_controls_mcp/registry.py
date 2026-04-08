"""Registry for managing all standard providers."""

import logging
from pathlib import Path
from typing import Dict, List, Optional

from .config import Config
from .providers import (
    BundledPublicStandardProvider,
    PaidStandardProvider,
    SearchResult,
    StandardProvider,
)

logger = logging.getLogger(__name__)


class StandardRegistry:
    """Registry for all available standards (SCF + bundled public + paid)."""

    def __init__(self, config: Optional[Config] = None):
        """Initialize the registry.

        Args:
            config: Configuration instance. If None, creates default config.
        """
        self.config = config or Config()
        self.providers: Dict[str, StandardProvider] = {}

        # Load bundled public profiles first, then user-imported paid standards.
        self._load_public_standards()
        self._load_paid_standards()

    def _load_public_standards(self) -> None:
        """Load bundled public framework profiles shipped with the package."""
        public_dir = Path(__file__).parent / "public_standards"
        if not public_dir.exists():
            return

        for standard_dir in sorted(path for path in public_dir.iterdir() if path.is_dir()):
            metadata_file = standard_dir / "metadata.json"
            full_text_file = standard_dir / "full_text.json"

            if not metadata_file.exists() or not full_text_file.exists():
                continue

            try:
                provider = BundledPublicStandardProvider(standard_dir)
                self.providers[provider.get_metadata().standard_id] = provider
            except Exception as e:
                logger.error(f"Could not load bundled public standard '{standard_dir.name}': {e}")

    def _load_paid_standards(self) -> None:
        """Load all enabled paid standards from config."""
        enabled_standards = self.config.get_enabled_standards()

        for standard_id, standard_config in enabled_standards.items():
            try:
                standard_path = self.config.get_standard_path(standard_id)
                if standard_path and standard_path.exists():
                    provider = PaidStandardProvider(standard_path)
                    self.providers[standard_id] = provider
            except Exception as e:
                # Log error but don't fail - just skip this standard
                logger.error(f"Could not load standard '{standard_id}': {e}")

    def get_provider(self, standard_id: str) -> Optional[StandardProvider]:
        """Get a provider by standard ID.

        Args:
            standard_id: The standard identifier

        Returns:
            The provider, or None if not found
        """
        return self.providers.get(standard_id)

    def list_standards(self) -> List[Dict[str, str]]:
        """List all available standards.

        Returns:
            List of dictionaries with standard information
        """
        standards = []

        # Add SCF (always available)
        standards.append(
            {
                "standard_id": "scf",
                "title": "Secure Controls Framework (SCF) 2025.4",
                "type": "built-in",
                "license": "Creative Commons BY-ND 4.0",
                "controls": "1,451 controls across 16 frameworks",
            }
        )

        public_records = []
        paid_records = []

        for standard_id, provider in self.providers.items():
            metadata = provider.get_metadata()
            record = {
                "standard_id": standard_id,
                "title": metadata.title,
                "type": metadata.access,
                "license": metadata.license,
                "version": metadata.version,
                "issuer": metadata.issuer,
                "jurisdiction": metadata.jurisdiction,
                "summary": metadata.summary,
                "source_documents": metadata.source_documents,
                "purchased_from": metadata.purchased_from,
                "purchase_date": metadata.purchase_date,
            }
            if metadata.access == "public":
                public_records.append(record)
            else:
                paid_records.append(record)

        standards.extend(sorted(public_records, key=lambda record: record["title"]))
        standards.extend(sorted(paid_records, key=lambda record: record["title"]))

        return standards

    def search_all(self, query: str, limit: int = 20) -> Dict[str, List[SearchResult]]:
        """Search across all available bundled public and paid standards.

        Args:
            query: Search query string
            limit: Maximum total results

        Returns:
            Dictionary mapping standard_id to list of search results
        """
        all_results = {}
        results_per_standard = max(5, limit // max(1, len(self.providers)))

        for standard_id, provider in self.providers.items():
            results = provider.search(query, limit=results_per_standard)
            if results:
                all_results[standard_id] = results

        return all_results

    def get_clause_from_any_standard(self, clause_id: str) -> Optional[tuple[str, SearchResult]]:
        """Search for a clause across all standards.

        Args:
            clause_id: The clause identifier to search for

        Returns:
            Tuple of (standard_id, SearchResult) if found, None otherwise
        """
        for standard_id, provider in self.providers.items():
            result = provider.get_clause(clause_id)
            if result:
                return (standard_id, result)

        return None

    def has_paid_standards(self) -> bool:
        """Check if any paid standards are loaded.

        Returns:
            True if at least one paid standard is available
        """
        return any(provider.get_metadata().access == "paid" for provider in self.providers.values())

    def has_public_standards(self) -> bool:
        """Check if any bundled public standards are loaded."""
        return any(
            provider.get_metadata().access == "public" for provider in self.providers.values()
        )

    def reload(self) -> None:
        """Reload all standards from config."""
        self.providers.clear()
        self._load_public_standards()
        self._load_paid_standards()
