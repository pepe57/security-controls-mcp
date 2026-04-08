"""Data loader for SCF controls and framework mappings."""

import json
from pathlib import Path
from typing import Any


class SCFData:
    """Loads and provides access to SCF control data."""

    def __init__(self):
        self.controls: list[dict[str, Any]] = []
        self.controls_by_id: dict[str, dict[str, Any]] = {}
        self.framework_to_scf: dict[str, dict[str, list[str]]] = {}
        self.frameworks: dict[str, dict[str, Any]] = {}
        self.framework_categories: dict[str, list[str]] = {}
        self._load_data()

    def _load_data(self):
        """Load SCF controls and reverse index from JSON files."""
        data_dir = Path(__file__).parent / "data"

        # Load controls
        with open(data_dir / "scf-controls.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            self.controls = data["controls"]

        # Build ID index
        self.controls_by_id = {ctrl["id"]: ctrl for ctrl in self.controls}

        # Load reverse index
        with open(data_dir / "framework-to-scf.json", "r", encoding="utf-8") as f:
            self.framework_to_scf = json.load(f)

        # Build framework metadata
        self._build_framework_metadata()

    def _build_framework_metadata(self):
        """Build framework metadata from the generated framework-metadata.json.

        The extraction script (scripts/extract_scf_frameworks.py) produces
        framework-metadata.json with framework names, categories, and stats
        derived directly from the SCF spreadsheet. This keeps the data_loader
        free of hardcoded framework IDs that break on every SCF version upgrade.
        """
        # Load generated metadata (produced by extract_scf_frameworks.py)
        metadata_path = (
            Path(__file__).parent.parent.parent / "scripts" / "data" / "framework-metadata.json"
        )
        if metadata_path.exists():
            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
            framework_names = {
                fw_id: info["name"] for fw_id, info in metadata.get("frameworks", {}).items()
            }
            self.framework_categories = metadata.get("categories", {})
        else:
            # Fallback: derive names from whatever keys exist in the control data
            framework_names = {}
            if self.controls:
                for fw_key in self.controls[0].get("framework_mappings", {}):
                    framework_names[fw_key] = fw_key.replace("_", " ").title()
            self.framework_categories = {}

        # Count controls per framework (only for frameworks that have mappings)
        for fw_key, fw_name in framework_names.items():
            count = sum(1 for ctrl in self.controls if ctrl["framework_mappings"].get(fw_key))
            if count > 0:  # Only include frameworks with actual mappings
                self.frameworks[fw_key] = {
                    "key": fw_key,
                    "name": fw_name,
                    "controls_mapped": count,
                }

        # Register frameworks that exist only in the reverse index
        # (manually-added frameworks that aren't in the SCF spreadsheet).
        # Only register if the framework appears in at least one category.
        all_categorized = set()
        for cat_fws in self.framework_categories.values():
            all_categorized.update(cat_fws)

        for fw_key in self.framework_to_scf:
            if (
                fw_key not in self.frameworks
                and fw_key in framework_names
                and fw_key in all_categorized
            ):
                reverse = self.framework_to_scf[fw_key]
                unique_scf_ids = set()
                for scf_ids in reverse.values():
                    unique_scf_ids.update(scf_ids)
                count = len(unique_scf_ids)
                if count > 0:
                    self.frameworks[fw_key] = {
                        "key": fw_key,
                        "name": framework_names[fw_key],
                        "controls_mapped": count,
                    }

    def get_control(self, control_id: str) -> dict[str, Any] | None:
        """Get control by SCF ID."""
        return self.controls_by_id.get(control_id)

    def search_controls(
        self, query: str, frameworks: list[str] | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Search controls by description with strict match + OR fallback for multi-term queries."""
        query_lower = (query or "").strip().lower()
        if not query_lower:
            return []

        terms = [term for term in query_lower.split() if term]
        if not terms:
            return []

        primary_matches: list[dict[str, Any]] = []
        fallback_matches: list[dict[str, Any]] = []

        for ctrl in self.controls:
            # Filter by frameworks if specified
            if frameworks:
                has_mapping = any(ctrl["framework_mappings"].get(fw) for fw in frameworks)
                if not has_mapping:
                    continue

            name_lower = ctrl["name"].lower() if ctrl["name"] else ""
            desc = ctrl["description"] or ""
            desc_lower = desc.lower()
            haystack = f"{name_lower} {desc_lower}"

            matched_terms = [term for term in terms if term in haystack]
            if not matched_terms:
                continue

            is_exact_phrase = query_lower in haystack
            is_primary = len(terms) == 1 or is_exact_phrase or len(matched_terms) == len(terms)

            # Get mapped frameworks for response
            mapped_frameworks = [
                fw for fw, mappings in ctrl["framework_mappings"].items() if mappings
            ]

            # Prefer phrase snippet, otherwise first matched term.
            snippet_term = query_lower if is_exact_phrase else matched_terms[0]
            idx = desc_lower.find(snippet_term)
            if idx >= 0:
                start = max(0, idx - 50)
                end = min(len(desc), idx + len(snippet_term) + 100)
                snippet = desc[start:end]
                if start > 0:
                    snippet = "..." + snippet
                if end < len(desc):
                    snippet = snippet + "..."
            else:
                snippet = desc[:150] + "..." if len(desc) > 150 else desc

            entry = {
                "control_id": ctrl["id"],
                "name": ctrl["name"],
                "snippet": snippet,
                "relevance": (1.0 if is_exact_phrase else len(matched_terms) / max(len(terms), 1)),
                "mapped_frameworks": mapped_frameworks,
            }

            if is_primary:
                primary_matches.append(entry)
            else:
                fallback_matches.append(entry)

        # Use strict results first; if none for multi-term query, fall back to OR-style matches.
        selected = primary_matches or fallback_matches
        selected.sort(key=lambda item: item["relevance"], reverse=True)
        return selected[:limit]

    def get_framework_controls(
        self, framework: str, include_descriptions: bool = False
    ) -> list[dict[str, Any]]:
        """Get all controls that map to a framework.

        Uses per-control framework_mappings first; falls back to the
        framework-to-scf reverse index for frameworks that only exist there.
        """
        results = []

        for ctrl in self.controls:
            fw_mappings = ctrl["framework_mappings"].get(framework)
            if fw_mappings:
                result = {
                    "scf_id": ctrl["id"],
                    "scf_name": ctrl["name"],
                    "framework_control_ids": fw_mappings,
                    "weight": ctrl["weight"],
                }

                if include_descriptions:
                    result["description"] = ctrl["description"]

                results.append(result)

        # Fallback: use reverse index if no per-control mappings found
        if not results and framework in self.framework_to_scf:
            reverse = self.framework_to_scf[framework]
            aggregated: dict[str, dict[str, Any]] = {}
            for section_id, scf_ids in reverse.items():
                for scf_id in scf_ids:
                    ctrl = self.controls_by_id.get(scf_id)
                    if ctrl:
                        result = aggregated.setdefault(
                            scf_id,
                            {
                                "scf_id": ctrl["id"],
                                "scf_name": ctrl["name"],
                                "framework_control_ids": [],
                                "weight": ctrl["weight"],
                            },
                        )
                        if section_id not in result["framework_control_ids"]:
                            result["framework_control_ids"].append(section_id)
                        if include_descriptions:
                            result["description"] = ctrl["description"]

            results = list(aggregated.values())

        return results

    def map_frameworks(
        self,
        source_framework: str,
        target_framework: str,
        source_control: str | None = None,
    ) -> list[dict[str, Any]]:
        """Map controls between two frameworks via SCF."""
        results = []

        # If source_control specified, filter to only controls with that mapping
        for ctrl in self.controls:
            source_mappings = ctrl["framework_mappings"].get(source_framework)
            target_mappings = ctrl["framework_mappings"].get(target_framework)

            # Skip if no source mapping
            if not source_mappings:
                continue

            # Filter by source_control if specified
            if source_control and not any(
                self._source_control_matches(source_control, mapped_id)
                for mapped_id in source_mappings
            ):
                continue

            results.append(
                {
                    "scf_id": ctrl["id"],
                    "scf_name": ctrl["name"],
                    "source_controls": source_mappings,
                    "target_controls": target_mappings or [],
                    "weight": ctrl["weight"],
                }
            )

        return results

    @staticmethod
    def _source_control_matches(source_control: str, mapped_id: str) -> bool:
        """Compare source control IDs with normalization for Annex-style aliases."""
        source = str(source_control or "").strip().upper()
        mapped = str(mapped_id or "").strip().upper()
        if not source or not mapped:
            return False
        if source == mapped:
            return True

        # Accept "A.5.15" and "5.15" as equivalent to reduce UX friction.
        source_no_annex = source[2:] if source.startswith("A.") else source
        mapped_no_annex = mapped[2:] if mapped.startswith("A.") else mapped
        return source_no_annex == mapped_no_annex
