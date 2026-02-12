"""
EpsteinAnalyzer - AI Pipeline Module
=====================================
Multi-model AI orchestration engine that sends documents to Codex CLI,
Gemini CLI, and Claude Code for analysis, then merges results via consensus.

Usage:
    python -m ai_pipeline.pipeline --dataset 1
    python -m ai_pipeline.pipeline --document 42
    python -m ai_pipeline.pipeline --check-models
    python -m ai_pipeline.pipeline --backfill
"""

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

# ---------------------------------------------------------------------------
# Resolve project root so imports work regardless of cwd
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from database.db import DatabaseManager  # noqa: E402

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ai_pipeline")


def _load_config(config_path: Optional[str] = None) -> dict:
    """Load settings.yaml from the project config directory."""
    if config_path is None:
        config_path = _PROJECT_ROOT / "config" / "settings.yaml"
    with open(config_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ===================================================================
# 1. PromptBuilder
# ===================================================================

class PromptBuilder:
    """Constructs structured analysis prompts for the AI models."""

    _PROMPT_TEMPLATE = """\
=== DOCUMENT ANALYSIS REQUEST ===

DOCUMENT TYPE: {doc_type}
METADATA:
{metadata_block}

{chain_block}
{known_entities_block}

--- DOCUMENT TEXT START ---
{document_text}
--- DOCUMENT TEXT END ---

Analyze the document above and produce your findings in the EXACT section format
shown below.  For each section header, write the header line exactly as shown,
then your content underneath.  Do NOT omit any section -- if you have no data
for a section, write "None identified." under it.

=== SUMMARY ===
Provide a 2-3 sentence plain-language summary of this document.

=== ENTITIES ===
List every person, organisation, location, financial reference, and case reference
you can identify.  For each entity use this format:
- NAME | TYPE | IDENTIFYING DETAILS | SEARCH: https://www.google.com/search?q=ENCODED_NAME

=== REDACTIONS ===
For each redaction you can detect (blacked-out text, [REDACTED] markers, missing
names, etc.) provide your top 5 candidates with confidence percentage and
one-line reasoning:
REDACTION #N (context: "<surrounding text>"):
  1. CANDIDATE_NAME (XX%) - reasoning
  2. CANDIDATE_NAME (XX%) - reasoning
  ... up to 5

=== CONNECTIONS ===
Map relationships between entities using this format:
[Entity A] --relationship_type-- [Entity B] | evidence: "..."

=== EVIDENCE_SCORE ===
For each person identified, assign an incrimination score from 0-100.
Format: NAME | SCORE | JUSTIFICATION

=== CROSS_REFERENCES ===
Note any connections to known cases, dates, locations, recurring patterns,
or external events.  Use bullet points.

=== FLAGS ===
List anything unusual, suspicious, or notable about this document.
Include formatting oddities, missing pages, suspicious timestamps, etc.

=== CAREER_ROLES ===
For each person, state their known role/title at the time of this document.
Format: NAME | ROLE/TITLE | ORGANISATION | TIME PERIOD (if known)
"""

    def __init__(self, data_dir: Optional[Path] = None):
        if data_dir is None:
            cfg = _load_config()
            self.data_dir = Path(cfg["project"]["data_dir"]).resolve()
        else:
            self.data_dir = Path(data_dir).resolve()
        self.queue_dir = self.data_dir / "analysis_queue"
        self.queue_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def build_analysis_prompt(
        self,
        document_text: str,
        doc_type: str,
        metadata: dict,
        known_entities: Optional[list[dict]] = None,
        chain_context: Optional[str] = None,
    ) -> str:
        """Build the full structured analysis prompt and persist to disk."""

        metadata_block = self._format_metadata(metadata)
        chain_block = self._format_chain(chain_context)
        known_entities_block = self._format_known_entities(known_entities)

        prompt = self._PROMPT_TEMPLATE.format(
            doc_type=doc_type or "unknown",
            metadata_block=metadata_block,
            chain_block=chain_block,
            known_entities_block=known_entities_block,
            document_text=document_text,
        )

        # Persist to analysis_queue for audit trail
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        prompt_path = self.queue_dir / f"prompt_{ts}_{prompt_hash}.txt"
        prompt_path.write_text(prompt, encoding="utf-8")
        logger.debug("Prompt saved to %s", prompt_path)

        return prompt

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_metadata(metadata: dict) -> str:
        lines = []
        for key, val in metadata.items():
            lines.append(f"  {key}: {val}")
        return "\n".join(lines) if lines else "  (none)"

    @staticmethod
    def _format_chain(chain_context: Optional[str]) -> str:
        if not chain_context:
            return ""
        return (
            "EMAIL CHAIN CONTEXT (earlier messages in this thread):\n"
            "--- CHAIN START ---\n"
            f"{chain_context}\n"
            "--- CHAIN END ---\n"
        )

    @staticmethod
    def _format_known_entities(known_entities: Optional[list[dict]]) -> str:
        if not known_entities:
            return ""
        compressed = []
        for ent in known_entities[:200]:  # cap to avoid prompt explosion
            parts = [ent.get("name", "?")]
            if ent.get("entity_type"):
                parts.append(f"({ent['entity_type']})")
            if ent.get("role"):
                parts.append(f"[{ent['role']}]")
            if ent.get("implication_score"):
                parts.append(f"score={ent['implication_score']}")
            compressed.append(" ".join(parts))
        graph_summary = "\n".join(f"  - {c}" for c in compressed)
        return (
            "KNOWN ENTITIES (find connections to these):\n"
            f"{graph_summary}\n"
        )


# ===================================================================
# 2. ModelRunner (base) + concrete runners
# ===================================================================

class ModelRunner(ABC):
    """Base class for CLI-based model runners."""

    def __init__(self, cli_command: str, timeout: int = 300):
        self.cli_command = cli_command
        self.timeout = timeout

    @abstractmethod
    def get_name(self) -> str:
        ...

    def check_available(self) -> bool:
        """Test whether the CLI tool responds at all."""
        try:
            cmd = shutil.which(self.cli_command) or self.cli_command
            # On Windows, .cmd/.bat files require shell=True to execute
            use_shell = sys.platform == "win32" and cmd.lower().endswith((".cmd", ".bat"))
            result = subprocess.run(
                [cmd, "--help"],
                capture_output=True,
                text=True,
                timeout=15,
                shell=use_shell,
            )
            return result.returncode in (0, 1, 2)  # --help may exit 1 or 2
        except FileNotFoundError:
            logger.warning("%s CLI not found on PATH", self.get_name())
            return False
        except subprocess.TimeoutExpired:
            logger.warning("%s CLI timed out on availability check", self.get_name())
            return False
        except Exception as exc:
            logger.warning("%s CLI check failed: %s", self.get_name(), exc)
            return False

    def run(self, prompt_text: str, timeout: Optional[int] = None) -> Optional[str]:
        """Send a prompt to the CLI and return the response text."""
        timeout = timeout or self.timeout
        tmp = None
        try:
            # Write prompt to a temp file (safest cross-platform approach)
            tmp = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".txt",
                prefix=f"ea_{self.get_name()}_",
                delete=False,
                encoding="utf-8",
            )
            tmp.write(prompt_text)
            tmp.close()

            cmd = self._build_command(tmp.name)
            # Resolve the executable path (handles Windows .cmd/.bat wrappers)
            resolved = shutil.which(cmd[0]) or cmd[0]
            cmd[0] = resolved
            use_shell = sys.platform == "win32" and resolved.lower().endswith((".cmd", ".bat"))
            logger.info("Running %s  (timeout=%ds)", self.get_name(), timeout)
            start = time.monotonic()

            # Use stdin file handle instead of shell piping to avoid injection
            with open(tmp.name, "r", encoding="utf-8") as stdin_fh:
                result = subprocess.run(
                    cmd,
                    stdin=stdin_fh,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    shell=use_shell,
                )
            elapsed = time.monotonic() - start
            logger.info("%s completed in %.1fs (exit=%d)", self.get_name(), elapsed, result.returncode)

            if result.returncode != 0:
                stderr = (result.stderr or "").strip()
                # Rate-limit detection (common patterns)
                if any(tok in stderr.lower() for tok in ("rate limit", "429", "quota", "too many")):
                    logger.warning("%s hit rate limit: %s", self.get_name(), stderr[:300])
                    return None
                logger.warning("%s exited %d: %s", self.get_name(), result.returncode, stderr[:500])
                # Still try to use stdout if there is content
                if result.stdout and len(result.stdout.strip()) > 50:
                    return result.stdout.strip()
                return None

            return (result.stdout or "").strip() or None

        except subprocess.TimeoutExpired:
            logger.error("%s timed out after %ds", self.get_name(), timeout)
            return None
        except FileNotFoundError:
            logger.error("%s CLI binary not found", self.get_name())
            return None
        except Exception as exc:
            logger.error("%s run error: %s", self.get_name(), exc)
            return None
        finally:
            if tmp is not None:
                try:
                    # Overwrite with random data before deleting (prompt may contain sensitive text)
                    # Use chunked writes to avoid memory spikes on large prompts
                    tmp_size = os.path.getsize(tmp.name)
                    with open(tmp.name, "wb") as wf:
                        remaining = tmp_size
                        while remaining > 0:
                            chunk = min(remaining, 65536)
                            wf.write(os.urandom(chunk))
                            remaining -= chunk
                    os.unlink(tmp.name)
                except OSError:
                    pass

    @abstractmethod
    def _build_command(self, prompt_file: str) -> list[str]:
        """Return the subprocess argument list."""
        ...


class CodexRunner(ModelRunner):
    """Runs prompts through the Codex CLI."""

    def __init__(self, timeout: int = 300):
        super().__init__("codex", timeout)

    def get_name(self) -> str:
        return "codex"

    def _build_command(self, prompt_file: str) -> list[str]:
        # Reads from stdin (file handle passed by run()); no shell piping needed
        return ["codex"]


class GeminiRunner(ModelRunner):
    """Runs prompts through the Gemini CLI."""

    def __init__(self, timeout: int = 300):
        super().__init__("gemini", timeout)

    def get_name(self) -> str:
        return "gemini"

    def _build_command(self, prompt_file: str) -> list[str]:
        return ["gemini", "-p", "-"]


class ClaudeRunner(ModelRunner):
    """Runs prompts through the Claude CLI (claude --print for non-interactive)."""

    def __init__(self, timeout: int = 300):
        super().__init__("claude", timeout)

    def get_name(self) -> str:
        return "claude"

    def _build_command(self, prompt_file: str) -> list[str]:
        return ["claude", "--print"]


# ===================================================================
# 3. ResponseParser
# ===================================================================

class ResponseParser:
    """Parses a structured AI response into a normalised dictionary."""

    # Canonical section keys mapped to the header patterns we look for
    _SECTIONS = [
        ("summary",              r"===\s*SUMMARY\s*==="),
        ("entities",             r"===\s*ENTITIES\s*==="),
        ("redaction_inferences", r"===\s*REDACTIONS?\s*==="),
        ("connections",          r"===\s*CONNECTIONS?\s*==="),
        ("evidence_scores",      r"===\s*EVIDENCE[_ ]?SCORES?\s*==="),
        ("cross_references",     r"===\s*CROSS[_ ]?REFERENCES?\s*==="),
        ("flags",                r"===\s*FLAGS?\s*==="),
        ("career_roles",         r"===\s*CAREER[_ ]?ROLES?\s*==="),
    ]

    def parse_response(self, raw_text: str, model_name: str) -> dict:
        """Parse a raw model response into a structured dict.

        Returns a dict with keys: summary, entities, redaction_inferences,
        connections, evidence_scores, cross_references, flags, career_roles.
        Any section that cannot be parsed is set to None.
        """
        if not raw_text:
            return {key: None for key, _ in self._SECTIONS}

        sections_raw = self._split_sections(raw_text)

        parsed: dict[str, Any] = {}
        parsed["summary"] = self._parse_summary(sections_raw.get("summary"))
        parsed["entities"] = self._parse_entities(sections_raw.get("entities"))
        parsed["redaction_inferences"] = self._parse_redactions(sections_raw.get("redaction_inferences"))
        parsed["connections"] = self._parse_connections(sections_raw.get("connections"))
        parsed["evidence_scores"] = self._parse_evidence_scores(sections_raw.get("evidence_scores"))
        parsed["cross_references"] = self._parse_cross_references(sections_raw.get("cross_references"))
        parsed["flags"] = self._parse_flags(sections_raw.get("flags"))
        parsed["career_roles"] = self._parse_career_roles(sections_raw.get("career_roles"))

        return parsed

    # ------------------------------------------------------------------
    # Section splitting
    # ------------------------------------------------------------------

    def _split_sections(self, text: str) -> dict[str, str]:
        """Split the raw text by section headers, returning {key: body}."""
        # Build one big alternation regex with named groups
        combined_parts = []
        for key, pat in self._SECTIONS:
            combined_parts.append(f"(?P<hdr_{key}>{pat})")
        header_re = re.compile("|".join(combined_parts), re.IGNORECASE)

        matches = list(header_re.finditer(text))
        result: dict[str, str] = {}
        for i, m in enumerate(matches):
            # Determine which key matched
            key = None
            for k, _ in self._SECTIONS:
                if m.group(f"hdr_{k}") is not None:
                    key = k
                    break
            if key is None:
                continue
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            body = text[start:end].strip()
            result[key] = body
        return result

    # ------------------------------------------------------------------
    # Individual parsers (all return None on failure)
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_summary(text: Optional[str]) -> Optional[str]:
        if not text:
            return None
        # Strip "None identified." default
        if text.lower().startswith("none identified"):
            return None
        return text.strip()

    @staticmethod
    def _parse_entities(text: Optional[str]) -> Optional[list[dict]]:
        if not text or text.lower().startswith("none identified"):
            return None
        entities: list[dict] = []
        # Expected format: - NAME | TYPE | DETAILS | SEARCH: url
        for line in text.splitlines():
            line = line.strip().lstrip("-").lstrip("*").strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("|")]
            ent: dict[str, Any] = {"raw": line}
            if len(parts) >= 1:
                ent["name"] = parts[0]
            if len(parts) >= 2:
                ent["type"] = parts[1]
            if len(parts) >= 3:
                ent["details"] = parts[2]
            if len(parts) >= 4:
                search_part = parts[3]
                url_match = re.search(r"https?://\S+", search_part)
                if url_match:
                    ent["search_url"] = url_match.group(0)
            entities.append(ent)
        return entities or None

    @staticmethod
    def _parse_redactions(text: Optional[str]) -> Optional[list[dict]]:
        if not text or text.lower().startswith("none identified"):
            return None
        redactions: list[dict] = []
        current: Optional[dict] = None
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            # Header line for a redaction block
            redact_header = re.match(r"REDACTION\s*#?\s*(\d+)", line, re.IGNORECASE)
            if redact_header:
                if current:
                    redactions.append(current)
                ctx_match = re.search(r'context:\s*"(.*?)"', line, re.IGNORECASE)
                current = {
                    "index": int(redact_header.group(1)),
                    "context": ctx_match.group(1) if ctx_match else "",
                    "candidates": [],
                }
                continue
            # Candidate line: N. NAME (XX%) - reasoning
            cand_match = re.match(
                r"(\d+)\.\s*(.+?)\s*\((\d+)%?\)\s*[-:]\s*(.*)", line
            )
            if cand_match and current is not None:
                current["candidates"].append({
                    "rank": int(cand_match.group(1)),
                    "name": cand_match.group(2).strip(),
                    "confidence": int(cand_match.group(3)),
                    "reasoning": cand_match.group(4).strip(),
                })
        if current:
            redactions.append(current)
        return redactions or None

    @staticmethod
    def _parse_connections(text: Optional[str]) -> Optional[list[dict]]:
        if not text or text.lower().startswith("none identified"):
            return None
        connections: list[dict] = []
        for line in text.splitlines():
            line = line.strip().lstrip("-").lstrip("*").strip()
            if not line:
                continue
            # [Entity A] --relationship-- [Entity B] | evidence: "..."
            m = re.match(
                r"\[(.+?)\]\s*[-—]+\s*(\w[\w\s]*\w?)\s*[-—]+\s*\[(.+?)\]",
                line,
            )
            if m:
                conn: dict[str, Any] = {
                    "source": m.group(1).strip(),
                    "relationship": m.group(2).strip(),
                    "target": m.group(3).strip(),
                }
                evidence_m = re.search(r'evidence:\s*"(.*?)"', line, re.IGNORECASE)
                if evidence_m:
                    conn["evidence"] = evidence_m.group(1)
                connections.append(conn)
            else:
                # Fallback: try pipe-delimited
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    connections.append({
                        "source": parts[0],
                        "relationship": parts[1],
                        "target": parts[2],
                        "evidence": parts[3] if len(parts) > 3 else None,
                    })
        return connections or None

    @staticmethod
    def _parse_evidence_scores(text: Optional[str]) -> Optional[list[dict]]:
        if not text or text.lower().startswith("none identified"):
            return None
        scores: list[dict] = []
        for line in text.splitlines():
            line = line.strip().lstrip("-").lstrip("*").strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2:
                score_str = re.search(r"\d+", parts[1])
                scores.append({
                    "name": parts[0],
                    "score": int(score_str.group(0)) if score_str else 0,
                    "justification": parts[2] if len(parts) >= 3 else "",
                })
        return scores or None

    @staticmethod
    def _parse_cross_references(text: Optional[str]) -> Optional[list[str]]:
        if not text or text.lower().startswith("none identified"):
            return None
        refs: list[str] = []
        for line in text.splitlines():
            line = line.strip().lstrip("-").lstrip("*").strip()
            if line:
                refs.append(line)
        return refs or None

    @staticmethod
    def _parse_flags(text: Optional[str]) -> Optional[list[str]]:
        if not text or text.lower().startswith("none identified"):
            return None
        flags: list[str] = []
        for line in text.splitlines():
            line = line.strip().lstrip("-").lstrip("*").strip()
            if line:
                flags.append(line)
        return flags or None

    @staticmethod
    def _parse_career_roles(text: Optional[str]) -> Optional[list[dict]]:
        if not text or text.lower().startswith("none identified"):
            return None
        roles: list[dict] = []
        for line in text.splitlines():
            line = line.strip().lstrip("-").lstrip("*").strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("|")]
            entry: dict[str, str] = {"name": parts[0]}
            if len(parts) >= 2:
                entry["role"] = parts[1]
            if len(parts) >= 3:
                entry["organization"] = parts[2]
            if len(parts) >= 4:
                entry["time_period"] = parts[3]
            roles.append(entry)
        return roles or None


# ===================================================================
# 4. ConsensusEngine
# ===================================================================

class ConsensusEngine:
    """Merges analyses from multiple models into a consensus result."""

    FULL_AGREEMENT = "full_agreement"
    MAJORITY = "majority"
    SPLIT = "split"
    SINGLE_SOURCE = "single_source"

    # Confidence tags applied per-field
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    UNIQUE_INSIGHT = "UNIQUE_INSIGHT"

    def merge_analyses(
        self,
        analyses: list[dict],
        model_names: list[str],
    ) -> dict:
        """Produce a consensus dict from 1-3 model analyses.

        Returns {
            "summary": ...,
            "entities": ...,
            "connections": ...,
            "evidence_scores": ...,
            "redaction_inferences": ...,
            "cross_references": ...,
            "flags": ...,
            "career_roles": ...,
            "agreement_level": ...,
            "models_used": ...,
            "disagreements": [...],
            "unique_insights": [...],
        }
        """
        n = len(analyses)
        if n == 0:
            return self._empty_consensus()

        disagreements: list[dict] = []
        unique_insights: list[dict] = []

        consensus: dict[str, Any] = {}

        # ---- Summary (take longest / merge) ----
        consensus["summary"] = self._merge_text_field(
            "summary", analyses, model_names, disagreements
        )

        # ---- List-based fields ----
        for field in ("entities", "connections", "cross_references", "flags", "career_roles"):
            consensus[field] = self._merge_list_field(
                field, analyses, model_names, disagreements, unique_insights
            )

        # ---- Evidence scores (average where names match) ----
        consensus["evidence_scores"] = self._merge_evidence_scores(
            analyses, model_names, disagreements
        )

        # ---- Redaction inferences ----
        consensus["redaction_inferences"] = self._merge_redaction_inferences(
            analyses, model_names, disagreements, unique_insights
        )

        # ---- Overall agreement level ----
        if n == 1:
            agreement = self.SINGLE_SOURCE
        elif len(disagreements) == 0:
            agreement = self.FULL_AGREEMENT
        elif len(disagreements) <= 3:
            agreement = self.MAJORITY
        else:
            agreement = self.SPLIT

        consensus["agreement_level"] = agreement
        consensus["models_used"] = n
        consensus["model_names"] = model_names
        consensus["disagreements"] = disagreements
        consensus["unique_insights"] = unique_insights
        consensus["needs_user_review"] = agreement in (self.SPLIT, self.SINGLE_SOURCE)

        return consensus

    # ------------------------------------------------------------------
    # Merge helpers
    # ------------------------------------------------------------------

    def _merge_text_field(
        self, field: str, analyses: list[dict], names: list[str],
        disagreements: list[dict],
    ) -> Optional[str]:
        """For text fields (summary), pick the longest non-None value."""
        values = [(names[i], a.get(field)) for i, a in enumerate(analyses) if a.get(field)]
        if not values:
            return None
        if len(values) == 1:
            return values[0][1]
        # Pick the longest
        longest = max(values, key=lambda x: len(x[1]))
        return longest[1]

    def _merge_list_field(
        self, field: str, analyses: list[dict], names: list[str],
        disagreements: list[dict], unique_insights: list[dict],
    ) -> Optional[list]:
        """Merge list fields by combining unique items across models."""
        all_items: list[tuple[str, Any]] = []  # (model, item)
        for i, a in enumerate(analyses):
            items = a.get(field)
            if items and isinstance(items, list):
                for item in items:
                    all_items.append((names[i], item))

        if not all_items:
            return None

        # Deduplicate by a normalised key
        seen: dict[str, dict] = {}
        for model, item in all_items:
            key = self._item_key(item)
            if key in seen:
                seen[key].setdefault("_models", []).append(model)
            else:
                entry = dict(item) if isinstance(item, dict) else {"value": item}
                entry["_models"] = [model]
                seen[key] = entry

        merged = []
        n = len(analyses)
        for key, entry in seen.items():
            models_with = entry.pop("_models", [])
            count = len(set(models_with))
            if n >= 3 and count == 1:
                entry["_consensus"] = self.UNIQUE_INSIGHT
                unique_insights.append({
                    "field": field,
                    "model": models_with[0],
                    "item": entry,
                })
            elif n >= 3 and count == 2:
                entry["_consensus"] = self.LIKELY
            elif count >= n:
                entry["_consensus"] = self.CONFIRMED
            else:
                entry["_consensus"] = self.LIKELY
            entry["_model_count"] = count
            merged.append(entry)

        return merged

    def _merge_evidence_scores(
        self, analyses: list[dict], names: list[str],
        disagreements: list[dict],
    ) -> Optional[list[dict]]:
        """Average evidence scores per person across models."""
        # Collect scores keyed by normalised name
        name_scores: dict[str, list[tuple[str, int, str]]] = {}
        for i, a in enumerate(analyses):
            scores = a.get("evidence_scores")
            if not scores or not isinstance(scores, list):
                continue
            for entry in scores:
                person = self._normalise_name(entry.get("name", ""))
                if not person:
                    continue
                name_scores.setdefault(person, []).append(
                    (names[i], entry.get("score", 0), entry.get("justification", ""))
                )

        if not name_scores:
            return None

        merged: list[dict] = []
        n = len(analyses)
        for person, model_scores in name_scores.items():
            scores_only = [s for _, s, _ in model_scores]
            avg = round(sum(scores_only) / len(scores_only))
            spread = max(scores_only) - min(scores_only) if len(scores_only) > 1 else 0
            justifications = "; ".join(
                f"[{m}] {j}" for m, _, j in model_scores if j
            )

            # Flag large disagreement
            if spread > 30:
                disagreements.append({
                    "field": "evidence_scores",
                    "entity": person,
                    "scores": {m: s for m, s, _ in model_scores},
                    "spread": spread,
                })

            consensus_level = self.CONFIRMED
            if len(model_scores) < n:
                consensus_level = self.UNIQUE_INSIGHT if len(model_scores) == 1 else self.LIKELY
            elif spread > 30:
                consensus_level = self.NEEDS_REVIEW

            merged.append({
                "name": person,
                "score": avg,
                "individual_scores": {m: s for m, s, _ in model_scores},
                "justification": justifications,
                "_consensus": consensus_level,
                "_model_count": len(model_scores),
            })

        merged.sort(key=lambda x: x["score"], reverse=True)
        return merged

    def _merge_redaction_inferences(
        self, analyses: list[dict], names: list[str],
        disagreements: list[dict], unique_insights: list[dict],
    ) -> Optional[list[dict]]:
        """Merge redaction candidate lists across models."""
        all_redactions: dict[int, list[tuple[str, dict]]] = {}
        for i, a in enumerate(analyses):
            rlist = a.get("redaction_inferences")
            if not rlist or not isinstance(rlist, list):
                continue
            for r in rlist:
                idx = r.get("index", 0)
                all_redactions.setdefault(idx, []).append((names[i], r))

        if not all_redactions:
            return None

        merged: list[dict] = []
        n = len(analyses)
        for idx in sorted(all_redactions.keys()):
            entries = all_redactions[idx]
            # Merge candidate lists: combine and score
            candidate_votes: dict[str, list[tuple[str, int, str]]] = {}
            context_parts: list[str] = []
            for model, r in entries:
                if r.get("context"):
                    context_parts.append(r["context"])
                for cand in r.get("candidates", []):
                    cname = self._normalise_name(cand.get("name", ""))
                    if cname:
                        candidate_votes.setdefault(cname, []).append(
                            (model, cand.get("confidence", 0), cand.get("reasoning", ""))
                        )

            ranked: list[dict] = []
            for cname, votes in candidate_votes.items():
                avg_conf = round(sum(c for _, c, _ in votes) / len(votes))
                model_count = len(set(m for m, _, _ in votes))
                if model_count >= n:
                    tag = self.CONFIRMED
                elif model_count >= 2:
                    tag = self.LIKELY
                else:
                    tag = self.UNIQUE_INSIGHT
                    unique_insights.append({
                        "field": "redaction_inferences",
                        "redaction_index": idx,
                        "model": votes[0][0],
                        "candidate": cname,
                    })
                ranked.append({
                    "name": cname,
                    "avg_confidence": avg_conf,
                    "model_count": model_count,
                    "reasoning": "; ".join(f"[{m}] {r}" for m, _, r in votes if r),
                    "_consensus": tag,
                })
            ranked.sort(key=lambda x: x["avg_confidence"], reverse=True)

            merged.append({
                "index": idx,
                "context": context_parts[0] if context_parts else "",
                "candidates": ranked[:5],
            })

        return merged

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _item_key(item: Any) -> str:
        """Generate a stable dedup key for a list item."""
        if isinstance(item, dict):
            # Use name or source+target for connections
            if "source" in item and "target" in item:
                return f"{item['source']}|{item.get('relationship', '')}|{item['target']}".lower()
            if "name" in item:
                return item["name"].lower().strip()
            return json.dumps(item, sort_keys=True, default=str)
        return str(item).lower().strip()

    @staticmethod
    def _normalise_name(name: str) -> str:
        return re.sub(r"\s+", " ", name).strip().title()

    @staticmethod
    def _empty_consensus() -> dict:
        return {
            "summary": None,
            "entities": None,
            "connections": None,
            "evidence_scores": None,
            "redaction_inferences": None,
            "cross_references": None,
            "flags": None,
            "career_roles": None,
            "agreement_level": "single_source",
            "models_used": 0,
            "model_names": [],
            "disagreements": [],
            "unique_insights": [],
            "needs_user_review": True,
        }


# ===================================================================
# 5. GracefulDegradation
# ===================================================================

class GracefulDegradation:
    """Manages model availability and degraded-mode operation."""

    _RUNNER_CLASSES: list[type[ModelRunner]] = [CodexRunner, GeminiRunner, ClaudeRunner]

    def __init__(self, config: Optional[dict] = None):
        self.config = config or _load_config()
        self._runners: list[ModelRunner] = []
        self._build_runners()

    def _build_runners(self):
        ai_cfg = self.config.get("ai_pipeline", {}).get("models", {})
        for cls in self._RUNNER_CLASSES:
            key = cls.__name__.replace("Runner", "").lower()
            model_cfg = ai_cfg.get(key, {})
            if model_cfg.get("enabled", True):
                timeout = model_cfg.get("timeout_seconds", 300)
                self._runners.append(cls(timeout=timeout))

    def check_all_models(self) -> dict[str, bool]:
        """Return {model_name: available} for every configured runner."""
        status = {}
        for runner in self._runners:
            avail = runner.check_available()
            status[runner.get_name()] = avail
            logger.info("Model %s: %s", runner.get_name(), "available" if avail else "unavailable")
        return status

    def get_available_runners(self) -> list[ModelRunner]:
        """Return only the runners whose CLI is currently reachable."""
        available = []
        for runner in self._runners:
            if runner.check_available():
                available.append(runner)
        return available

    def describe_mode(self, available_count: int) -> str:
        if available_count >= 3:
            return "full_consensus"
        if available_count == 2:
            return "dual_consensus"
        if available_count == 1:
            return "single_source"
        return "paused"

    def backfill_queue(self, db: DatabaseManager) -> list[dict]:
        """Find documents analyzed by fewer models than currently available.

        Returns a list of {document_id, models_completed, models_available}.
        """
        available = self.get_available_runners()
        available_names = {r.get_name() for r in available}
        n_available = len(available_names)
        if n_available < 2:
            logger.info("Backfill skipped: fewer than 2 models available")
            return []

        conn = db.get_connection()
        try:
            # Find documents that have fewer completed analyses than available models
            rows = conn.execute("""
                SELECT d.id AS document_id,
                       COUNT(DISTINCT a.model_name) AS models_completed,
                       GROUP_CONCAT(DISTINCT a.model_name) AS completed_models
                FROM documents d
                LEFT JOIN ai_analyses a ON d.id = a.document_id
                WHERE d.status IN ('analyzed', 'ocr_complete')
                  AND d.analysis_completed = 1
                GROUP BY d.id
                HAVING models_completed < ?
                ORDER BY d.priority_score DESC
            """, (n_available,)).fetchall()

            queue: list[dict] = []
            for row in rows:
                completed = set((row["completed_models"] or "").split(",")) - {""}
                missing = available_names - completed
                if missing:
                    queue.append({
                        "document_id": row["document_id"],
                        "models_completed": row["models_completed"],
                        "models_available": n_available,
                        "missing_models": list(missing),
                    })

            logger.info("Backfill queue: %d documents need additional analysis", len(queue))
            return queue
        finally:
            conn.close()


# ===================================================================
# 6. PipelineEngine
# ===================================================================

class PipelineEngine:
    """Main orchestrator: prompt -> models -> parse -> consensus -> DB."""

    def __init__(self, config_path: Optional[str] = None):
        self.config = _load_config(config_path)
        self.db = DatabaseManager(config_path)
        self.prompt_builder = PromptBuilder(
            Path(self.config["project"]["data_dir"]).resolve()
        )
        self.parser = ResponseParser()
        self.consensus_engine = ConsensusEngine()
        self.degradation = GracefulDegradation(self.config)

        batch_cfg = self.config.get("ai_pipeline", {}).get("batch", {})
        self.rate_limit_seconds = batch_cfg.get("rate_limit_seconds", 5)
        self.max_batch_size = batch_cfg.get("max_batch_size", 20)
        self.chain_aware = batch_cfg.get("chain_aware", True)

        # Optional progress callback: fn(current, total, document_id, status_msg)
        self.progress_callback: Optional[Callable] = None

    # ------------------------------------------------------------------
    # Single document
    # ------------------------------------------------------------------

    def analyze_document(self, document_id: int) -> dict:
        """Full pipeline for one document.

        Returns the consensus dict (also saved to DB).
        """
        logger.info("=== Analyzing document %d ===", document_id)

        # 1. Load document data
        doc = self._load_document(document_id)
        if doc is None:
            logger.error("Document %d not found", document_id)
            return {"error": f"Document {document_id} not found"}

        # Mark as analyzing
        self._update_doc_status(document_id, "analyzing")

        # 2. Gather chain context if applicable
        chain_context = self._get_chain_context(document_id) if self.chain_aware else None

        # 3. Gather known entities for connection finding
        known_entities = self._get_known_entities()

        # 4. Build prompt
        document_text = self._get_document_text(document_id)
        metadata = {
            "filename": doc["original_filename"],
            "file_type": doc["file_type"],
            "dataset_id": doc["dataset_id"],
            "priority_score": doc["priority_score"],
            "page_count": doc["page_count"],
            "source": doc["source"],
        }
        prompt = self.prompt_builder.build_analysis_prompt(
            document_text=document_text,
            doc_type=doc["doc_type"],
            metadata=metadata,
            known_entities=known_entities,
            chain_context=chain_context,
        )

        # 5. Run available models
        runners = self.degradation.get_available_runners()
        if not runners:
            logger.error("No AI models available -- pipeline paused")
            self._update_doc_status(document_id, "ocr_complete")  # revert
            return {"error": "No AI models available", "status": "paused"}

        mode = self.degradation.describe_mode(len(runners))
        logger.info("Running in %s mode with %d model(s)", mode, len(runners))

        raw_responses: dict[str, Optional[str]] = {}
        parsed_analyses: list[dict] = []
        model_names: list[str] = []

        for runner in runners:
            t0 = time.time()
            response = runner.run(prompt)
            elapsed = time.time() - t0
            raw_responses[runner.get_name()] = response

            if response:
                parsed = self.parser.parse_response(response, runner.get_name())
                # Save individual analysis to DB
                self._save_analysis(document_id, runner.get_name(), parsed, response, elapsed)
                parsed_analyses.append(parsed)
                model_names.append(runner.get_name())
            else:
                logger.warning("No response from %s for document %d", runner.get_name(), document_id)

            # Rate limiting between model calls
            if runner is not runners[-1]:
                time.sleep(self.rate_limit_seconds)

        # 6. Build consensus
        if not parsed_analyses:
            logger.error("All models failed for document %d", document_id)
            self._update_doc_status(document_id, "ocr_complete")
            return {"error": "All models failed to produce output"}

        consensus = self.consensus_engine.merge_analyses(parsed_analyses, model_names)

        # 7. Save consensus to DB
        self._save_consensus(document_id, consensus)

        # 8. Update document status
        self._update_doc_status(document_id, "analyzed")
        self._mark_analysis_complete(document_id)

        # 9. Update knowledge graph entities/relationships
        self._update_knowledge_graph(document_id, consensus)

        logger.info(
            "Document %d analysis complete: agreement=%s, models=%d",
            document_id, consensus["agreement_level"], consensus["models_used"],
        )
        return consensus

    # ------------------------------------------------------------------
    # Batch
    # ------------------------------------------------------------------

    def analyze_batch(self, document_ids: list[int]) -> list[dict]:
        """Process multiple documents with progress tracking."""
        total = len(document_ids)
        results: list[dict] = []

        # If chain-aware, reorder so email chains are grouped
        if self.chain_aware:
            document_ids = self._order_by_chains(document_ids)

        for idx, doc_id in enumerate(document_ids, 1):
            if self.progress_callback:
                self.progress_callback(idx, total, doc_id, "starting")

            try:
                result = self.analyze_document(doc_id)
                results.append({"document_id": doc_id, "result": result})
            except Exception as exc:
                logger.error("Error analyzing document %d: %s", doc_id, exc)
                logger.debug(traceback.format_exc())
                results.append({"document_id": doc_id, "error": str(exc)})

            if self.progress_callback:
                status = "error" if "error" in results[-1] else "complete"
                self.progress_callback(idx, total, doc_id, status)

            # Rate limit between documents
            if idx < total:
                time.sleep(self.rate_limit_seconds)

        return results

    def analyze_dataset(self, dataset_number: int) -> list[dict]:
        """Analyze all priority-queued documents in a dataset."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute("""
                SELECT d.id
                FROM documents d
                JOIN datasets ds ON d.dataset_id = ds.id
                WHERE ds.dataset_number = ?
                  AND d.status IN ('ocr_complete', 'pending')
                  AND d.analysis_completed = 0
                ORDER BY d.priority_score DESC
                LIMIT ?
            """, (dataset_number, self.max_batch_size)).fetchall()
        finally:
            conn.close()

        doc_ids = [r["id"] for r in rows]
        if not doc_ids:
            logger.info("No documents queued for dataset %d", dataset_number)
            return []

        logger.info(
            "Starting analysis of %d documents from dataset %d",
            len(doc_ids), dataset_number,
        )
        return self.analyze_batch(doc_ids)

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _load_document(self, document_id: int) -> Optional[dict]:
        conn = self.db.get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM documents WHERE id = ?", (document_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def _get_document_text(self, document_id: int) -> str:
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                "SELECT page_number, text_content FROM document_pages "
                "WHERE document_id = ? ORDER BY page_number",
                (document_id,),
            ).fetchall()
            if not rows:
                return "(No extracted text available for this document.)"
            pages: list[str] = []
            for r in rows:
                pages.append(f"--- Page {r['page_number']} ---\n{r['text_content'] or ''}")
            return "\n\n".join(pages)
        finally:
            conn.close()

    def _get_chain_context(self, document_id: int) -> Optional[str]:
        """If this document is part of an email chain, return earlier messages."""
        conn = self.db.get_connection()
        try:
            # Find chain membership
            msg = conn.execute(
                "SELECT chain_id, position_in_chain FROM email_messages WHERE document_id = ?",
                (document_id,),
            ).fetchone()
            if not msg or not msg["chain_id"]:
                return None

            # Get earlier messages in the chain
            earlier = conn.execute("""
                SELECT em.from_name, em.subject, em.email_date, em.body_text
                FROM email_messages em
                WHERE em.chain_id = ? AND em.position_in_chain < ?
                ORDER BY em.position_in_chain ASC
            """, (msg["chain_id"], msg["position_in_chain"])).fetchall()

            if not earlier:
                return None

            parts: list[str] = []
            for m in earlier:
                parts.append(
                    f"From: {m['from_name'] or 'Unknown'}\n"
                    f"Date: {m['email_date'] or 'Unknown'}\n"
                    f"Subject: {m['subject'] or 'N/A'}\n"
                    f"{m['body_text'] or '(no body)'}\n"
                )
            return "\n---\n".join(parts)
        finally:
            conn.close()

    def _get_known_entities(self) -> Optional[list[dict]]:
        """Return a compressed summary of known entities for the prompt."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute("""
                SELECT name, entity_type, role, implication_score
                FROM entities
                WHERE is_redacted_placeholder = 0
                ORDER BY implication_score DESC
                LIMIT 200
            """).fetchall()
            if not rows:
                return None
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def _update_doc_status(self, document_id: int, status: str):
        conn = self.db.get_connection()
        try:
            conn.execute(
                "UPDATE documents SET status = ?, updated_at = ? WHERE id = ?",
                (status, datetime.now(timezone.utc).isoformat(), document_id),
            )
            conn.commit()
        finally:
            conn.close()

    def _mark_analysis_complete(self, document_id: int):
        conn = self.db.get_connection()
        try:
            conn.execute(
                "UPDATE documents SET analysis_completed = 1, updated_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), document_id),
            )
            conn.commit()
        finally:
            conn.close()

    def _save_analysis(
        self,
        document_id: int,
        model_name: str,
        parsed: dict,
        raw_response: str,
        processing_time: float,
    ):
        conn = self.db.get_connection()
        try:
            conn.execute("""
                INSERT INTO ai_analyses (
                    document_id, model_name, summary, entities_found,
                    redaction_inferences, connections_found, evidence_scores,
                    cross_references, flags, career_roles, raw_response,
                    processing_time_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                document_id,
                model_name,
                parsed.get("summary"),
                json.dumps(parsed.get("entities"), default=str) if parsed.get("entities") else None,
                json.dumps(parsed.get("redaction_inferences"), default=str) if parsed.get("redaction_inferences") else None,
                json.dumps(parsed.get("connections"), default=str) if parsed.get("connections") else None,
                json.dumps(parsed.get("evidence_scores"), default=str) if parsed.get("evidence_scores") else None,
                json.dumps(parsed.get("cross_references"), default=str) if parsed.get("cross_references") else None,
                json.dumps(parsed.get("flags"), default=str) if parsed.get("flags") else None,
                json.dumps(parsed.get("career_roles"), default=str) if parsed.get("career_roles") else None,
                raw_response,
                processing_time,
            ))
            conn.commit()
            logger.debug("Saved %s analysis for document %d", model_name, document_id)
        finally:
            conn.close()

    def _save_consensus(self, document_id: int, consensus: dict):
        conn = self.db.get_connection()
        try:
            conn.execute("""
                INSERT INTO ai_consensus (
                    document_id, consensus_summary, consensus_entities,
                    consensus_connections, consensus_evidence_scores,
                    consensus_redaction_inferences, agreement_level,
                    models_used, disagreements, unique_insights,
                    needs_user_review
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                document_id,
                consensus.get("summary"),
                json.dumps(consensus.get("entities"), default=str) if consensus.get("entities") else None,
                json.dumps(consensus.get("connections"), default=str) if consensus.get("connections") else None,
                json.dumps(consensus.get("evidence_scores"), default=str) if consensus.get("evidence_scores") else None,
                json.dumps(consensus.get("redaction_inferences"), default=str) if consensus.get("redaction_inferences") else None,
                consensus.get("agreement_level"),
                consensus.get("models_used", 0),
                json.dumps(consensus.get("disagreements", []), default=str),
                json.dumps(consensus.get("unique_insights", []), default=str),
                1 if consensus.get("needs_user_review") else 0,
            ))
            conn.commit()

            # Mark individual analyses as consensus-processed
            conn.execute(
                "UPDATE ai_analyses SET is_consensus_processed = 1 WHERE document_id = ?",
                (document_id,),
            )
            conn.commit()
            logger.debug("Saved consensus for document %d", document_id)
        finally:
            conn.close()

    def _update_knowledge_graph(self, document_id: int, consensus: dict):
        """Insert or update entities and relationships from the consensus."""
        conn = self.db.get_connection()
        try:
            now = datetime.now(timezone.utc).isoformat()

            # --- Entities ---
            entities_list = consensus.get("entities") or []
            entity_id_map: dict[str, int] = {}  # normalised_name -> entity_id

            for ent in entities_list:
                if not isinstance(ent, dict):
                    continue
                name = ent.get("name", "").strip()
                if not name:
                    continue

                etype = self._map_entity_type(ent.get("type", "person"))
                canonical = re.sub(r"\s+", " ", name).strip().title()
                google_url = ent.get("search_url", f"https://www.google.com/search?q={canonical.replace(' ', '+')}")

                # Upsert entity
                existing = conn.execute(
                    "SELECT id FROM entities WHERE canonical_name = ? AND entity_type = ?",
                    (canonical, etype),
                ).fetchone()

                if existing:
                    eid = existing["id"]
                    conn.execute(
                        "UPDATE entities SET document_count = document_count + 1, updated_at = ? WHERE id = ?",
                        (now, eid),
                    )
                else:
                    role = None
                    # Check career_roles for this entity
                    roles_list = consensus.get("career_roles") or []
                    for cr in roles_list:
                        if isinstance(cr, dict) and self._names_match(cr.get("name", ""), name):
                            role = cr.get("role")
                            break

                    cursor = conn.execute("""
                        INSERT INTO entities (name, entity_type, canonical_name, google_url,
                                              role, document_count, first_seen_document_id, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                    """, (name, etype, canonical, google_url, role, document_id, now, now))
                    eid = cursor.lastrowid

                entity_id_map[canonical.lower()] = eid

                # Link entity to document
                conn.execute("""
                    INSERT OR IGNORE INTO entity_document_links (entity_id, document_id, mention_type, created_at)
                    VALUES (?, ?, 'mentioned', ?)
                """, (eid, document_id, now))

            # --- Evidence scores ---
            scores_list = consensus.get("evidence_scores") or []
            for sc in scores_list:
                if not isinstance(sc, dict):
                    continue
                name_key = re.sub(r"\s+", " ", sc.get("name", "")).strip().title().lower()
                eid = entity_id_map.get(name_key)
                if eid:
                    conn.execute(
                        "UPDATE entities SET implication_score = MAX(implication_score, ?), "
                        "evidence_count = evidence_count + 1, updated_at = ? WHERE id = ?",
                        (sc.get("score", 0), now, eid),
                    )
                    # Update entity-document link score
                    conn.execute("""
                        UPDATE entity_document_links SET damning_score = ?, score_reasoning = ?
                        WHERE entity_id = ? AND document_id = ?
                    """, (sc.get("score", 0), sc.get("justification", ""), eid, document_id))

            # --- Connections / Relationships ---
            conns_list = consensus.get("connections") or []
            for c in conns_list:
                if not isinstance(c, dict):
                    continue
                src_name = re.sub(r"\s+", " ", c.get("source", "")).strip().title().lower()
                tgt_name = re.sub(r"\s+", " ", c.get("target", "")).strip().title().lower()
                rel_type = c.get("relationship", "associated_with")

                src_id = entity_id_map.get(src_name)
                tgt_id = entity_id_map.get(tgt_name)

                if src_id and tgt_id and src_id != tgt_id:
                    existing_rel = conn.execute(
                        "SELECT id, evidence_count FROM relationships "
                        "WHERE source_entity_id = ? AND target_entity_id = ? AND relationship_type = ?",
                        (src_id, tgt_id, rel_type),
                    ).fetchone()

                    if existing_rel:
                        conn.execute("""
                            UPDATE relationships
                            SET weight = weight + 1, evidence_count = evidence_count + 1,
                                updated_at = ?
                            WHERE id = ?
                        """, (now, existing_rel["id"]))
                    else:
                        evidence_doc_ids = json.dumps([document_id])
                        conn.execute("""
                            INSERT INTO relationships (
                                source_entity_id, target_entity_id, relationship_type,
                                weight, confidence, is_inferred, inference_method,
                                evidence_document_ids, evidence_count, created_at, updated_at
                            ) VALUES (?, ?, ?, 1.0, ?, 0, 'ai', ?, 1, ?, ?)
                        """, (
                            src_id, tgt_id, rel_type,
                            c.get("_consensus_confidence", 0.8),
                            evidence_doc_ids, now, now,
                        ))

            # --- Redaction inferences ---
            redact_list = consensus.get("redaction_inferences") or []
            for ri in redact_list:
                if not isinstance(ri, dict):
                    continue
                candidates = ri.get("candidates", [])
                if candidates:
                    ai_candidates_json = json.dumps(candidates, default=str)
                    # Update any matching redaction record for this document
                    conn.execute("""
                        UPDATE redactions
                        SET ai_candidates = ?,
                            status = CASE WHEN status = 'unresolved' THEN 'inferred' ELSE status END,
                            updated_at = ?
                        WHERE document_id = ? AND id IN (
                            SELECT id FROM redactions WHERE document_id = ?
                            ORDER BY id LIMIT 1 OFFSET ?
                        )
                    """, (ai_candidates_json, now, document_id, document_id, ri.get("index", 0)))

            conn.commit()
            logger.info("Knowledge graph updated for document %d (%d entities, %d connections)",
                        document_id, len(entity_id_map), len(conns_list))

        except Exception as exc:
            conn.rollback()
            logger.error("Knowledge graph update failed for document %d: %s", document_id, exc)
            logger.debug(traceback.format_exc())
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Chain-aware ordering
    # ------------------------------------------------------------------

    def _order_by_chains(self, document_ids: list[int]) -> list[int]:
        """Reorder document IDs so email chains are grouped and in order."""
        if not document_ids:
            return document_ids

        conn = self.db.get_connection()
        try:
            placeholders = ",".join("?" for _ in document_ids)
            rows = conn.execute(f"""
                SELECT em.document_id, em.chain_id, em.position_in_chain
                FROM email_messages em
                WHERE em.document_id IN ({placeholders})
                ORDER BY em.chain_id, em.position_in_chain
            """, document_ids).fetchall()

            chained: dict[int, list[int]] = {}  # chain_id -> [doc_ids in order]
            chained_set: set[int] = set()
            for r in rows:
                cid = r["chain_id"]
                did = r["document_id"]
                if cid:
                    chained.setdefault(cid, []).append(did)
                    chained_set.add(did)

            # Build ordered list: chained first (grouped), then non-chained
            ordered: list[int] = []
            for chain_docs in chained.values():
                for did in chain_docs:
                    if did not in ordered:
                        ordered.append(did)
            for did in document_ids:
                if did not in chained_set and did not in ordered:
                    ordered.append(did)

            return ordered
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Entity type mapping
    # ------------------------------------------------------------------

    _ENTITY_TYPE_MAP = {
        "person": "person",
        "individual": "person",
        "people": "person",
        "org": "organization",
        "organisation": "organization",
        "organization": "organization",
        "company": "organization",
        "location": "location",
        "place": "location",
        "address": "location",
        "aircraft": "aircraft",
        "plane": "aircraft",
        "financial": "financial",
        "money": "financial",
        "bank": "financial",
        "legal": "legal_case",
        "case": "legal_case",
        "court": "legal_case",
        "contact": "contact_info",
        "phone": "contact_info",
        "email": "contact_info",
        "event": "event",
    }

    @classmethod
    def _map_entity_type(cls, raw_type: str) -> str:
        key = raw_type.lower().strip()
        return cls._ENTITY_TYPE_MAP.get(key, "person")

    @staticmethod
    def _names_match(a: str, b: str) -> bool:
        na = re.sub(r"\s+", " ", a).strip().lower()
        nb = re.sub(r"\s+", " ", b).strip().lower()
        return na == nb or na in nb or nb in na


# ===================================================================
# __main__ CLI
# ===================================================================

def main():
    parser = argparse.ArgumentParser(
        description="EpsteinAnalyzer AI Pipeline",
        prog="python -m ai_pipeline.pipeline",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dataset", type=int, help="Analyze all queued documents in dataset N")
    group.add_argument("--document", type=int, help="Analyze a single document by ID")
    group.add_argument("--check-models", action="store_true", help="Check which AI models are available")
    group.add_argument("--backfill", action="store_true", help="Queue documents for backfill analysis")

    parser.add_argument("--config", type=str, default=None, help="Path to settings.yaml")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("ai_pipeline").setLevel(logging.DEBUG)

    # Progress callback for CLI
    def cli_progress(current: int, total: int, doc_id: int, status: str):
        pct = round(current / total * 100) if total else 0
        print(f"  [{current}/{total}] ({pct}%) Document {doc_id}: {status}")

    # ------- Check models -------
    if args.check_models:
        config = _load_config(args.config)
        degradation = GracefulDegradation(config)
        status = degradation.check_all_models()
        print("\n=== AI Model Availability ===")
        for name, avail in status.items():
            icon = "[OK]" if avail else "[UNAVAILABLE]"
            print(f"  {icon} {name}")
        available = sum(1 for v in status.values() if v)
        mode = degradation.describe_mode(available)
        print(f"\nMode: {mode} ({available}/{len(status)} models)")
        return

    # ------- Backfill -------
    if args.backfill:
        config = _load_config(args.config)
        db = DatabaseManager(args.config)
        degradation = GracefulDegradation(config)
        queue = degradation.backfill_queue(db)
        if not queue:
            print("No documents need backfill analysis.")
            return
        print(f"\n=== Backfill Queue: {len(queue)} documents ===")
        for item in queue[:20]:
            print(f"  Document {item['document_id']}: "
                  f"{item['models_completed']}/{item['models_available']} models, "
                  f"missing: {', '.join(item['missing_models'])}")

        answer = input(f"\nAnalyze {len(queue)} documents now? [y/N]: ").strip().lower()
        if answer == "y":
            engine = PipelineEngine(args.config)
            engine.progress_callback = cli_progress
            doc_ids = [item["document_id"] for item in queue]
            results = engine.analyze_batch(doc_ids)
            successes = sum(1 for r in results if "error" not in r)
            print(f"\nBackfill complete: {successes}/{len(results)} succeeded")
        return

    # ------- Analyze document -------
    if args.document:
        engine = PipelineEngine(args.config)
        result = engine.analyze_document(args.document)
        if "error" in result:
            print(f"ERROR: {result['error']}")
            sys.exit(1)
        print(f"\n=== Analysis Complete: Document {args.document} ===")
        print(f"Agreement: {result.get('agreement_level', 'N/A')}")
        print(f"Models used: {result.get('models_used', 0)}")
        if result.get("disagreements"):
            print(f"Disagreements: {len(result['disagreements'])}")
        if result.get("unique_insights"):
            print(f"Unique insights: {len(result['unique_insights'])}")
        if result.get("summary"):
            print(f"\nSummary: {result['summary'][:300]}")
        return

    # ------- Analyze dataset -------
    if args.dataset is not None:
        engine = PipelineEngine(args.config)
        engine.progress_callback = cli_progress
        print(f"\n=== Analyzing Dataset {args.dataset} ===")
        results = engine.analyze_dataset(args.dataset)
        if not results:
            print("No documents to analyze in this dataset.")
            return
        successes = sum(1 for r in results if "error" not in r.get("result", {}))
        errors = len(results) - successes
        print(f"\nDataset {args.dataset} complete: {successes} succeeded, {errors} failed")


if __name__ == "__main__":
    main()
