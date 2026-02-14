"""
EpsteinAnalyzer - AI Pipeline Module
=====================================
Multi-model AI orchestration engine that sends documents to Codex CLI,
Gemini CLI, Claude Code, and Kimi CLI for analysis, then merges results via consensus.

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
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
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

You are an investigative analyst reviewing documents from the Jeffrey Epstein case.
Analyze the document above with the mindset of a federal investigator building a
prosecution case.  Produce your findings in the EXACT section format shown below.
Write each header line exactly as shown, then your content underneath.
If you have no data for a section, write "None identified." under it.

IMPORTANT RULES:
- Only extract REAL entities you can identify with reasonable confidence.
  Ignore OCR artifacts, garbled text, and nonsense strings.
- Distinguish between alleged perpetrators, witnesses, victims, and bystanders.
- Treat allegations as allegations. Do not present unproven claims as established fact.
- Ground every claim in specific text from the document.  Quote the source text.
- Dates and locations are critical -- extract every one you can find.

=== SUMMARY ===
Provide a 3-5 sentence investigative summary: What is this document? Who created it
and when?  What is its significance to the Epstein case?  What would a prosecutor
or investigator find most important here?

=== ENTITIES ===
List every identifiable person, organisation, location, financial reference, aircraft,
and case/docket reference.  Skip OCR garbage and unreadable fragments.
For each entity use this format:
- NAME | TYPE | ROLE IN DOCUMENT | IDENTIFYING DETAILS | SEARCH: https://www.google.com/search?q=ENCODED_NAME

TYPE must be one of: person, organization, location, aircraft, financial, legal_case,
contact_info, event
ROLE IN DOCUMENT examples: sender, recipient, subject of testimony, witness,
attorney, accused, victim, property owner, pilot, passenger, employer, etc.

=== TIMELINE ===
Extract every date, time, or time period mentioned or implied.  For each entry:
- DATE/PERIOD | EVENT DESCRIPTION | ENTITIES INVOLVED | SOURCE QUOTE
If no dates are found, infer approximate timeframes from context (e.g. letterhead
dates, filing stamps, "last Tuesday", fiscal years).

=== LOCATIONS ===
Extract every geographic reference -- addresses, cities, countries, properties,
islands, airports, flight routes.  For each:
- LOCATION | TYPE (address/city/property/airport/route) | CONTEXT | CONNECTED ENTITIES

=== FINANCIAL ===
Extract every financial reference -- dollar amounts, account numbers, wire transfers,
payments, invoices, salaries, gifts.  For each:
- AMOUNT/REFERENCE | TYPE (payment/invoice/salary/gift/wire/account) | FROM | TO | DATE | PURPOSE

=== REDACTIONS ===
For each redaction you can detect (blacked-out text, [REDACTED] markers, missing
names, suspicious gaps) provide your top 5 candidates:
REDACTION #N (context: "<surrounding text>"):
  1. CANDIDATE_NAME (XX%) - reasoning
  2. CANDIDATE_NAME (XX%) - reasoning
  ... up to 5

=== CONNECTIONS ===
Map relationships between entities.  Focus on relationships that matter for an
investigation: who communicated with whom, who paid whom, who traveled with whom,
who employed whom, who witnessed what.
Format: [Entity A] --relationship_type-- [Entity B] | evidence: "direct quote from doc"

=== EVIDENCE_SCORE ===
For each person identified, assign an investigative relevance score from 0-100
using this rubric:
  90-100: Direct evidence of criminal conduct (admissions, eyewitness testimony)
  70-89:  Strong circumstantial evidence (financial flows to/from Epstein,
          repeated travel to known locations, employment by Epstein)
  50-69:  Moderate relevance (named in communications, present at events,
          business dealings)
  30-49:  Peripheral involvement (mentioned in passing, clerical role,
          one-time contact)
  10-29:  Minimal relevance (government officials in official capacity,
          service providers with no suspicious activity)
  0-9:    No investigative relevance (document authors, filing clerks)
Format: NAME | SCORE | CATEGORY (perpetrator/facilitator/witness/victim/bystander) | JUSTIFICATION

=== CROSS_REFERENCES ===
Note connections to:
- Known Epstein associates (Ghislaine Maxwell, Jean-Luc Brunel, etc.)
- Known properties (Little St. James, Zorro Ranch, NYC townhouse, Paris apt, NM ranch)
- Known aircraft (N908JE, N909JE, "Lolita Express")
- Known legal proceedings (FL plea deal, SDNY case, Maxwell trial, civil suits)
- Known victims or Jane Does
- Any external events, dates, or patterns that correlate
Use bullet points with specific document evidence.

=== FLAGS ===
Flag anything an investigator should pay special attention to:
- Evidence of witness tampering, obstruction, or destruction of evidence
- Inconsistencies with other known facts
- Signs of coded language or euphemisms
- Unusual financial patterns
- Missing pages, altered dates, or document tampering
- Names that appear to be pseudonyms or aliases
- Any mention of minors or age-related references

=== CAREER_ROLES ===
For each person, classify both role and relationship to Epstein.
Format:
NAME | ROLE/TITLE | ORGANISATION | TIME PERIOD (if known) |
EMPLOYMENT_LINK_TYPE | CRIME_LINK_TYPE | EVIDENCE_QUOTE

EMPLOYMENT_LINK_TYPE must be one of:
- direct_employee_of_epstein
- employee_of_vendor_or_contractor
- independent_associate
- government_or_law_enforcement_official
- unknown

CRIME_LINK_TYPE must be one of:
- none_not_indicated
- alleged_facilitator
- alleged_procurement_of_minors
- logistics_or_transport_support
- financial_or_obstruction_support
- unknown
"""

    _REDACTION_INFERENCE_TEMPLATE = """\
=== REDACTION INFERENCE REQUEST ===

A redacted section was found in a legal/government document related to the
Jeffrey Epstein case.  Your task is to infer the most likely content that
was redacted based on surrounding context, estimated character count, and
font information.

DOCUMENT TYPE: {doc_type}
DOCUMENT ID: {document_id}

--- CONTEXT BEFORE REDACTION ---
{context_before}
--- END CONTEXT BEFORE ---

[████ REDACTED — approx. {estimated_chars} characters ████]

--- CONTEXT AFTER REDACTION ---
{context_after}
--- END CONTEXT AFTER ---

FONT INFORMATION:
  Font: {font_name}
  Size: {font_size}pt
  Estimated characters: ~{estimated_chars}
  Redaction width: {redaction_width}px

{partial_recovery_block}
{known_entities_block}

Provide your top 5 candidates for what was redacted.
For each candidate use this EXACT format (one per line):
CANDIDATE: <your inferred text> | CONFIDENCE: <0-100>% | REASONING: <one-line explanation>

IMPORTANT RULES:
- The inferred text MUST be approximately {estimated_chars} characters long.
- Consider: person names (associates, victims, officials), locations, dates,
  financial amounts, legal terms, case references, organisation names.
- Base your reasoning on contextual clues, sentence structure, and known facts.
- If context suggests a name, cross-reference with known Epstein associates.
- Higher confidence = stronger contextual evidence.  Do NOT guess above 80%
  unless the context makes the answer nearly certain.
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

    def build_redaction_inference_prompt(
        self,
        context_before: Optional[str],
        context_after: Optional[str],
        estimated_chars: int,
        document_id: int = 0,
        doc_type: str = "legal/government",
        font_name: str = "unknown",
        font_size: float = 12.0,
        redaction_width: float = 0.0,
        partial_recovery: Optional[str] = None,
        known_entities: Optional[list[dict]] = None,
    ) -> str:
        """Build a structured prompt for AI-powered redaction inference."""
        partial_block = ""
        if partial_recovery:
            partial_block = (
                "PARTIAL RECOVERY (from other forensic steps):\n"
                f"  \"{partial_recovery}\"\n"
                "  Use this as a strong hint but verify against context.\n"
            )

        entities_block = self._format_known_entities(known_entities)

        prompt = self._REDACTION_INFERENCE_TEMPLATE.format(
            doc_type=doc_type,
            document_id=document_id,
            context_before=context_before or "(no context available)",
            context_after=context_after or "(no context available)",
            estimated_chars=estimated_chars,
            font_name=font_name,
            font_size=font_size,
            redaction_width=redaction_width,
            partial_recovery_block=partial_block,
            known_entities_block=entities_block,
        )

        # Persist to queue for audit trail
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        prompt_path = self.queue_dir / f"redaction_inference_{ts}_{prompt_hash}.txt"
        prompt_path.write_text(prompt, encoding="utf-8")
        logger.debug("Redaction inference prompt saved to %s", prompt_path)

        return prompt

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
            name = ent.get("name", "?")
            # Filter out OCR garbage before injecting into prompts
            if ResponseParser._is_ocr_garbage(name):
                continue
            parts = [name]
            if ent.get("entity_type"):
                parts.append(f"({ent['entity_type']})")
            if ent.get("role"):
                parts.append(f"[{ent['role']}]")
            if ent.get("implication_score"):
                parts.append(f"score={ent['implication_score']}")
            compressed.append(" ".join(parts))
        if not compressed:
            return ""
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

    _TRANSIENT_ERROR_TOKENS = (
        "rate limit",
        "429",
        "quota",
        "too many requests",
        "temporarily unavailable",
        "timed out",
        "timeout",
        "connection reset",
        "network",
        "econnreset",
        "service unavailable",
    )

    def __init__(
        self,
        cli_command: str,
        timeout: int = 300,
        extra_args: Optional[list[str]] = None,
        max_retries: int = 0,
        retry_backoff_seconds: float = 2.0,
    ):
        self.cli_command = cli_command
        self.timeout = timeout
        self.extra_args = extra_args or []
        self.max_retries = max(0, int(max_retries))
        self.retry_backoff_seconds = max(0.0, float(retry_backoff_seconds))

    @abstractmethod
    def get_name(self) -> str:
        ...

    def check_available(self) -> bool:
        """Test whether the CLI tool responds at all."""
        try:
            cmd = shutil.which(self.cli_command) or self.cli_command
            # On Windows, .cmd/.bat wrappers must run through cmd.exe,
            # but we keep shell=False to avoid command-injection risk.
            run_cmd = [cmd, "--help"]
            if sys.platform == "win32" and cmd.lower().endswith((".cmd", ".bat")):
                run_cmd = ["cmd.exe", "/c"] + run_cmd
            result = subprocess.run(
                run_cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                shell=False,
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

            attempts = self.max_retries + 1
            for attempt in range(1, attempts + 1):
                cmd = self._build_command(tmp.name)
                # Resolve the executable path (handles Windows .cmd/.bat wrappers)
                resolved = shutil.which(cmd[0]) or cmd[0]
                cmd[0] = resolved
                # On Windows, .cmd/.bat wrappers must run through cmd.exe,
                # but we keep shell=False to avoid command-injection risk.
                if sys.platform == "win32" and resolved.lower().endswith((".cmd", ".bat")):
                    cmd = ["cmd.exe", "/c"] + cmd
                logger.info(
                    "Running %s (attempt %d/%d, timeout=%ds)",
                    self.get_name(),
                    attempt,
                    attempts,
                    timeout,
                )
                start = time.monotonic()

                # Use stdin file handle instead of shell piping to avoid injection
                with open(tmp.name, "r", encoding="utf-8") as stdin_fh:
                    child_env = os.environ.copy()
                    # Keep CLI child processes on UTF-8 across Windows shells/tools.
                    child_env.setdefault("PYTHONUTF8", "1")
                    child_env.setdefault("PYTHONIOENCODING", "utf-8")
                    child_env.setdefault("NO_COLOR", "1")
                    popen_kwargs = {
                        "stdin": stdin_fh,
                        "stdout": subprocess.PIPE,
                        "stderr": subprocess.PIPE,
                        "text": True,
                        "encoding": "utf-8",
                        "errors": "replace",
                        "shell": False,
                        "env": child_env,
                    }
                    # Isolate child process groups so timeout cleanup can kill full trees.
                    if sys.platform == "win32":
                        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
                    else:
                        popen_kwargs["start_new_session"] = True

                    proc = subprocess.Popen(cmd, **popen_kwargs)
                    try:
                        stdout, stderr = proc.communicate(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        self._kill_process_tree(proc)
                        logger.error(
                            "%s timed out after %ds (killed PID %s)",
                            self.get_name(),
                            timeout,
                            proc.pid,
                        )
                        if attempt < attempts:
                            self._sleep_before_retry(attempt)
                            continue
                        return None

                    result = subprocess.CompletedProcess(
                        args=cmd,
                        returncode=proc.returncode,
                        stdout=stdout,
                        stderr=stderr,
                    )

                elapsed = time.monotonic() - start
                logger.info("%s completed in %.1fs (exit=%d)", self.get_name(), elapsed, result.returncode)

                cleaned_stdout = self._clean_output(result.stdout or "")
                stderr = (result.stderr or "").strip()

                if result.returncode != 0:
                    lower_err = stderr.lower()
                    if self._is_transient_error(lower_err):
                        logger.warning("%s transient failure: %s", self.get_name(), stderr[:300])
                        if attempt < attempts:
                            self._sleep_before_retry(attempt)
                            continue
                    logger.warning("%s exited %d: %s", self.get_name(), result.returncode, stderr[:500])
                    # Still try to use stdout if there is content
                    if cleaned_stdout and len(cleaned_stdout) > 50:
                        return cleaned_stdout
                    if attempt < attempts and self._is_transient_error((cleaned_stdout + "\n" + lower_err).lower()):
                        self._sleep_before_retry(attempt)
                        continue
                    return None

                if cleaned_stdout:
                    return cleaned_stdout

                # Empty response despite success exit code: retry for flaky CLIs.
                if attempt < attempts:
                    logger.warning("%s returned empty output; retrying", self.get_name())
                    self._sleep_before_retry(attempt)
                    continue
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
                except OSError:
                    pass
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass

    def _is_transient_error(self, text: str) -> bool:
        if not text:
            return False
        return any(tok in text for tok in self._TRANSIENT_ERROR_TOKENS)

    def _sleep_before_retry(self, attempt: int) -> None:
        delay = self.retry_backoff_seconds * (2 ** (attempt - 1))
        if delay > 0:
            time.sleep(delay)

    @staticmethod
    def _clean_output(text: str) -> str:
        """Normalize CLI output by removing ANSI noise and outer code fences."""
        if not text:
            return ""
        # Strip ANSI escape sequences.
        text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text).strip()
        if text.startswith("```") and text.endswith("```"):
            lines = text.splitlines()
            if len(lines) >= 3:
                text = "\n".join(lines[1:-1]).strip()
        return text

    @staticmethod
    def _kill_process_tree(proc: subprocess.Popen) -> None:
        """Terminate a model process and all descendants."""
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=False,
                )
            else:
                os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    @abstractmethod
    def _build_command(self, prompt_file: str) -> list[str]:
        """Return the subprocess argument list."""
        ...


class CodexRunner(ModelRunner):
    """Runs prompts through the Codex CLI (codex exec for non-interactive)."""

    def __init__(
        self,
        cli_command: str = "codex",
        timeout: int = 300,
        extra_args: Optional[list[str]] = None,
        max_retries: int = 0,
        retry_backoff_seconds: float = 2.0,
    ):
        super().__init__(
            cli_command,
            timeout,
            extra_args=extra_args,
            max_retries=max_retries,
            retry_backoff_seconds=retry_backoff_seconds,
        )

    def get_name(self) -> str:
        return "codex"

    def _build_command(self, prompt_file: str) -> list[str]:
        # codex exec reads from stdin when prompt is "-"
        # -C sets working dir to project root (codex requires a git repo)
        # --ephemeral skips session persistence for faster execution
        return [self.cli_command, "exec", "--ephemeral", "-C", str(_PROJECT_ROOT), "-"] + self.extra_args


class GeminiRunner(ModelRunner):
    """Runs prompts through the Gemini CLI."""

    def __init__(
        self,
        cli_command: str = "gemini",
        timeout: int = 300,
        extra_args: Optional[list[str]] = None,
        max_retries: int = 1,
        retry_backoff_seconds: float = 2.0,
    ):
        super().__init__(
            cli_command,
            timeout,
            extra_args=extra_args,
            max_retries=max_retries,
            retry_backoff_seconds=retry_backoff_seconds,
        )

    def get_name(self) -> str:
        return "gemini"

    def _build_command(self, prompt_file: str) -> list[str]:
        # Default model produces complete output; flash truncates sections
        return [self.cli_command, "-p", "-"] + self.extra_args


class ClaudeRunner(ModelRunner):
    """Runs prompts through the Claude CLI (claude --print for non-interactive)."""

    def __init__(
        self,
        cli_command: str = "claude",
        timeout: int = 300,
        extra_args: Optional[list[str]] = None,
        max_retries: int = 0,
        retry_backoff_seconds: float = 2.0,
    ):
        super().__init__(
            cli_command,
            timeout,
            extra_args=extra_args,
            max_retries=max_retries,
            retry_backoff_seconds=retry_backoff_seconds,
        )

    def get_name(self) -> str:
        return "claude"

    def _build_command(self, prompt_file: str) -> list[str]:
        return [self.cli_command, "--print", "--model", "claude-sonnet-4-5-20250929"] + self.extra_args


class KimiRunner(ModelRunner):
    """Runs prompts through the Kimi CLI (kimi --quiet for non-interactive)."""

    def __init__(
        self,
        cli_command: str = "kimi",
        timeout: int = 300,
        extra_args: Optional[list[str]] = None,
        max_retries: int = 1,
        retry_backoff_seconds: float = 2.0,
    ):
        super().__init__(
            cli_command,
            timeout,
            extra_args=extra_args,
            max_retries=max_retries,
            retry_backoff_seconds=retry_backoff_seconds,
        )

    def get_name(self) -> str:
        return "kimi"

    def _build_command(self, prompt_file: str) -> list[str]:
        # --quiet = --print --output-format text --final-message-only
        # Uses default model from ~/.kimi/config.toml (kimi-code/kimi-for-coding)
        return [self.cli_command, "--quiet"] + self.extra_args


# ===================================================================
# 3. ResponseParser
# ===================================================================

class ResponseParser:
    """Parses a structured AI response into a normalised dictionary."""

    # Canonical section keys mapped to the header patterns we look for
    _SECTIONS = [
        ("summary",              r"===\s*SUMMARY\s*==="),
        ("entities",             r"===\s*ENTITIES\s*==="),
        ("timeline",             r"===\s*TIMELINE\s*==="),
        ("locations",            r"===\s*LOCATIONS?\s*==="),
        ("financial",            r"===\s*FINANCIAL\s*==="),
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
        parsed["timeline"] = self._parse_pipe_delimited(sections_raw.get("timeline"), ["date", "event", "entities_involved", "source_quote"])
        parsed["locations"] = self._parse_pipe_delimited(sections_raw.get("locations"), ["location", "type", "context", "connected_entities"])
        parsed["financial"] = self._parse_pipe_delimited(sections_raw.get("financial"), ["amount", "type", "from_entity", "to_entity", "date", "purpose"])
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
    def _is_ocr_garbage(name: str) -> bool:
        """Detect OCR artifacts and garbage strings that aren't real entities."""
        if not name or len(name.strip()) < 2:
            return True
        name = name.strip()
        # Too short to be meaningful
        if len(name) <= 2:
            return True
        # Contains embedded newlines (OCR artifact)
        if "\n" in name or "\r" in name:
            return True
        # Looks like a document ID being treated as an entity
        if re.match(r"^EFTA\d+$", name):
            return True
        # Mostly non-alphabetic characters (allow $ for financial)
        alpha_ratio = sum(1 for c in name if c.isalpha()) / max(len(name), 1)
        if alpha_ratio < 0.5 and not name.startswith("$"):
            return True
        # Excessive repeated characters (e.g. MINININININNNVNVNNVhVNN)
        if re.search(r"(.)\1{4,}", name):
            return True
        # Repeated 2-char patterns (e.g. NINININI)
        if re.search(r"(.{2})\1{3,}", name):
            return True
        # Contains control characters or unusual symbols (not common in names)
        if re.search(r"[^\w\s.,'\-/&()#@$%:]", name) and not name.startswith("$"):
            return True
        # Contains underscores mid-word (OCR artifact like 9e_a_St)
        if "_" in name and not any(w in name.lower() for w in ("u.s.", "u.k.", "d.c.")):
            return True
        # Nonsense consonant clusters unlikely in any real language (5+ consonants)
        if re.search(r"[^aeiouAEIOU\s]{5,}", name):
            return True
        # Long strings with no vowels suggest OCR garbage
        words = name.split()
        for word in words:
            clean = re.sub(r"[^a-zA-Z]", "", word)
            if len(clean) >= 4 and not any(c in clean.lower() for c in "aeiouy"):
                return True
        # Names that are very long single "words" with no spaces (likely OCR run-together)
        if len(words) == 1 and len(name) > 12:
            return True
        # Multiple words where most are not recognizable (high entropy garbage)
        if len(words) >= 2:
            odd_words = sum(1 for w in words if len(w) >= 4 and (
                sum(1 for c in w.lower() if c in "aeiouy") / max(len(w), 1) < 0.15
                or re.search(r"(.)\1{2,}", w)
            ))
            if odd_words >= len(words) * 0.5 and odd_words >= 2:
                return True
        return False

    @staticmethod
    def _parse_entities(text: Optional[str]) -> Optional[list[dict]]:
        if not text or text.lower().startswith("none identified"):
            return None
        entities: list[dict] = []
        # Expected format: - NAME | TYPE | ROLE | DETAILS | SEARCH: url
        for line in text.splitlines():
            line = line.strip().lstrip("-").lstrip("*").strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("|")]
            ent: dict[str, Any] = {"raw": line}
            if len(parts) >= 1:
                ent["name"] = parts[0]
            if len(parts) >= 2:
                ent["type"] = parts[1].lower().strip()
            if len(parts) >= 3:
                ent["role"] = parts[2]
            if len(parts) >= 4:
                ent["details"] = parts[3]
            # Search URL may be in parts[4] or parts[3]
            for p in parts[3:]:
                url_match = re.search(r"https?://\S+", p)
                if url_match:
                    ent["search_url"] = url_match.group(0)
                    break
            # Filter OCR garbage
            if ResponseParser._is_ocr_garbage(ent.get("name", "")):
                continue
            entities.append(ent)
        return entities or None

    @staticmethod
    def _parse_pipe_delimited(text: Optional[str], field_names: list[str]) -> Optional[list[dict]]:
        """Generic parser for pipe-delimited sections (timeline, locations, financial)."""
        if not text or text.lower().startswith("none identified"):
            return None
        items: list[dict] = []
        for line in text.splitlines():
            line = line.strip().lstrip("-").lstrip("*").strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 2:
                continue
            entry: dict[str, str] = {}
            for idx, field in enumerate(field_names):
                if idx < len(parts):
                    entry[field] = parts[idx]
            items.append(entry)
        return items or None

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
                category = ""
                justification = ""
                if len(parts) >= 4:
                    category = parts[2]
                    justification = parts[3]
                elif len(parts) >= 3:
                    justification = parts[2]
                scores.append({
                    "name": parts[0],
                    "score": int(score_str.group(0)) if score_str else 0,
                    "category": category,
                    "justification": justification,
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
            if len(parts) >= 5:
                entry["employment_link"] = parts[4]
            if len(parts) >= 6:
                entry["crime_link"] = parts[5]
            if len(parts) >= 7:
                entry["evidence_quote"] = parts[6]
            roles.append(entry)
        return roles or None


# ===================================================================
# 4. ConsensusEngine
# ===================================================================

class ConsensusEngine:
    """Merges analyses from multiple models into a consensus result."""

    FULL_AGREEMENT = "full"
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
        for field in ("entities", "connections", "cross_references", "flags", "career_roles",
                       "timeline", "locations", "financial"):
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
                return f"{item['name']}|{item.get('type', item.get('entity_type', ''))}".lower().strip()
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

    _RUNNER_CLASSES: list[type[ModelRunner]] = [CodexRunner, GeminiRunner, ClaudeRunner, KimiRunner]

    def __init__(self, config: Optional[dict] = None):
        self.config = config or _load_config()
        self._runners: list[ModelRunner] = []
        self._cache_lock = threading.Lock()
        # Cache expensive CLI availability checks so batch runs stay fast.
        self._availability_cache: Optional[dict[str, bool]] = None
        self._availability_checked_at: float = 0.0
        self._availability_cache_seconds = float(
            self.config.get("ai_pipeline", {}).get("models_availability_cache_seconds", 120)
        )
        self._build_runners()

    def _build_runners(self):
        ai_cfg = self.config.get("ai_pipeline", {}).get("models", {})
        for cls in self._RUNNER_CLASSES:
            key = cls.__name__.replace("Runner", "").lower()
            model_cfg = ai_cfg.get(key, {})
            if model_cfg.get("enabled", True):
                timeout = model_cfg.get("timeout_seconds", 300)
                cli_command = model_cfg.get("cli_command", key)
                extra_args = model_cfg.get("extra_args", [])
                max_retries = model_cfg.get("max_retries", 0)
                retry_backoff_seconds = model_cfg.get("retry_backoff_seconds", 2.0)
                self._runners.append(
                    cls(
                        cli_command=cli_command,
                        timeout=timeout,
                        extra_args=extra_args,
                        max_retries=max_retries,
                        retry_backoff_seconds=retry_backoff_seconds,
                    )
                )

    def _get_model_status(self, force_refresh: bool = False) -> dict[str, bool]:
        with self._cache_lock:
            now = time.monotonic()
            if (
                not force_refresh
                and self._availability_cache is not None
                and (now - self._availability_checked_at) < self._availability_cache_seconds
            ):
                return dict(self._availability_cache)

            status: dict[str, bool] = {}
            for runner in self._runners:
                avail = runner.check_available()
                status[runner.get_name()] = avail
                logger.info("Model %s: %s", runner.get_name(), "available" if avail else "unavailable")
            self._availability_cache = dict(status)
            self._availability_checked_at = now
            return status

    def check_all_models(self, force_refresh: bool = False) -> dict[str, bool]:
        """Return {model_name: available} for every configured runner."""
        return self._get_model_status(force_refresh=force_refresh)

    def get_available_runners(self, force_refresh: bool = False) -> list[ModelRunner]:
        """Return only the runners whose CLI is currently reachable."""
        status = self._get_model_status(force_refresh=force_refresh)
        available = []
        for runner in self._runners:
            if status.get(runner.get_name(), False):
                available.append(runner)
        return available

    def describe_mode(self, available_count: int) -> str:
        if available_count >= 4:
            return "quad_consensus"
        if available_count == 3:
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
        self.parallel_documents = max(1, int(batch_cfg.get("parallel_documents", 1)))

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
        if document_text.startswith("(No extracted text"):
            logger.warning("Document %d has no extracted text — skipping AI analysis", document_id)
            self._update_doc_status(document_id, "ocr_complete")
            return {"error": "No text content available for analysis", "skipped": True}
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

        def _run_single_model(runner):
            """Run a single model and return (name, response, elapsed)."""
            name = runner.get_name()
            t0 = time.time()
            response = runner.run(prompt)
            elapsed = time.time() - t0
            return name, response, elapsed

        # --- Adaptive tiered confidence approach ---
        # Stage 1: run Gemini+Kimi fast pair (if both available).
        # Stage 2: if pair confidence/agreement is weak, escalate to slower models.
        # Stage 3: if pair is unavailable, fall back to single-model fast-pass.
        consensus_cfg = self.config.get("ai_pipeline", {}).get("consensus", {})
        fast_pass_threshold = float(consensus_cfg.get("fast_pass_threshold", 0.88))
        fast_pair_models = [
            str(m).strip().lower()
            for m in consensus_cfg.get("fast_pair_models", ["gemini", "kimi"])
            if str(m).strip()
        ]
        pair_quality_threshold = float(consensus_cfg.get("pair_quality_threshold", 0.78))
        pair_disagreement_max = int(consensus_cfg.get("pair_disagreement_max", 3))

        # Sort runners by expected speed.
        speed_order = {"gemini": 0, "kimi": 1, "claude": 2, "codex": 3}
        runners_sorted = sorted(runners, key=lambda r: speed_order.get(r.get_name(), 99))
        runner_by_name = {r.get_name(): r for r in runners_sorted}
        fast_pair_runners: list[ModelRunner] = []
        for model_name in fast_pair_models:
            r = runner_by_name.get(model_name)
            if r and r not in fast_pair_runners:
                fast_pair_runners.append(r)
            if len(fast_pair_runners) >= 2:
                break

        parsed_by_model: dict[str, dict] = {}

        def _consume_result(name: str, response: Optional[str], elapsed: float) -> None:
            raw_responses[name] = response
            if not response:
                logger.warning("No response from %s for document %d", name, document_id)
                return
            parsed = self.parser.parse_response(response, name)
            self._save_analysis(document_id, name, parsed, response, elapsed)
            parsed_analyses.append(parsed)
            model_names.append(name)
            parsed_by_model[name] = parsed

        def _run_runner_group(group: list[ModelRunner]) -> None:
            if not group:
                return
            if len(group) == 1:
                name, response, elapsed = _run_single_model(group[0])
                _consume_result(name, response, elapsed)
                return
            with ThreadPoolExecutor(max_workers=len(group)) as executor:
                futures = {executor.submit(_run_single_model, r): r for r in group}
                for future in as_completed(futures):
                    name, response, elapsed = future.result()
                    _consume_result(name, response, elapsed)

        escalation_runners = [r for r in runners_sorted if r not in fast_pair_runners]
        should_escalate = True

        if len(fast_pair_runners) >= 2:
            pair_names = [r.get_name() for r in fast_pair_runners]
            logger.info("Running fast pair first for doc %d: %s", document_id, ", ".join(pair_names))
            _run_runner_group(fast_pair_runners)

            pair_available = [n for n in pair_names if n in parsed_by_model]
            if len(pair_available) >= 2:
                pair_analyses = [parsed_by_model[n] for n in pair_available]
                pair_consensus = self.consensus_engine.merge_analyses(pair_analyses, pair_available)
                pair_disagreements = len(pair_consensus.get("disagreements", []))
                pair_agreement = pair_consensus.get("agreement_level", ConsensusEngine.SPLIT)
                pair_qualities = [self._evaluate_response_quality(parsed_by_model[n]) for n in pair_available]
                pair_min_quality = min(pair_qualities)
                pair_avg_quality = sum(pair_qualities) / len(pair_qualities)

                should_escalate = not (
                    pair_agreement in (ConsensusEngine.FULL_AGREEMENT, ConsensusEngine.MAJORITY)
                    and pair_min_quality >= pair_quality_threshold
                    and pair_disagreements <= pair_disagreement_max
                )
                logger.info(
                    "Fast pair doc %d: agreement=%s, min_quality=%.0f%%, avg_quality=%.0f%%, disagreements=%d, escalate=%s",
                    document_id,
                    pair_agreement,
                    pair_min_quality * 100,
                    pair_avg_quality * 100,
                    pair_disagreements,
                    should_escalate,
                )
            elif len(pair_available) == 1:
                # If only one fast model answered, reuse single-model fast-pass logic.
                only = pair_available[0]
                quality = self._evaluate_response_quality(parsed_by_model[only])
                should_escalate = quality < fast_pass_threshold
                logger.info(
                    "%s solo quality=%.0f%% for doc %d (threshold=%d%%) -> escalate=%s",
                    only,
                    quality * 100,
                    document_id,
                    int(fast_pass_threshold * 100),
                    should_escalate,
                )
            else:
                should_escalate = True
        else:
            # Fallback: single fastest model first.
            primary_runner = runners_sorted[0]
            _run_runner_group([primary_runner])
            p_name = primary_runner.get_name()
            if p_name in parsed_by_model:
                quality = self._evaluate_response_quality(parsed_by_model[p_name])
                should_escalate = quality < fast_pass_threshold
                logger.info(
                    "%s quality=%.0f%% for doc %d (threshold=%d%%) -> escalate=%s",
                    p_name,
                    quality * 100,
                    document_id,
                    int(fast_pass_threshold * 100),
                    should_escalate,
                )
            else:
                should_escalate = True
            escalation_runners = [r for r in runners_sorted if r.get_name() != p_name]

        if should_escalate and escalation_runners:
            logger.info(
                "Escalating doc %d to %d additional model(s): %s",
                document_id,
                len(escalation_runners),
                ", ".join(r.get_name() for r in escalation_runners),
            )
            _run_runner_group(escalation_runners)
        elif escalation_runners:
            logger.info(
                "Fast-tier accepted for doc %d — skipping %d slower model(s)",
                document_id,
                len(escalation_runners),
            )

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
        if total == 0:
            return []

        # If chain-aware, reorder so email chains are grouped
        if self.chain_aware:
            document_ids = self._order_by_chains(document_ids)

        workers = max(1, min(self.parallel_documents, total))
        if workers == 1:
            results: list[dict] = []
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

                # Configurable inter-document cooldown for CLI/API stability.
                if idx < total:
                    time.sleep(max(0.0, float(self.rate_limit_seconds)))
            return results

        logger.info("Parallel document analysis enabled: workers=%d total_docs=%d", workers, total)
        progress_lock = threading.Lock()
        completed = 0
        results_by_index: dict[int, dict] = {}

        def _run_one(index: int, doc_id: int):
            nonlocal completed
            if self.progress_callback:
                with progress_lock:
                    start_pos = max(1, completed + 1)
                self.progress_callback(start_pos, total, doc_id, "starting")

            try:
                result = self.analyze_document(doc_id)
                out = {"document_id": doc_id, "result": result}
            except Exception as exc:
                logger.error("Error analyzing document %d: %s", doc_id, exc)
                logger.debug(traceback.format_exc())
                out = {"document_id": doc_id, "error": str(exc)}

            with progress_lock:
                completed += 1
                done_pos = completed

            if self.progress_callback:
                status = "error" if "error" in out else "complete"
                self.progress_callback(done_pos, total, doc_id, status)

            # Keep a short post-doc cooldown option for rate-limited providers.
            if done_pos < total and float(self.rate_limit_seconds) > 0:
                time.sleep(max(0.0, float(self.rate_limit_seconds)))

            return index, out

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_run_one, idx, doc_id) for idx, doc_id in enumerate(document_ids)]
            for future in as_completed(futures):
                index, out = future.result()
                results_by_index[index] = out

        return [results_by_index[idx] for idx in range(total)]

    def analyze_dataset(self, dataset_number: int) -> list[dict]:
        """Analyze all priority-queued documents in a dataset."""
        # Recover stale in-flight jobs from crashed or hung runs.
        self._recover_stuck_documents(dataset_number)

        conn = self.db.get_connection()
        try:
            rows = conn.execute("""
                SELECT d.id
                FROM documents d
                JOIN datasets ds ON d.dataset_id = ds.id
                WHERE ds.dataset_number = ?
                  AND d.analysis_completed = 0
                  AND d.status != 'analyzing'
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

    def _recover_stuck_documents(self, dataset_number: Optional[int] = None) -> int:
        """Reset stale analyzing docs so they can be retried."""
        stale_minutes = (
            self.config.get("ai_pipeline", {})
            .get("batch", {})
            .get("stuck_reset_minutes", 15)
        )
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=stale_minutes)

        conn = self.db.get_connection()
        try:
            if dataset_number is None:
                rows = conn.execute("""
                    SELECT id, updated_at
                    FROM documents
                    WHERE status = 'analyzing' AND analysis_completed = 0
                """).fetchall()
            else:
                rows = conn.execute("""
                    SELECT d.id, d.updated_at
                    FROM documents d
                    JOIN datasets ds ON d.dataset_id = ds.id
                    WHERE ds.dataset_number = ?
                      AND d.status = 'analyzing'
                      AND d.analysis_completed = 0
                """, (dataset_number,)).fetchall()

            stale_ids: list[int] = []
            for row in rows:
                try:
                    updated = datetime.fromisoformat(row["updated_at"])
                except Exception:
                    stale_ids.append(row["id"])
                    continue
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)
                if updated < cutoff:
                    stale_ids.append(row["id"])

            if stale_ids:
                placeholders = ",".join("?" for _ in stale_ids)
                params = [datetime.now(timezone.utc).isoformat(), *stale_ids]
                conn.execute(
                    f"UPDATE documents "
                    f"SET status = 'ocr_complete', updated_at = ? "
                    f"WHERE id IN ({placeholders})",
                    params,
                )
                conn.commit()
                logger.warning(
                    "Recovered %d stale analyzing document(s): %s",
                    len(stale_ids),
                    stale_ids,
                )
            return len(stale_ids)
        finally:
            conn.close()

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

    @staticmethod
    def _evaluate_response_quality(parsed: dict) -> float:
        """Score how complete/confident a single model's parsed response is (0.0-1.0).

        Checks: did the model produce a summary, entities, connections, evidence
        scores, and other sections?  A high score means the response is rich
        enough to stand on its own without needing consensus from other models.
        """
        score = 0.0
        weights = {
            "summary": 0.10,
            "entities": 0.15,
            "timeline": 0.10,
            "locations": 0.05,
            "financial": 0.05,
            "connections": 0.15,
            "evidence_scores": 0.15,
            "redaction_inferences": 0.08,
            "cross_references": 0.05,
            "flags": 0.05,
            "career_roles": 0.07,
        }
        for key, weight in weights.items():
            val = parsed.get(key)
            if val is None:
                continue
            if isinstance(val, str) and val:
                score += weight  # summary
            elif isinstance(val, list) and len(val) > 0:
                # More items = higher sub-score (capped at 1.0 of the weight)
                # e.g. 5+ entities = full credit, 1 entity = partial
                fullness = min(len(val) / 3.0, 1.0)
                score += weight * fullness
        return min(score, 1.0)

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
            # Prevent duplicate analyses for same document+model
            existing = conn.execute(
                "SELECT id FROM ai_analyses WHERE document_id = ? AND model_name = ?",
                (document_id, model_name),
            ).fetchone()
            if existing:
                logger.debug("Skipping duplicate %s analysis for document %d", model_name, document_id)
                return

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
                INSERT OR REPLACE INTO ai_consensus (
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

                # Atomic upsert: try INSERT OR IGNORE then UPDATE, avoiding race conditions
                role = None
                roles_list = consensus.get("career_roles") or []
                for cr in roles_list:
                    if isinstance(cr, dict) and self._names_match(cr.get("name", ""), name):
                        role = cr.get("role")
                        break

                conn.execute("""
                    INSERT OR IGNORE INTO entities (name, entity_type, canonical_name, google_url,
                                          role, document_count, first_seen_document_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                """, (name, etype, canonical, google_url, role, document_id, now, now))

                inserted_new = conn.execute("SELECT changes()").fetchone()[0] > 0

                existing = conn.execute(
                    "SELECT id FROM entities WHERE canonical_name = ? AND entity_type = ?",
                    (canonical, etype),
                ).fetchone()
                if existing is None:
                    # Fallback: look up by name if canonical mismatch
                    existing = conn.execute(
                        "SELECT id FROM entities WHERE name = ?", (name,)
                    ).fetchone()
                if existing is None:
                    continue
                eid = existing["id"]

                entity_id_map[canonical.lower()] = eid

                # Link entity to document (skip increment if already linked)
                already_linked = conn.execute(
                    "SELECT 1 FROM entity_document_links WHERE entity_id = ? AND document_id = ?",
                    (eid, document_id),
                ).fetchone()
                if not already_linked:
                    conn.execute("""
                        INSERT OR IGNORE INTO entity_document_links (entity_id, document_id, mention_type, created_at)
                        VALUES (?, ?, 'mentioned', ?)
                    """, (eid, document_id, now))
                    # Only bump count for existing entities if this is a NEW link
                    if not inserted_new:
                        conn.execute(
                            "UPDATE entities SET document_count = document_count + 1, updated_at = ? WHERE id = ?",
                            (now, eid),
                        )

            # --- Evidence scores ---
            scores_list = consensus.get("evidence_scores") or []
            for sc in scores_list:
                if not isinstance(sc, dict):
                    continue
                name_key = re.sub(r"\s+", " ", sc.get("name", "")).strip().title().lower()
                eid = entity_id_map.get(name_key)
                if eid:
                    # Only increment evidence_count if this doc hasn't already been scored
                    existing_score = conn.execute(
                        "SELECT damning_score FROM entity_document_links WHERE entity_id = ? AND document_id = ?",
                        (eid, document_id),
                    ).fetchone()
                    if existing_score and existing_score["damning_score"]:
                        # Already scored — just update the max implication score
                        conn.execute(
                            "UPDATE entities SET implication_score = MAX(implication_score, ?), "
                            "updated_at = ? WHERE id = ?",
                            (sc.get("score", 0), now, eid),
                        )
                    else:
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
                        "SELECT id, evidence_count, evidence_document_ids FROM relationships "
                        "WHERE source_entity_id = ? AND target_entity_id = ? AND relationship_type = ?",
                        (src_id, tgt_id, rel_type),
                    ).fetchone()

                    if existing_rel:
                        # Only increment if this document hasn't already been counted
                        existing_doc_ids = json.loads(existing_rel["evidence_document_ids"] or "[]")
                        if document_id not in existing_doc_ids:
                            existing_doc_ids.append(document_id)
                            conn.execute("""
                                UPDATE relationships
                                SET weight = weight + 1, evidence_count = evidence_count + 1,
                                    evidence_document_ids = ?, updated_at = ?
                                WHERE id = ?
                            """, (json.dumps(existing_doc_ids), now, existing_rel["id"]))
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
            # Pre-fetch ordered redaction IDs for stable index-based lookup
            redaction_rows = conn.execute(
                "SELECT id FROM redactions WHERE document_id = ? ORDER BY page_number, id",
                (document_id,)
            ).fetchall()
            redaction_ids = [r["id"] for r in redaction_rows]
            for ri in redact_list:
                if not isinstance(ri, dict):
                    continue
                candidates = ri.get("candidates", [])
                if candidates:
                    ai_candidates_json = json.dumps(candidates, default=str)
                    # AI indices are 1-based (REDACTION #1, #2, ...)
                    idx = ri.get("index", 1) - 1
                    if 0 <= idx < len(redaction_ids):
                        conn.execute("""
                            UPDATE redactions
                            SET ai_candidates = ?,
                                status = CASE WHEN status = 'unresolved' THEN 'inferred' ELSE status END,
                                updated_at = ?
                            WHERE id = ?
                        """, (ai_candidates_json, now, redaction_ids[idx]))

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
        if not na or not nb:
            return False
        if na == nb:
            return True
        # Substring matching: require word-boundary alignment to avoid
        # false positives like "Alan" matching "Evaluation".
        # For short names (4-5 chars), require exact word boundary on both sides.
        # For longer names (6+), simple substring is safe enough.
        for short, long in [(na, nb), (nb, na)]:
            if len(short) < 4:
                continue
            if short in long:
                if len(short) <= 5:
                    # Require word-boundary match (space or start/end of string)
                    if re.search(r"(?:^|\s)" + re.escape(short) + r"(?:\s|$)", long):
                        return True
                else:
                    return True
        return False


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
        status = degradation.check_all_models(force_refresh=True)
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
