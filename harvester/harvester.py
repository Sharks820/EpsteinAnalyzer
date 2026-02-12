"""
EpsteinAnalyzer - Document Harvester Engine
============================================
Acquisition engine for publicly released Epstein case documents.
Sources: DOJ releases, GitHub mirrors, Internet Archive, Zenodo,
Reddit, MuckRock FOIA, CourtListener, torrents, state courts.

Highest priority feature: removed-file detection. Diffs mirror inventories
against current DOJ listings and flags anything that existed on mirrors
but is now absent from DOJ as REMOVED -- CRITICAL PRIORITY.
"""

import argparse
import hashlib
import json
import logging
import os
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import requests
import yaml
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from database.db import DatabaseManager  # noqa: E402

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("harvester")
logger.setLevel(logging.DEBUG)

_console = logging.StreamHandler()
_console.setLevel(logging.INFO)
_console.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
)
logger.addHandler(_console)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)
CHUNK_SIZE = 1024 * 256  # 256 KiB download chunks
MAX_RETRIES = 5
BACKOFF_BASE = 2.0
BACKOFF_MAX = 120.0
REQUEST_TIMEOUT = 60


def _load_config(config_path: Optional[str] = None) -> dict:
    """Load settings.yaml and return the parsed dict."""
    if config_path is None:
        config_path = Path(__file__).resolve().parent.parent / "config" / "settings.yaml"
    with open(config_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _sha256_file(path: Path) -> str:
    """Return hex SHA-256 digest of a file on disk."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ===================================================================
# Retry / HTTP helpers
# ===================================================================

def _build_session(extra_headers: Optional[dict] = None) -> requests.Session:
    """Return a requests.Session with sensible defaults."""
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    })
    if extra_headers:
        s.headers.update(extra_headers)
    return s


def _request_with_retries(
    session: requests.Session,
    url: str,
    *,
    method: str = "GET",
    max_retries: int = MAX_RETRIES,
    timeout: int = REQUEST_TIMEOUT,
    stream: bool = False,
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
) -> requests.Response:
    """Execute an HTTP request with exponential back-off on transient errors."""
    last_exc: Optional[Exception] = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = session.request(
                method,
                url,
                timeout=timeout,
                stream=stream,
                params=params,
                headers=headers,
            )
            if resp.status_code == 429:
                wait = min(BACKOFF_BASE ** attempt, BACKOFF_MAX)
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    wait = max(wait, int(retry_after))
                jittered = wait * (0.5 + random.random())
                logger.warning("429 Too Many Requests for %s -- waiting %.1fs", url, jittered)
                time.sleep(jittered)
                continue
            if resp.status_code in (502, 503, 504):
                wait = min(BACKOFF_BASE ** attempt, BACKOFF_MAX)
                jittered = wait * (0.5 + random.random())
                logger.warning("%d from %s -- retry %d/%d in %.1fs",
                               resp.status_code, url, attempt, max_retries, jittered)
                time.sleep(jittered)
                continue
            resp.raise_for_status()
            return resp
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_exc = exc
            wait = min(BACKOFF_BASE ** attempt, BACKOFF_MAX)
            jittered = wait * (0.5 + random.random())
            logger.warning("Network error for %s: %s -- retry %d/%d in %.1fs",
                           url, exc, attempt, max_retries, jittered)
            time.sleep(jittered)
    raise requests.ConnectionError(
        f"Failed after {max_retries} retries for {url}"
    ) from last_exc


def _download_file(
    session: requests.Session,
    url: str,
    dest: Path,
    *,
    progress_cb: Optional[Callable] = None,
    expected_size: Optional[int] = None,
) -> Path:
    """
    Download *url* to *dest*, supporting auto-resume of partial downloads.
    Returns the final Path on success.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(dest.suffix + ".partial")

    resume_pos = 0
    if partial.exists():
        resume_pos = partial.stat().st_size

    hdrs: dict = {}
    if resume_pos > 0:
        hdrs["Range"] = f"bytes={resume_pos}-"
        logger.info("Resuming download at byte %d for %s", resume_pos, url)

    resp = _request_with_retries(session, url, stream=True, headers=hdrs)

    # Server may not support Range -- if so, start from scratch
    if resume_pos > 0 and resp.status_code != 206:
        resume_pos = 0
        partial.unlink(missing_ok=True)

    total_size = expected_size
    cl = resp.headers.get("Content-Length")
    if cl and cl.isdigit():
        total_size = int(cl) + resume_pos

    mode = "ab" if resume_pos > 0 else "wb"
    downloaded = resume_pos
    with open(partial, mode) as fh:
        for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
            if chunk:
                fh.write(chunk)
                downloaded += len(chunk)
                if progress_cb and total_size:
                    progress_cb(downloaded, total_size)

    partial.rename(dest)
    return dest


# ===================================================================
# Abstract base for every source module
# ===================================================================

class SourceModule(ABC):
    """Base class for all harvester source modules."""

    name: str = "base"

    def __init__(self, config: dict, db: DatabaseManager, data_dir: Path,
                 progress_cb: Optional[Callable] = None):
        self.config = config
        self.db = db
        self.data_dir = data_dir
        self.progress_cb = progress_cb
        self.session = _build_session()
        self.logger = logging.getLogger(f"harvester.{self.name}")

    # ------------------------------------------------------------------
    # Public API every source must implement
    # ------------------------------------------------------------------

    @abstractmethod
    def inventory(self) -> List[Dict[str, Any]]:
        """
        Return a list of dicts describing every file this source knows about.
        Each dict must contain at minimum:
            url        - download URL (str)
            filename   - suggested filename (str)
            source     - source name matching self.name
        Optional keys: dataset_number, size_bytes, file_type
        """

    @abstractmethod
    def download_all(self, dest_dir: Path) -> List[Path]:
        """Download everything this source offers.  Returns list of local paths."""

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _report_progress(self, msg: str, pct: Optional[float] = None,
                         detail: Optional[str] = None):
        self.logger.info(msg)
        if self.progress_cb:
            self.progress_cb({
                "source": self.name,
                "message": msg,
                "percent": pct,
                "detail": detail,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def _register_file(self, local_path: Path, source_url: str,
                       dataset_number: Optional[int] = None,
                       file_type: str = "pdf") -> Optional[int]:
        """Hash a downloaded file, insert/skip in the DB, return document ID."""
        file_hash = _sha256_file(local_path)
        conn = self.db.get_connection()
        try:
            existing = conn.execute(
                "SELECT id FROM documents WHERE file_hash = ?", (file_hash,)
            ).fetchone()
            if existing:
                self.logger.debug("Duplicate skipped: %s (hash %s)", local_path.name, file_hash[:12])
                return existing["id"]

            dataset_id = None
            if dataset_number is not None:
                row = conn.execute(
                    "SELECT id FROM datasets WHERE dataset_number = ?", (dataset_number,)
                ).fetchone()
                if row:
                    dataset_id = row["id"]

            cur = conn.execute(
                """INSERT INTO documents
                   (dataset_id, file_hash, original_filename, file_path, file_type,
                    source, source_url, size_bytes, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'downloaded')""",
                (
                    dataset_id,
                    file_hash,
                    local_path.name,
                    str(local_path),
                    file_type,
                    self.name,
                    source_url,
                    local_path.stat().st_size,
                ),
            )
            doc_id = cur.lastrowid

            # File integrity record (single atomic commit for both inserts)
            conn.execute(
                """INSERT OR REPLACE INTO file_integrity
                   (file_path, sha256_hash, size_bytes, last_verified_at)
                   VALUES (?, ?, ?, ?)""",
                (str(local_path), file_hash, local_path.stat().st_size,
                 datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            return doc_id
        finally:
            conn.close()

    def _already_have(self, url: str) -> bool:
        """Return True if a document with this source_url exists in the DB."""
        conn = self.db.get_connection()
        try:
            row = conn.execute(
                "SELECT id FROM documents WHERE source_url = ?", (url,)
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def _safe_filename(self, name: str) -> str:
        """Sanitise a filename to be filesystem-safe."""
        name = re.sub(r'[<>:"/\\|?*]', "_", name)
        # Block path traversal
        name = name.replace("..", "_")
        name = name.strip(". ")
        # Block Windows reserved device names
        _RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
            f"{d}{n}" for d in ("COM", "LPT") for n in range(1, 10)
        }
        stem = Path(name).stem.upper()
        if stem in _RESERVED:
            name = f"_{name}"
        if len(name) > 200:
            base, ext = os.path.splitext(name)
            name = base[:200] + ext
        return name or "_unnamed"


# ===================================================================
# 1. DOJ Scraper
# ===================================================================

class DOJScraper(SourceModule):
    """
    Scrapes https://www.justice.gov/epstein and its dataset pages.
    Handles Akamai WAF protection through proper headers, cookies,
    and exponential back-off with jitter.
    """

    name = "doj"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cfg = self.config.get("harvester", {}).get("doj", {})
        self.base_url = cfg.get("base_url", "https://www.justice.gov/epstein")
        self.datasets_url = cfg.get("datasets_url", "https://www.justice.gov/epstein/doj-disclosures")
        self.total_datasets = cfg.get("total_datasets", 12)

        # Akamai-friendly headers
        self.session.headers.update({
            "Referer": "https://www.justice.gov/",
            "DNT": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        })

    # ------------------------------------------------------------------
    # Build dataset page URL
    # ------------------------------------------------------------------

    def _dataset_page_url(self, n: int) -> str:
        return f"{self.datasets_url}/data-set-{n}-files"

    # ------------------------------------------------------------------
    # Parse a single dataset page for downloadable links
    # ------------------------------------------------------------------

    def _scrape_dataset_page(self, dataset_number: int) -> List[Dict[str, Any]]:
        """Return list of file metadata dicts from a single dataset page."""
        url = self._dataset_page_url(dataset_number)
        self.logger.info("Scraping dataset %d: %s", dataset_number, url)

        # Polite delay -- Akamai rate-limits aggressive crawlers
        time.sleep(1.5)

        resp = _request_with_retries(self.session, url)
        soup = BeautifulSoup(resp.text, "lxml")

        files: List[Dict[str, Any]] = []

        # DOJ pages use <a> tags pointing to /media/* or /sites/default/files/*
        for link in soup.find_all("a", href=True):
            href = link["href"]
            # Normalise relative URLs
            if href.startswith("/"):
                href = "https://www.justice.gov" + href
            # Filter to file downloads
            lower = href.lower()
            is_file = any(lower.endswith(ext) for ext in
                          (".pdf", ".jpg", ".jpeg", ".png", ".gif", ".mp4",
                           ".mp3", ".wav", ".doc", ".docx", ".xls", ".xlsx",
                           ".zip", ".tif", ".tiff"))
            if not is_file and "/media/" not in lower and "/sites/default/files/" not in lower:
                continue

            filename = urllib.parse.unquote(href.split("/")[-1].split("?")[0])
            if not filename:
                filename = f"dataset{dataset_number}_file_{len(files)}"

            file_type = "pdf"
            ext = os.path.splitext(filename)[1].lower()
            if ext in (".jpg", ".jpeg", ".png", ".gif", ".tif", ".tiff"):
                file_type = "image"
            elif ext in (".mp4", ".avi", ".mov"):
                file_type = "video"
            elif ext in (".mp3", ".wav"):
                file_type = "audio"
            elif ext not in (".pdf",):
                file_type = "other"

            files.append({
                "url": href,
                "filename": self._safe_filename(filename),
                "source": self.name,
                "dataset_number": dataset_number,
                "file_type": file_type,
                "link_text": link.get_text(strip=True)[:200],
            })

        # Also scrape paginated sub-pages (some dataset pages have ?page=1, ?page=2 ...)
        pager = soup.select("nav.pager a[href], ul.pager a[href]")
        visited = {url}
        for pg_link in pager:
            pg_href = pg_link["href"]
            if pg_href.startswith("/"):
                pg_href = "https://www.justice.gov" + pg_href
            if pg_href in visited:
                continue
            visited.add(pg_href)
            time.sleep(1.0)
            try:
                pg_resp = _request_with_retries(self.session, pg_href)
                pg_soup = BeautifulSoup(pg_resp.text, "lxml")
                for link2 in pg_soup.find_all("a", href=True):
                    h2 = link2["href"]
                    if h2.startswith("/"):
                        h2 = "https://www.justice.gov" + h2
                    lo2 = h2.lower()
                    if not any(lo2.endswith(e) for e in
                               (".pdf", ".jpg", ".jpeg", ".png", ".gif",
                                ".mp4", ".mp3", ".wav", ".doc", ".docx",
                                ".xls", ".xlsx", ".zip", ".tif", ".tiff")):
                        if "/media/" not in lo2 and "/sites/default/files/" not in lo2:
                            continue
                    fn2 = urllib.parse.unquote(h2.split("/")[-1].split("?")[0])
                    if not fn2:
                        fn2 = f"dataset{dataset_number}_pg_file_{len(files)}"
                    files.append({
                        "url": h2,
                        "filename": self._safe_filename(fn2),
                        "source": self.name,
                        "dataset_number": dataset_number,
                        "file_type": "pdf",
                        "link_text": link2.get_text(strip=True)[:200],
                    })
            except Exception as exc:
                self.logger.warning("Failed to scrape paginated page %s: %s", pg_href, exc)

        self.logger.info("Dataset %d: found %d file links", dataset_number, len(files))
        return files

    # ------------------------------------------------------------------
    # Scrape the main index page for top-level links
    # ------------------------------------------------------------------

    def _scrape_index(self) -> List[Dict[str, Any]]:
        """Scrape the main /epstein page for any directly linked files."""
        self.logger.info("Scraping DOJ index: %s", self.base_url)
        resp = _request_with_retries(self.session, self.base_url)
        soup = BeautifulSoup(resp.text, "lxml")
        files: List[Dict[str, Any]] = []
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if href.startswith("/"):
                href = "https://www.justice.gov" + href
            lower = href.lower()
            if any(lower.endswith(ext) for ext in (".pdf", ".zip")):
                fn = urllib.parse.unquote(href.split("/")[-1].split("?")[0])
                files.append({
                    "url": href,
                    "filename": self._safe_filename(fn or "doj_index_file"),
                    "source": self.name,
                    "file_type": "pdf",
                })
        return files

    # ------------------------------------------------------------------
    # Get current DOJ file listing (for removed-file detection)
    # ------------------------------------------------------------------

    def get_current_listing(self) -> Set[str]:
        """
        Return the set of file URLs currently listed on DOJ pages.
        Used by the removed-file scanner.
        """
        urls: Set[str] = set()
        # Index page
        for f in self._scrape_index():
            urls.add(f["url"])
        # Each dataset page
        for n in range(1, self.total_datasets + 1):
            try:
                for f in self._scrape_dataset_page(n):
                    urls.add(f["url"])
            except Exception as exc:
                self.logger.error("Could not scrape dataset %d for listing: %s", n, exc)
        return urls

    # ------------------------------------------------------------------
    # SourceModule API
    # ------------------------------------------------------------------

    def inventory(self) -> List[Dict[str, Any]]:
        all_files: List[Dict[str, Any]] = []
        all_files.extend(self._scrape_index())
        for n in range(1, self.total_datasets + 1):
            try:
                all_files.extend(self._scrape_dataset_page(n))
            except Exception as exc:
                self.logger.error("Dataset %d inventory failed: %s", n, exc)
        return all_files

    def download_all(self, dest_dir: Path) -> List[Path]:
        items = self.inventory()
        return self._download_items(items, dest_dir)

    def download_dataset(self, dataset_number: int, dest_dir: Path) -> List[Path]:
        """Download a single numbered dataset."""
        items = self._scrape_dataset_page(dataset_number)
        return self._download_items(items, dest_dir, dataset_number=dataset_number)

    def _download_items(self, items: List[dict], dest_dir: Path,
                        dataset_number: Optional[int] = None) -> List[Path]:
        downloaded: List[Path] = []
        total = len(items)
        for i, item in enumerate(items, 1):
            url = item["url"]
            if self._already_have(url):
                self.logger.debug("Already have %s", url)
                continue
            ds = item.get("dataset_number", dataset_number)
            sub = dest_dir / f"dataset_{ds}" if ds else dest_dir / "index"
            sub.mkdir(parents=True, exist_ok=True)
            dest = sub / item["filename"]

            def _progress(dl, tot, _url=url, _i=i, _total=total):
                self._report_progress(
                    f"[{_i}/{_total}] Downloading {_url}",
                    pct=(_i / _total) * 100,
                    detail=f"{dl}/{tot} bytes",
                )

            try:
                _download_file(self.session, url, dest, progress_cb=_progress)
                self._register_file(dest, url,
                                    dataset_number=ds,
                                    file_type=item.get("file_type", "pdf"))
                downloaded.append(dest)
                self._report_progress(
                    f"Downloaded {item['filename']}",
                    pct=(i / total) * 100,
                )
                # Polite crawl delay
                time.sleep(0.5)
            except Exception as exc:
                self.logger.error("Failed to download %s: %s", url, exc)
        return downloaded

    # ------------------------------------------------------------------
    # Ensure dataset rows exist in the DB
    # ------------------------------------------------------------------

    def ensure_datasets_registered(self):
        """Create dataset rows 1..total_datasets if they do not exist."""
        conn = self.db.get_connection()
        try:
            for n in range(1, self.total_datasets + 1):
                conn.execute(
                    """INSERT OR IGNORE INTO datasets
                       (dataset_number, source, source_url, status)
                       VALUES (?, 'doj', ?, 'pending')""",
                    (n, self._dataset_page_url(n)),
                )
            conn.commit()
        finally:
            conn.close()


# ===================================================================
# 2. GitHub Mirror
# ===================================================================

class GitHubMirror(SourceModule):
    """
    Clones / pulls from known GitHub mirrors of the Epstein files.
    Also uses the GitHub Search API to discover forks and related repos.
    """

    name = "github_mirror"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cfg = self.config.get("harvester", {}).get("github_mirrors", [])
        self.repos: List[str] = list(cfg) if cfg else [
            "https://github.com/yung-megafone/Epstein-Files",
        ]

    # ------------------------------------------------------------------
    # Git operations
    # ------------------------------------------------------------------

    def _clone_or_pull(self, repo_url: str, dest: Path) -> Path:
        """Clone a repo, or pull if it already exists locally."""
        # Validate URL to prevent command injection via flag-style strings
        if not repo_url.startswith(("https://", "http://")):
            raise ValueError(f"Refusing to clone non-HTTP URL: {repo_url!r}")
        repo_name = repo_url.rstrip("/").split("/")[-1]
        local = dest / repo_name
        if (local / ".git").exists():
            self.logger.info("Pulling updates for %s", repo_name)
            subprocess.run(
                ["git", "-C", str(local), "pull", "--ff-only"],
                capture_output=True, timeout=300,
            )
        else:
            self.logger.info("Cloning %s", repo_url)
            local.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(local)],
                capture_output=True, timeout=600,
            )
        return local

    # ------------------------------------------------------------------
    # Extract file links from repo contents
    # ------------------------------------------------------------------

    def _scan_repo_files(self, local: Path) -> List[Dict[str, Any]]:
        """Walk the cloned repo and catalogue files + extract magnet/download links."""
        items: List[Dict[str, Any]] = []
        magnet_pattern = re.compile(r"magnet:\?xt=urn:[^\s\"'<>]+")
        url_pattern = re.compile(
            r"https?://[^\s\"'<>]+\.(?:pdf|zip|rar|7z|tar\.gz)", re.IGNORECASE
        )

        for root, _dirs, files in os.walk(local):
            for fname in files:
                fp = Path(root) / fname
                # Prevent symlink-based path traversal / exfiltration
                try:
                    resolved = fp.resolve()
                    if not str(resolved).startswith(str(local.resolve())):
                        self.logger.warning("Skipping symlink outside repo: %s -> %s", fp, resolved)
                        continue
                except OSError:
                    continue
                if fp.is_symlink():
                    continue
                ext = fp.suffix.lower()
                if ext in (".pdf", ".jpg", ".jpeg", ".png", ".gif",
                           ".mp4", ".mp3", ".doc", ".docx", ".zip",
                           ".tif", ".tiff"):
                    items.append({
                        "url": f"file://{fp}",
                        "filename": fname,
                        "source": self.name,
                        "local_path": str(fp),
                        "file_type": "pdf" if ext == ".pdf" else "other",
                    })

                # Scan text files for links
                if ext in (".md", ".txt", ".csv", ".json", ".yaml", ".yml", ""):
                    try:
                        text = fp.read_text(encoding="utf-8", errors="ignore")
                        for m in magnet_pattern.finditer(text):
                            items.append({
                                "url": m.group(0),
                                "filename": f"magnet_from_{fname}",
                                "source": self.name,
                                "is_magnet": True,
                            })
                        for m in url_pattern.finditer(text):
                            items.append({
                                "url": m.group(0),
                                "filename": urllib.parse.unquote(
                                    m.group(0).split("/")[-1].split("?")[0]
                                ),
                                "source": self.name,
                            })
                    except Exception:
                        logger.debug("Skipped harvester item", exc_info=True)
        return items

    # ------------------------------------------------------------------
    # Discover forks / related repos via GitHub API
    # ------------------------------------------------------------------

    def discover_related_repos(self) -> List[str]:
        """Search GitHub for Epstein-file repos and forks."""
        found: List[str] = []
        queries = ["epstein files", "epstein documents", "epstein doj"]
        for q in queries:
            try:
                resp = _request_with_retries(
                    self.session,
                    "https://api.github.com/search/repositories",
                    params={"q": q, "sort": "updated", "per_page": "30"},
                )
                data = resp.json()
                for repo in data.get("items", []):
                    html_url = repo.get("html_url", "")
                    if html_url and html_url not in found:
                        found.append(html_url)
                time.sleep(2)  # GitHub rate-limit courtesy
            except Exception as exc:
                self.logger.warning("GitHub search failed for '%s': %s", q, exc)

        # Discover forks of known repos
        for repo_url in list(self.repos):
            parts = repo_url.rstrip("/").split("/")
            if len(parts) >= 2:
                owner, name = parts[-2], parts[-1]
                try:
                    resp = _request_with_retries(
                        self.session,
                        f"https://api.github.com/repos/{owner}/{name}/forks",
                        params={"per_page": "100"},
                    )
                    for fork in resp.json():
                        fork_url = fork.get("html_url", "")
                        if fork_url and fork_url not in found:
                            found.append(fork_url)
                    time.sleep(1)
                except Exception as exc:
                    self.logger.warning("Fork discovery failed for %s: %s", repo_url, exc)

        return found

    # ------------------------------------------------------------------
    # Get mirror inventory (for removed-file detection)
    # ------------------------------------------------------------------

    def get_mirror_file_urls(self, dest_dir: Path) -> Set[str]:
        """Return set of all download URLs found in mirror repos."""
        urls: Set[str] = set()
        for repo_url in self.repos:
            try:
                local = self._clone_or_pull(repo_url, dest_dir / "github_repos")
                items = self._scan_repo_files(local)
                for item in items:
                    if not item.get("is_magnet") and not item["url"].startswith("file://"):
                        urls.add(item["url"])
            except Exception as exc:
                self.logger.error("Mirror scan failed for %s: %s", repo_url, exc)
        return urls

    # ------------------------------------------------------------------
    # SourceModule API
    # ------------------------------------------------------------------

    def inventory(self) -> List[Dict[str, Any]]:
        all_items: List[Dict[str, Any]] = []
        dest = self.data_dir / "github_repos"
        for repo_url in self.repos:
            try:
                local = self._clone_or_pull(repo_url, dest)
                all_items.extend(self._scan_repo_files(local))
            except Exception as exc:
                self.logger.error("Inventory failed for %s: %s", repo_url, exc)
        return all_items

    def download_all(self, dest_dir: Path) -> List[Path]:
        items = self.inventory()
        downloaded: List[Path] = []
        total = len(items)
        for i, item in enumerate(items, 1):
            if item.get("is_magnet"):
                self.logger.info("Skipping magnet link (use TorrentEngine): %s",
                                 item["url"][:80])
                continue
            if item["url"].startswith("file://"):
                local = Path(item.get("local_path", item["url"][7:]))
                if local.exists():
                    dest = dest_dir / "github" / item["filename"]
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if not dest.exists():
                        shutil.copy2(local, dest)
                    self._register_file(dest, item["url"])
                    downloaded.append(dest)
                continue
            url = item["url"]
            if self._already_have(url):
                continue
            dest = dest_dir / "github" / self._safe_filename(item["filename"])
            try:
                _download_file(self.session, url, dest)
                self._register_file(dest, url)
                downloaded.append(dest)
                self._report_progress(
                    f"[{i}/{total}] GitHub: {item['filename']}",
                    pct=(i / total) * 100,
                )
                time.sleep(0.3)
            except Exception as exc:
                self.logger.error("Download failed %s: %s", url, exc)
        return downloaded


# ===================================================================
# 3. Archive.org Fetcher
# ===================================================================

class ArchiveOrgFetcher(SourceModule):
    """
    Downloads from the Internet Archive mirror collection and uses the
    Wayback Machine CDX/API to find snapshots of removed DOJ pages.
    """

    name = "archive_org"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cfg = self.config.get("harvester", {}).get("archive_org", {})
        self.collection_url = cfg.get(
            "collection_url",
            "https://ia600705.us.archive.org/21/items/epsteindocs/",
        )
        self.wayback_prefix = cfg.get(
            "wayback_prefix",
            "https://web.archive.org/web/*/justice.gov/epstein*",
        )

    # ------------------------------------------------------------------
    # Scrape the IA collection listing
    # ------------------------------------------------------------------

    def _scrape_collection(self) -> List[Dict[str, Any]]:
        """Parse the IA item listing page for downloadable files."""
        self.logger.info("Scraping IA collection: %s", self.collection_url)
        items: List[Dict[str, Any]] = []
        try:
            resp = _request_with_retries(self.session, self.collection_url)
            soup = BeautifulSoup(resp.text, "lxml")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if href.startswith("//") or href.startswith("http"):
                    full = href
                elif href.startswith("/"):
                    full = "https://archive.org" + href
                else:
                    full = self.collection_url.rstrip("/") + "/" + href
                lower = full.lower()
                if any(lower.endswith(ext) for ext in
                       (".pdf", ".zip", ".jpg", ".jpeg", ".png",
                        ".mp4", ".xml", ".json", ".csv")):
                    fn = urllib.parse.unquote(full.split("/")[-1].split("?")[0])
                    items.append({
                        "url": full,
                        "filename": self._safe_filename(fn),
                        "source": self.name,
                    })
        except Exception as exc:
            self.logger.error("IA collection scrape failed: %s", exc)

        # Also try the metadata API for the item
        # Extract the identifier from the URL
        match = re.search(r"/items/([^/]+)", self.collection_url)
        if match:
            identifier = match.group(1)
            meta_url = f"https://archive.org/metadata/{identifier}"
            try:
                resp = _request_with_retries(self.session, meta_url)
                meta = resp.json()
                for f in meta.get("files", []):
                    fname = f.get("name", "")
                    if any(fname.lower().endswith(ext) for ext in
                           (".pdf", ".zip", ".jpg", ".jpeg", ".png", ".mp4")):
                        dl_url = f"https://archive.org/download/{identifier}/{urllib.parse.quote(fname)}"
                        items.append({
                            "url": dl_url,
                            "filename": self._safe_filename(fname),
                            "source": self.name,
                            "size_bytes": int(f.get("size", 0)) if f.get("size") else None,
                        })
            except Exception as exc:
                self.logger.warning("IA metadata API failed: %s", exc)

        return items

    # ------------------------------------------------------------------
    # Wayback Machine CDX API -- find snapshots of DOJ pages
    # ------------------------------------------------------------------

    def search_wayback(self, url_pattern: str = "justice.gov/epstein*") -> List[Dict[str, str]]:
        """
        Query the Wayback CDX API for all snapshots matching *url_pattern*.
        Returns list of dicts with keys: timestamp, original_url, wayback_url, status.
        """
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": url_pattern,
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype,digest",
            "collapse": "digest",  # deduplicate identical captures
            "limit": "10000",
        }
        snapshots: List[Dict[str, str]] = []
        try:
            resp = _request_with_retries(self.session, cdx_url, params=params, timeout=120)
            rows = resp.json()
            if rows and len(rows) > 1:
                headers = rows[0]
                for row in rows[1:]:
                    entry = dict(zip(headers, row))
                    ts = entry.get("timestamp", "")
                    orig = entry.get("original", "")
                    wb_url = f"https://web.archive.org/web/{ts}/{orig}"
                    snapshots.append({
                        "timestamp": ts,
                        "original_url": orig,
                        "wayback_url": wb_url,
                        "status": entry.get("statuscode", ""),
                        "mimetype": entry.get("mimetype", ""),
                    })
        except Exception as exc:
            self.logger.error("Wayback CDX query failed: %s", exc)
        self.logger.info("Wayback: found %d snapshots for %s", len(snapshots), url_pattern)
        return snapshots

    def find_removed_page_snapshots(self, original_url: str) -> List[Dict[str, str]]:
        """Find Wayback snapshots specifically for a removed DOJ URL."""
        return self.search_wayback(original_url)

    def get_mirror_file_urls(self) -> Set[str]:
        """Return all file URLs known from the IA collection (for removed-file scan)."""
        items = self._scrape_collection()
        return {item["url"] for item in items}

    # ------------------------------------------------------------------
    # SourceModule API
    # ------------------------------------------------------------------

    def inventory(self) -> List[Dict[str, Any]]:
        return self._scrape_collection()

    def download_all(self, dest_dir: Path) -> List[Path]:
        items = self._scrape_collection()
        downloaded: List[Path] = []
        total = len(items)
        for i, item in enumerate(items, 1):
            url = item["url"]
            if self._already_have(url):
                continue
            dest = dest_dir / "archive_org" / item["filename"]
            try:
                _download_file(self.session, url, dest)
                self._register_file(dest, url)
                downloaded.append(dest)
                self._report_progress(
                    f"[{i}/{total}] IA: {item['filename']}",
                    pct=(i / total) * 100,
                )
                time.sleep(0.5)
            except Exception as exc:
                self.logger.error("IA download failed %s: %s", url, exc)
        return downloaded


# ===================================================================
# 4. Zenodo Puller
# ===================================================================

class ZenodoPuller(SourceModule):
    """Download files from a Zenodo record via its REST API."""

    name = "zenodo"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cfg = self.config.get("harvester", {}).get("zenodo", {})
        self.record_url = cfg.get("record_url", "https://zenodo.org/records/18512562")
        # Extract record ID
        self.record_id = self.record_url.rstrip("/").split("/")[-1]

    def _get_record_files(self) -> List[Dict[str, Any]]:
        """Query Zenodo API for files in this record."""
        api_url = f"https://zenodo.org/api/records/{self.record_id}"
        self.logger.info("Querying Zenodo API: %s", api_url)
        items: List[Dict[str, Any]] = []
        try:
            resp = _request_with_retries(self.session, api_url)
            data = resp.json()
            for f in data.get("files", []):
                items.append({
                    "url": f.get("links", {}).get("self", ""),
                    "filename": self._safe_filename(f.get("key", "unknown")),
                    "source": self.name,
                    "size_bytes": f.get("size"),
                    "checksum": f.get("checksum", ""),
                })
        except Exception as exc:
            self.logger.error("Zenodo API failed: %s", exc)
        return items

    def inventory(self) -> List[Dict[str, Any]]:
        return self._get_record_files()

    def download_all(self, dest_dir: Path) -> List[Path]:
        items = self._get_record_files()
        downloaded: List[Path] = []
        total = len(items)
        for i, item in enumerate(items, 1):
            url = item["url"]
            if not url or self._already_have(url):
                continue
            dest = dest_dir / "zenodo" / item["filename"]
            try:
                _download_file(self.session, url, dest,
                               expected_size=item.get("size_bytes"))
                self._register_file(dest, url)
                downloaded.append(dest)
                self._report_progress(
                    f"[{i}/{total}] Zenodo: {item['filename']}",
                    pct=(i / total) * 100,
                )
                time.sleep(0.3)
            except Exception as exc:
                self.logger.error("Zenodo download failed %s: %s", url, exc)
        return downloaded


# ===================================================================
# 5. Reddit Crawler
# ===================================================================

class RedditCrawler(SourceModule):
    """
    Searches Reddit for document links using the public JSON API.
    Appends .json to regular Reddit URLs to avoid needing OAuth.
    """

    name = "reddit"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cfg = self.config.get("harvester", {}).get("reddit", {})
        self.subreddits: List[str] = cfg.get("subreddits", ["Epstein", "EpsteinFiles", "conspiracy"])
        self.search_terms: List[str] = cfg.get("search_terms", [
            "epstein files", "epstein documents", "DOJ epstein release",
        ])
        # Reddit blocks the default User-Agent for its JSON endpoint
        self.session.headers["User-Agent"] = (
            "EpsteinAnalyzer/1.0 (research tool; document harvester)"
        )

    def _extract_links_from_posts(self, posts: list) -> List[Dict[str, Any]]:
        """Extract file download links from Reddit post data."""
        url_pattern = re.compile(
            r"https?://[^\s\"'<>\)\]]+\.(?:pdf|zip|rar|7z)", re.IGNORECASE
        )
        magnet_pattern = re.compile(r"magnet:\?xt=urn:[^\s\"'<>\)\]]+")
        items: List[Dict[str, Any]] = []

        for post in posts:
            data = post.get("data", {})
            # Check URL field
            post_url = data.get("url", "")
            selftext = data.get("selftext", "")
            title = data.get("title", "")
            combined = f"{post_url} {selftext}"

            for m in url_pattern.finditer(combined):
                link = m.group(0)
                fn = urllib.parse.unquote(link.split("/")[-1].split("?")[0])
                items.append({
                    "url": link,
                    "filename": self._safe_filename(fn),
                    "source": self.name,
                    "reddit_title": title[:200],
                    "reddit_id": data.get("id", ""),
                })

            for m in magnet_pattern.finditer(combined):
                items.append({
                    "url": m.group(0),
                    "filename": f"reddit_magnet_{data.get('id', '')}",
                    "source": self.name,
                    "is_magnet": True,
                    "reddit_title": title[:200],
                })
        return items

    def _search_subreddit(self, subreddit: str, query: str) -> List[Dict[str, Any]]:
        """Search a single subreddit using the .json API."""
        url = f"https://www.reddit.com/r/{subreddit}/search.json"
        params = {
            "q": query,
            "restrict_sr": "1",
            "sort": "new",
            "limit": "100",
            "t": "all",
        }
        items: List[Dict[str, Any]] = []
        try:
            resp = _request_with_retries(self.session, url, params=params)
            data = resp.json()
            posts = data.get("data", {}).get("children", [])
            items.extend(self._extract_links_from_posts(posts))
        except Exception as exc:
            self.logger.warning("Reddit search failed r/%s q=%s: %s", subreddit, query, exc)
        time.sleep(2)  # Reddit rate limit
        return items

    def _get_hot_posts(self, subreddit: str) -> List[Dict[str, Any]]:
        """Get hot posts from a subreddit."""
        url = f"https://www.reddit.com/r/{subreddit}/hot.json"
        params = {"limit": "100"}
        items: List[Dict[str, Any]] = []
        try:
            resp = _request_with_retries(self.session, url, params=params)
            data = resp.json()
            posts = data.get("data", {}).get("children", [])
            items.extend(self._extract_links_from_posts(posts))
        except Exception as exc:
            self.logger.warning("Reddit hot fetch failed r/%s: %s", subreddit, exc)
        time.sleep(2)
        return items

    def inventory(self) -> List[Dict[str, Any]]:
        all_items: List[Dict[str, Any]] = []
        for sub in self.subreddits:
            all_items.extend(self._get_hot_posts(sub))
            for term in self.search_terms:
                all_items.extend(self._search_subreddit(sub, term))
        # Deduplicate by URL
        seen: Set[str] = set()
        deduped: List[Dict[str, Any]] = []
        for item in all_items:
            if item["url"] not in seen:
                seen.add(item["url"])
                deduped.append(item)
        return deduped

    def download_all(self, dest_dir: Path) -> List[Path]:
        items = self.inventory()
        downloaded: List[Path] = []
        total = len(items)
        for i, item in enumerate(items, 1):
            if item.get("is_magnet"):
                self.logger.info("Magnet link from Reddit (use TorrentEngine): %s",
                                 item["url"][:80])
                continue
            url = item["url"]
            if self._already_have(url):
                continue
            dest = dest_dir / "reddit" / item["filename"]
            try:
                _download_file(self.session, url, dest)
                self._register_file(dest, url)
                downloaded.append(dest)
                self._report_progress(
                    f"[{i}/{total}] Reddit: {item['filename']}",
                    pct=(i / total) * 100,
                )
                time.sleep(1)
            except Exception as exc:
                self.logger.error("Reddit download failed %s: %s", url, exc)
        return downloaded


# ===================================================================
# 6. FOIA Scanner (MuckRock)
# ===================================================================

class FOIAScanner(SourceModule):
    """Search MuckRock for Epstein-related FOIA responses and download attachments."""

    name = "foia_muckrock"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cfg = self.config.get("harvester", {}).get("foia", {})
        self.search_query = cfg.get("muckrock_search", "jeffrey epstein")
        self.api_base = "https://www.muckrock.com/api_v1/"

    def _search_foia(self) -> List[Dict[str, Any]]:
        """Search MuckRock FOIA API for requests matching our query."""
        items: List[Dict[str, Any]] = []
        url = f"{self.api_base}foia/"
        params = {
            "search": self.search_query,
            "per_page": "100",
            "format": "json",
        }
        page = 1
        while True:
            params["page"] = str(page)
            try:
                resp = _request_with_retries(self.session, url, params=params)
                data = resp.json()
                results = data.get("results", [])
                if not results:
                    break
                for req in results:
                    req_id = req.get("id")
                    title = req.get("title", "Unknown FOIA")
                    # Get communications/files for this request
                    comms_url = f"{self.api_base}foia/{req_id}/communications/"
                    try:
                        comms_resp = _request_with_retries(self.session, comms_url,
                                                           params={"format": "json"})
                        comms = comms_resp.json()
                        for comm in comms.get("results", []):
                            for f in comm.get("files", []):
                                file_url = f.get("ffile", "")
                                if file_url:
                                    fn = urllib.parse.unquote(
                                        file_url.split("/")[-1].split("?")[0]
                                    )
                                    items.append({
                                        "url": file_url,
                                        "filename": self._safe_filename(fn or f"foia_{req_id}"),
                                        "source": self.name,
                                        "foia_title": title[:200],
                                        "foia_id": req_id,
                                    })
                        time.sleep(0.5)
                    except Exception as exc:
                        self.logger.warning("Failed to get FOIA comms for %s: %s", req_id, exc)
                # Pagination
                if data.get("next"):
                    page += 1
                    time.sleep(1)
                else:
                    break
            except Exception as exc:
                self.logger.error("MuckRock search failed page %d: %s", page, exc)
                break
        return items

    def inventory(self) -> List[Dict[str, Any]]:
        return self._search_foia()

    def download_all(self, dest_dir: Path) -> List[Path]:
        items = self._search_foia()
        downloaded: List[Path] = []
        total = len(items)
        for i, item in enumerate(items, 1):
            url = item["url"]
            if self._already_have(url):
                continue
            dest = dest_dir / "foia" / item["filename"]
            try:
                _download_file(self.session, url, dest)
                self._register_file(dest, url, file_type="pdf")
                downloaded.append(dest)
                self._report_progress(
                    f"[{i}/{total}] FOIA: {item['filename']}",
                    pct=(i / total) * 100,
                )
                time.sleep(0.5)
            except Exception as exc:
                self.logger.error("FOIA download failed %s: %s", url, exc)
        return downloaded


# ===================================================================
# 7. CourtListener Fetcher
# ===================================================================

class CourtListenerFetcher(SourceModule):
    """
    Uses the free CourtListener REST API to search for and download
    federal case filings related to the Epstein case.
    """

    name = "court_listener"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cfg = self.config.get("harvester", {}).get("court_listener", {})
        self.api_base = cfg.get("api_base", "https://www.courtlistener.com/api/rest/v4/")
        self.case_searches: List[str] = cfg.get("case_searches", [
            "Giuffre v. Maxwell",
            "United States v. Epstein",
            "United States v. Maxwell",
            "Doe v. Epstein",
        ])

    def _search_opinions(self, query: str) -> List[Dict[str, Any]]:
        """Search CourtListener opinions endpoint."""
        items: List[Dict[str, Any]] = []
        url = f"{self.api_base}search/"
        params = {
            "q": query,
            "type": "o",  # opinions
            "format": "json",
        }
        try:
            resp = _request_with_retries(self.session, url, params=params)
            data = resp.json()
            for result in data.get("results", []):
                # Opinions may have a download_url or absolute_url
                dl = result.get("download_url", "")
                abs_url = result.get("absolute_url", "")
                if dl:
                    full_url = dl if dl.startswith("http") else f"https://www.courtlistener.com{dl}"
                    case_name = result.get("caseName", "unknown_case")
                    fn = self._safe_filename(f"{case_name}_{result.get('id', '')}.pdf")
                    items.append({
                        "url": full_url,
                        "filename": fn,
                        "source": self.name,
                        "case_name": case_name[:200],
                        "doc_type": "court_filing",
                    })
                elif abs_url:
                    full_url = f"https://www.courtlistener.com{abs_url}" if abs_url.startswith("/") else abs_url
                    items.append({
                        "url": full_url,
                        "filename": self._safe_filename(f"cl_{result.get('id', '')}.html"),
                        "source": self.name,
                        "case_name": result.get("caseName", "")[:200],
                        "doc_type": "court_filing",
                        "file_type": "other",
                    })
        except Exception as exc:
            self.logger.error("CourtListener search failed for '%s': %s", query, exc)
        return items

    def _search_dockets(self, query: str) -> List[Dict[str, Any]]:
        """Search CourtListener dockets for RECAP documents."""
        items: List[Dict[str, Any]] = []
        url = f"{self.api_base}search/"
        params = {
            "q": query,
            "type": "r",  # RECAP
            "format": "json",
        }
        try:
            resp = _request_with_retries(self.session, url, params=params)
            data = resp.json()
            for result in data.get("results", []):
                dl = result.get("download_url", "")
                if dl:
                    full_url = dl if dl.startswith("http") else f"https://www.courtlistener.com{dl}"
                    case_name = result.get("caseName", result.get("docketNumber", "unknown"))
                    fn = self._safe_filename(f"recap_{case_name}_{result.get('id', '')}.pdf")
                    items.append({
                        "url": full_url,
                        "filename": fn,
                        "source": self.name,
                        "case_name": case_name[:200],
                        "doc_type": "court_filing",
                    })
        except Exception as exc:
            self.logger.error("CourtListener docket search failed for '%s': %s", query, exc)
        return items

    def inventory(self) -> List[Dict[str, Any]]:
        all_items: List[Dict[str, Any]] = []
        for query in self.case_searches:
            all_items.extend(self._search_opinions(query))
            all_items.extend(self._search_dockets(query))
            time.sleep(1)
        # Deduplicate
        seen: Set[str] = set()
        deduped: List[Dict[str, Any]] = []
        for item in all_items:
            if item["url"] not in seen:
                seen.add(item["url"])
                deduped.append(item)
        return deduped

    def download_all(self, dest_dir: Path) -> List[Path]:
        items = self.inventory()
        downloaded: List[Path] = []
        total = len(items)
        for i, item in enumerate(items, 1):
            url = item["url"]
            if self._already_have(url):
                continue
            dest = dest_dir / "court_listener" / item["filename"]
            try:
                _download_file(self.session, url, dest)
                self._register_file(dest, url, file_type=item.get("file_type", "pdf"))
                downloaded.append(dest)
                self._report_progress(
                    f"[{i}/{total}] CourtListener: {item['filename']}",
                    pct=(i / total) * 100,
                )
                time.sleep(0.5)
            except Exception as exc:
                self.logger.error("CourtListener download failed %s: %s", url, exc)
        return downloaded


# ===================================================================
# 8. Torrent Engine
# ===================================================================

class TorrentEngine(SourceModule):
    """
    Handles magnet links gathered by other source modules.
    Delegates to a locally installed torrent client via subprocess.
    Supports aria2c (preferred) or transmission-cli as backends.
    """

    name = "torrent"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._backend = self._detect_backend()

    def _detect_backend(self) -> Optional[str]:
        """Find an installed CLI torrent client."""
        for cmd in ("aria2c", "transmission-cli", "ctorrent"):
            if shutil.which(cmd):
                self.logger.info("Torrent backend: %s", cmd)
                return cmd
        self.logger.warning(
            "No torrent CLI found. Install aria2c for magnet-link support."
        )
        return None

    def download_magnet(self, magnet_uri: str, dest_dir: Path,
                        timeout: int = 3600) -> Optional[Path]:
        """
        Download a single magnet link to *dest_dir*.
        Returns the path to the downloaded content or None on failure.
        """
        # Validate magnet URI to prevent command injection
        if not magnet_uri.startswith("magnet:"):
            self.logger.error("Refusing non-magnet URI: %s", magnet_uri[:80])
            return None
        if not self._backend:
            self.logger.error("No torrent backend available")
            return None

        dest_dir.mkdir(parents=True, exist_ok=True)

        if self._backend == "aria2c":
            cmd = [
                "aria2c",
                "--dir", str(dest_dir),
                "--seed-time=0",
                "--max-overall-download-limit=0",
                "--file-allocation=none",
                "--summary-interval=30",
                magnet_uri,
            ]
        elif self._backend == "transmission-cli":
            cmd = [
                "transmission-cli",
                "-w", str(dest_dir),
                magnet_uri,
            ]
        else:
            cmd = [self._backend, magnet_uri]

        self.logger.info("Starting torrent download: %s", magnet_uri[:80])
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                text=True,
            )
            if result.returncode == 0:
                self.logger.info("Torrent download completed")
                # Find newly created files
                for root, _dirs, files in os.walk(dest_dir):
                    for f in files:
                        fp = Path(root) / f
                        if fp.stat().st_mtime > time.time() - timeout:
                            return fp
            else:
                self.logger.error("Torrent client error: %s", result.stderr[:500])
        except subprocess.TimeoutExpired:
            self.logger.error("Torrent download timed out after %ds", timeout)
        except FileNotFoundError:
            self.logger.error("Torrent backend '%s' not found", self._backend)
        return None

    def inventory(self) -> List[Dict[str, Any]]:
        """
        Torrent engine does not independently discover links.
        It processes magnets found by other modules.
        Gather unprocessed magnets from the DB.
        """
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                "SELECT source_url FROM documents WHERE source_url LIKE 'magnet:%'"
            ).fetchall()
            return [{"url": r["source_url"], "source": self.name, "filename": "magnet",
                     "is_magnet": True} for r in rows]
        finally:
            conn.close()

    def download_all(self, dest_dir: Path) -> List[Path]:
        """Download all pending magnet links."""
        items = self.inventory()
        downloaded: List[Path] = []
        for item in items:
            result = self.download_magnet(item["url"], dest_dir / "torrents")
            if result:
                self._register_file(result, item["url"])
                downloaded.append(result)
        return downloaded


# ===================================================================
# 9. State Court Scraper
# ===================================================================

class StateCourtScraper(SourceModule):
    """
    Scrapes free public state court portals for Epstein-related filings.
    Targets: Florida (Palm Beach County), New York, USVI.
    """

    name = "state_courts"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cfg = self.config.get("harvester", {}).get("state_courts", {})
        self.florida_cfg = cfg.get("florida", {})
        self.ny_cfg = cfg.get("new_york", {})
        self.usvi_cfg = cfg.get("usvi", {})

    # ------------------------------------------------------------------
    # Florida -- Palm Beach County Clerk
    # ------------------------------------------------------------------

    def _scrape_florida(self) -> List[Dict[str, Any]]:
        """Scrape the Palm Beach County Clerk portal for Epstein cases."""
        items: List[Dict[str, Any]] = []
        if not self.florida_cfg.get("enabled"):
            return items

        portal = self.florida_cfg.get("portal", "https://www.pbcclerk.org/clerkwebportal/")
        search_url = portal.rstrip("/") + "/Search/CaseSearch"

        # The PBC portal requires form-based search.
        # We search for "Epstein" as party name.
        try:
            # First, get the search page to collect any CSRF tokens / cookies
            self.logger.info("Scraping Florida PBC portal: %s", search_url)
            page = _request_with_retries(self.session, portal)
            soup = BeautifulSoup(page.text, "lxml")

            # Attempt the case search
            search_resp = self.session.get(
                search_url,
                params={"lastName": "Epstein", "firstName": "Jeffrey"},
                timeout=REQUEST_TIMEOUT,
            )
            if search_resp.status_code == 200:
                result_soup = BeautifulSoup(search_resp.text, "lxml")
                # Look for links to case documents
                for link in result_soup.find_all("a", href=True):
                    href = link["href"]
                    if "document" in href.lower() or "image" in href.lower():
                        full = href if href.startswith("http") else portal.rstrip("/") + "/" + href.lstrip("/")
                        fn = self._safe_filename(link.get_text(strip=True)[:100] or "fl_doc")
                        items.append({
                            "url": full,
                            "filename": fn + ".pdf",
                            "source": self.name,
                            "state": "FL",
                            "doc_type": "court_filing",
                        })
        except Exception as exc:
            self.logger.error("Florida court scrape failed: %s", exc)
        return items

    # ------------------------------------------------------------------
    # New York -- WebCivil Supreme (free)
    # ------------------------------------------------------------------

    def _scrape_new_york(self) -> List[Dict[str, Any]]:
        """Search NY WebCivil Supreme for Epstein cases."""
        items: List[Dict[str, Any]] = []
        if not self.ny_cfg.get("enabled"):
            return items

        # NY eCourts has a public search at iapps.courts.state.ny.us
        search_url = "https://iapps.courts.state.ny.us/nyscef/CaseSearch"
        try:
            self.logger.info("Searching NY eCourts for Epstein filings")
            # Search by party name
            resp = self.session.get(
                search_url,
                params={"txtPartyName": "Epstein", "selCounty": "", "selCaseType": ""},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "lxml")
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    if "DocumentList" in href or "ViewDocument" in href:
                        full = href if href.startswith("http") else \
                            "https://iapps.courts.state.ny.us" + href
                        fn = self._safe_filename(
                            link.get_text(strip=True)[:100] or "ny_doc"
                        )
                        items.append({
                            "url": full,
                            "filename": fn + ".pdf",
                            "source": self.name,
                            "state": "NY",
                            "doc_type": "court_filing",
                        })
        except Exception as exc:
            self.logger.error("NY court scrape failed: %s", exc)
        return items

    # ------------------------------------------------------------------
    # USVI -- Territorial Court
    # ------------------------------------------------------------------

    def _scrape_usvi(self) -> List[Dict[str, Any]]:
        """Search USVI court portal for Epstein cases."""
        items: List[Dict[str, Any]] = []
        if not self.usvi_cfg.get("enabled"):
            return items

        # USVI Superior Court public search
        search_url = "https://www.visuperiorcourt.org/case-search"
        try:
            self.logger.info("Searching USVI court for Epstein filings")
            resp = _request_with_retries(self.session, search_url)
            soup = BeautifulSoup(resp.text, "lxml")
            # Look for case-related links with "Epstein" in text
            for link in soup.find_all("a", href=True):
                text = link.get_text(strip=True).lower()
                href = link["href"]
                if "epstein" in text:
                    full = href if href.startswith("http") else \
                        "https://www.visuperiorcourt.org" + href
                    fn = self._safe_filename(link.get_text(strip=True)[:100] or "usvi_doc")
                    items.append({
                        "url": full,
                        "filename": fn + ".pdf",
                        "source": self.name,
                        "state": "USVI",
                        "doc_type": "court_filing",
                    })
        except Exception as exc:
            self.logger.error("USVI court scrape failed: %s", exc)
        return items

    # ------------------------------------------------------------------
    # SourceModule API
    # ------------------------------------------------------------------

    def inventory(self) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        items.extend(self._scrape_florida())
        items.extend(self._scrape_new_york())
        items.extend(self._scrape_usvi())
        return items

    def download_all(self, dest_dir: Path) -> List[Path]:
        items = self.inventory()
        downloaded: List[Path] = []
        total = len(items)
        for i, item in enumerate(items, 1):
            url = item["url"]
            if self._already_have(url):
                continue
            state = item.get("state", "unknown")
            dest = dest_dir / "state_courts" / state / item["filename"]
            try:
                _download_file(self.session, url, dest)
                self._register_file(dest, url, file_type="pdf")
                downloaded.append(dest)
                self._report_progress(
                    f"[{i}/{total}] {state} Court: {item['filename']}",
                    pct=(i / total) * 100,
                )
                time.sleep(1)
            except Exception as exc:
                self.logger.error("State court download failed %s: %s", url, exc)
        return downloaded


# ===================================================================
#  HARVESTER ENGINE -- Main orchestrator
# ===================================================================

class HarvesterEngine:
    """
    Orchestrates all source modules, manages deduplication, tracks downloads
    in SQLite, detects removed files, and reports progress.
    """

    # Registry mapping config names to classes
    SOURCE_CLASSES = {
        "doj": DOJScraper,
        "github_mirror": GitHubMirror,
        "archive_org": ArchiveOrgFetcher,
        "zenodo": ZenodoPuller,
        "reddit": RedditCrawler,
        "foia_muckrock": FOIAScanner,
        "court_listener": CourtListenerFetcher,
        "torrent": TorrentEngine,
        "state_courts": StateCourtScraper,
    }

    def __init__(self, config_path: Optional[str] = None,
                 progress_cb: Optional[Callable] = None):
        self.config = _load_config(config_path)
        self.db = DatabaseManager(config_path)
        self.db.initialize()
        self.data_dir = Path(self.config["project"]["data_dir"]).resolve()
        self.datasets_dir = self.data_dir / "datasets"
        self.datasets_dir.mkdir(parents=True, exist_ok=True)
        self.progress_cb = progress_cb
        self.logger = logging.getLogger("harvester.engine")

        # Instantiate enabled source modules
        enabled = self.config.get("harvester", {}).get("enabled_sources", [])
        self.sources: Dict[str, SourceModule] = {}
        for name in enabled:
            cls = self.SOURCE_CLASSES.get(name)
            if cls:
                self.sources[name] = cls(
                    config=self.config,
                    db=self.db,
                    data_dir=self.data_dir,
                    progress_cb=progress_cb,
                )
            else:
                self.logger.warning("Unknown source module: %s", name)

        # Ensure DOJ dataset rows exist
        doj = self.sources.get("doj")
        if isinstance(doj, DOJScraper):
            doj.ensure_datasets_registered()

    # ------------------------------------------------------------------
    # Download a single DOJ dataset by number
    # ------------------------------------------------------------------

    def download_dataset(self, number: int) -> List[Path]:
        """
        One-click download of DOJ dataset *number* (1-12).
        Updates dataset status in the database throughout.
        """
        doj = self.sources.get("doj")
        if not isinstance(doj, DOJScraper):
            raise RuntimeError("DOJ source module not enabled")

        conn = self.db.get_connection()
        try:
            conn.execute(
                "UPDATE datasets SET status = 'downloading', downloaded_at = ? WHERE dataset_number = ?",
                (datetime.now(timezone.utc).isoformat(), number),
            )
            conn.commit()
        finally:
            conn.close()

        self.logger.info("=== Downloading DOJ Dataset %d ===", number)
        self._report_progress(f"Starting download of Dataset {number}")

        try:
            paths = doj.download_dataset(number, self.datasets_dir)

            conn = self.db.get_connection()
            try:
                conn.execute(
                    """UPDATE datasets
                       SET status = 'downloaded',
                           total_files = ?,
                           downloaded_at = ?
                       WHERE dataset_number = ?""",
                    (len(paths), datetime.now(timezone.utc).isoformat(), number),
                )
                conn.commit()
            finally:
                conn.close()

            self.db.log_action(
                "dataset_download",
                f"Dataset {number}: {len(paths)} files downloaded",
                user_initiated=True,
            )
            self._report_progress(
                f"Dataset {number} complete: {len(paths)} files",
                pct=100,
            )
            return paths

        except Exception as exc:
            conn = self.db.get_connection()
            try:
                conn.execute(
                    "UPDATE datasets SET status = 'error', notes = ? WHERE dataset_number = ?",
                    (str(exc)[:500], number),
                )
                conn.commit()
            finally:
                conn.close()
            raise

    # ------------------------------------------------------------------
    # Download everything from all enabled sources
    # ------------------------------------------------------------------

    def download_all(self) -> Dict[str, List[Path]]:
        """Run all enabled source modules and download everything."""
        results: Dict[str, List[Path]] = {}
        for name, source in self.sources.items():
            self.logger.info("=== Running source: %s ===", name)
            self._report_progress(f"Starting source: {name}")
            try:
                paths = source.download_all(self.datasets_dir)
                results[name] = paths
                self.logger.info("Source %s: %d files", name, len(paths))
            except Exception as exc:
                self.logger.error("Source %s failed: %s", name, exc)
                results[name] = []
        total = sum(len(v) for v in results.values())
        self.db.log_action(
            "full_harvest",
            f"Harvested {total} files from {len(results)} sources",
            user_initiated=True,
        )
        return results

    # ------------------------------------------------------------------
    # REMOVED FILE DETECTION -- HIGHEST PRIORITY
    # ------------------------------------------------------------------

    def removed_file_scan(self) -> List[Dict[str, Any]]:
        """
        Compare mirror inventories against current DOJ listings.
        Any file that exists on mirrors but is gone from DOJ is flagged
        as REMOVED -- CRITICAL PRIORITY.

        Returns list of removed-file records.
        """
        self.logger.info("=" * 60)
        self.logger.info("REMOVED FILE SCAN -- CRITICAL PRIORITY")
        self.logger.info("=" * 60)
        self._report_progress("Starting removed-file scan", pct=0)

        removed: List[Dict[str, Any]] = []

        # Step 1: Get current DOJ listing
        doj = self.sources.get("doj")
        if not isinstance(doj, DOJScraper):
            self.logger.error("DOJ source not enabled -- cannot scan for removals")
            return removed

        self._report_progress("Scanning current DOJ listings...", pct=10)
        current_doj_urls = doj.get_current_listing()
        self.logger.info("Current DOJ listings: %d URLs", len(current_doj_urls))

        # Step 2: Collect mirror inventories
        mirror_urls: Set[str] = set()

        # GitHub mirrors
        gh = self.sources.get("github_mirror")
        if isinstance(gh, GitHubMirror):
            self._report_progress("Scanning GitHub mirrors...", pct=25)
            try:
                gh_urls = gh.get_mirror_file_urls(self.data_dir)
                mirror_urls.update(gh_urls)
                self.logger.info("GitHub mirror URLs: %d", len(gh_urls))
            except Exception as exc:
                self.logger.error("GitHub mirror scan failed: %s", exc)

        # Internet Archive
        ia = self.sources.get("archive_org")
        if isinstance(ia, ArchiveOrgFetcher):
            self._report_progress("Scanning Internet Archive...", pct=40)
            try:
                ia_urls = ia.get_mirror_file_urls()
                mirror_urls.update(ia_urls)
                self.logger.info("IA mirror URLs: %d", len(ia_urls))
            except Exception as exc:
                self.logger.error("IA mirror scan failed: %s", exc)

        # Also check what we already have in our own DB
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                "SELECT source_url FROM documents WHERE source = 'doj' AND source_url IS NOT NULL"
            ).fetchall()
            for row in rows:
                mirror_urls.add(row["source_url"])
        finally:
            conn.close()

        self._report_progress("Comparing inventories...", pct=60)

        # Step 3: Normalise URLs for comparison
        def _normalise(url: str) -> str:
            """Strip query params and fragments, lowercase, remove trailing slash."""
            parsed = urllib.parse.urlparse(url)
            path = parsed.path.rstrip("/").lower()
            return f"{parsed.scheme}://{parsed.netloc}{path}"

        doj_normalised = {_normalise(u) for u in current_doj_urls}

        # Step 4: Find URLs that mirrors know about but DOJ no longer lists
        # We only flag URLs that look like DOJ URLs
        now = datetime.now(timezone.utc).isoformat()
        for mirror_url in mirror_urls:
            norm = _normalise(mirror_url)
            # Only consider DOJ-origin URLs
            if "justice.gov" not in norm:
                continue
            if norm not in doj_normalised:
                # This file existed on mirrors but is no longer on DOJ
                filename = urllib.parse.unquote(mirror_url.split("/")[-1].split("?")[0])
                record = {
                    "original_url": mirror_url,
                    "original_source": "doj",
                    "filename": filename,
                    "removed_detected_at": now,
                    "priority": "CRITICAL",
                }
                removed.append(record)

                # Insert into removed_files table
                conn = self.db.get_connection()
                try:
                    conn.execute(
                        """INSERT OR IGNORE INTO removed_files
                           (original_url, original_source, filename,
                            removed_detected_at, priority)
                           VALUES (?, ?, ?, ?, 'CRITICAL')""",
                        (mirror_url, "doj", filename, now),
                    )
                    # Also flag in documents table
                    conn.execute(
                        """UPDATE documents
                           SET is_removed_from_source = 1,
                               removed_detected_at = ?,
                               priority_score = MAX(priority_score, 90)
                           WHERE source_url = ?""",
                        (now, mirror_url),
                    )
                    conn.commit()
                finally:
                    conn.close()

                self.logger.warning(
                    "REMOVED -- CRITICAL PRIORITY: %s (was at %s)",
                    filename, mirror_url,
                )

        self._report_progress("Searching Wayback Machine for removed pages...", pct=75)

        # Step 5: For each removed file, check Wayback Machine for snapshots
        if isinstance(ia, ArchiveOrgFetcher) and removed:
            for rec in removed:
                try:
                    snapshots = ia.find_removed_page_snapshots(rec["original_url"])
                    if snapshots:
                        rec["wayback_snapshots"] = len(snapshots)
                        rec["latest_snapshot"] = snapshots[-1]["wayback_url"]
                        # Update DB
                        conn = self.db.get_connection()
                        try:
                            conn.execute(
                                """UPDATE removed_files
                                   SET found_on_mirror = 1,
                                       mirror_source = 'wayback',
                                       mirror_url = ?
                                   WHERE original_url = ?""",
                                (snapshots[-1]["wayback_url"], rec["original_url"]),
                            )
                            conn.commit()
                        finally:
                            conn.close()
                        self.logger.info(
                            "Wayback has %d snapshots for removed file: %s",
                            len(snapshots), rec["filename"],
                        )
                except Exception as exc:
                    self.logger.warning(
                        "Wayback lookup failed for %s: %s",
                        rec["original_url"], exc,
                    )
                time.sleep(0.5)

        self._report_progress(
            f"Removed-file scan complete: {len(removed)} removals detected",
            pct=100,
        )

        # Log the action
        self.db.log_action(
            "removed_file_scan",
            f"Detected {len(removed)} removed files",
            user_initiated=True,
        )

        if removed:
            self.logger.warning("=" * 60)
            self.logger.warning(
                "ALERT: %d files have been REMOVED from DOJ", len(removed)
            )
            for rec in removed:
                self.logger.warning(
                    "  REMOVED: %s (%s)", rec["filename"], rec["original_url"]
                )
            self.logger.warning("=" * 60)

        return removed

    # ------------------------------------------------------------------
    # Attempt to recover removed files from mirrors
    # ------------------------------------------------------------------

    def recover_removed_files(self) -> List[Path]:
        """
        For every un-recovered entry in removed_files, attempt to download
        from mirrors (Wayback, IA, GitHub).
        """
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM removed_files WHERE recovered = 0"
            ).fetchall()
        finally:
            conn.close()

        recovered: List[Path] = []
        session = _build_session()
        ia = self.sources.get("archive_org")

        for row in rows:
            original_url = row["original_url"]
            filename = row["filename"] or "recovered_file"
            dest = self.datasets_dir / "recovered" / self._safe_filename(filename)
            dest.parent.mkdir(parents=True, exist_ok=True)

            # Try mirror_url first (Wayback)
            mirror_url = row["mirror_url"]
            if mirror_url:
                try:
                    _download_file(session, mirror_url, dest)
                    file_hash = _sha256_file(dest)
                    conn = self.db.get_connection()
                    try:
                        # Register the document
                        cur = conn.execute(
                            """INSERT OR IGNORE INTO documents
                               (file_hash, original_filename, file_path, file_type,
                                source, source_url, size_bytes, status,
                                is_removed_from_source, removed_detected_at,
                                priority_score)
                               VALUES (?, ?, ?, 'pdf', 'recovered', ?, ?, 'downloaded',
                                       1, ?, 95)""",
                            (file_hash, filename, str(dest), original_url,
                             dest.stat().st_size, row["removed_detected_at"]),
                        )
                        doc_id = cur.lastrowid
                        conn.execute(
                            """UPDATE removed_files
                               SET recovered = 1, recovered_document_id = ?
                               WHERE id = ?""",
                            (doc_id, row["id"]),
                        )
                        conn.commit()
                    finally:
                        conn.close()
                    recovered.append(dest)
                    self.logger.info("RECOVERED removed file: %s", filename)
                    continue
                except Exception as exc:
                    self.logger.warning("Mirror recovery failed for %s: %s", filename, exc)

            # Try Wayback Machine directly
            if isinstance(ia, ArchiveOrgFetcher):
                snapshots = ia.find_removed_page_snapshots(original_url)
                for snap in reversed(snapshots):
                    try:
                        _download_file(session, snap["wayback_url"], dest)
                        self.logger.info("RECOVERED from Wayback: %s", filename)
                        recovered.append(dest)
                        conn = self.db.get_connection()
                        try:
                            conn.execute(
                                """UPDATE removed_files
                                   SET recovered = 1, mirror_source = 'wayback',
                                       mirror_url = ?
                                   WHERE id = ?""",
                                (snap["wayback_url"], row["id"]),
                            )
                            conn.commit()
                        finally:
                            conn.close()
                        break
                    except Exception:
                        continue

        self.db.log_action(
            "removed_file_recovery",
            f"Recovered {len(recovered)} of {len(rows)} removed files",
            user_initiated=True,
        )
        return recovered

    # ------------------------------------------------------------------
    # Discover new sources / mirrors
    # ------------------------------------------------------------------

    def discover_new_sources(self) -> Dict[str, List[str]]:
        """
        Search for new mirrors, repos, and sources of Epstein documents.
        Returns dict of source type -> list of discovered URLs.
        """
        self.logger.info("=== Discovering new sources ===")
        self._report_progress("Searching for new document sources...")
        discovered: Dict[str, List[str]] = {
            "github_repos": [],
            "archive_org_items": [],
            "reddit_links": [],
        }

        # GitHub repos
        gh = self.sources.get("github_mirror")
        if isinstance(gh, GitHubMirror):
            try:
                repos = gh.discover_related_repos()
                discovered["github_repos"] = repos
                self.logger.info("Discovered %d GitHub repos", len(repos))
            except Exception as exc:
                self.logger.error("GitHub discovery failed: %s", exc)

        # Archive.org -- search for related items
        session = _build_session()
        try:
            resp = _request_with_retries(
                session,
                "https://archive.org/advancedsearch.php",
                params={
                    "q": "epstein documents OR epstein files OR epstein doj",
                    "fl[]": "identifier,title",
                    "output": "json",
                    "rows": "50",
                },
            )
            data = resp.json()
            for doc in data.get("response", {}).get("docs", []):
                ident = doc.get("identifier", "")
                if ident:
                    item_url = f"https://archive.org/details/{ident}"
                    discovered["archive_org_items"].append(item_url)
            self.logger.info(
                "Discovered %d Archive.org items",
                len(discovered["archive_org_items"]),
            )
        except Exception as exc:
            self.logger.error("IA discovery failed: %s", exc)

        # Reddit -- additional subreddit scan
        reddit = self.sources.get("reddit")
        if isinstance(reddit, RedditCrawler):
            try:
                items = reddit.inventory()
                for item in items:
                    if not item.get("is_magnet"):
                        discovered["reddit_links"].append(item["url"])
                self.logger.info(
                    "Discovered %d Reddit links", len(discovered["reddit_links"])
                )
            except Exception as exc:
                self.logger.error("Reddit discovery failed: %s", exc)

        total = sum(len(v) for v in discovered.values())
        self.db.log_action(
            "source_discovery",
            f"Discovered {total} potential new sources",
            user_initiated=True,
        )
        self._report_progress(f"Discovery complete: {total} new sources found", pct=100)
        return discovered

    # ------------------------------------------------------------------
    # Full inventory across all sources
    # ------------------------------------------------------------------

    def full_inventory(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return the inventory from every enabled source."""
        result: Dict[str, List[Dict[str, Any]]] = {}
        for name, source in self.sources.items():
            try:
                result[name] = source.inventory()
            except Exception as exc:
                self.logger.error("Inventory failed for %s: %s", name, exc)
                result[name] = []
        return result

    # ------------------------------------------------------------------
    # Status / stats
    # ------------------------------------------------------------------

    def get_harvest_status(self) -> Dict[str, Any]:
        """Return current harvest status for the dashboard."""
        conn = self.db.get_connection()
        try:
            total_docs = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            by_source = conn.execute(
                "SELECT source, COUNT(*) as cnt FROM documents GROUP BY source"
            ).fetchall()
            removed_count = conn.execute(
                "SELECT COUNT(*) FROM removed_files"
            ).fetchone()[0]
            removed_recovered = conn.execute(
                "SELECT COUNT(*) FROM removed_files WHERE recovered = 1"
            ).fetchone()[0]
            datasets = conn.execute(
                "SELECT dataset_number, status, total_files FROM datasets ORDER BY dataset_number"
            ).fetchall()
        finally:
            conn.close()

        return {
            "total_documents": total_docs,
            "by_source": {r["source"]: r["cnt"] for r in by_source},
            "removed_files": removed_count,
            "removed_recovered": removed_recovered,
            "datasets": [dict(d) for d in datasets],
            "enabled_sources": list(self.sources.keys()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _report_progress(self, msg: str, pct: Optional[float] = None):
        self.logger.info(msg)
        if self.progress_cb:
            self.progress_cb({
                "source": "engine",
                "message": msg,
                "percent": pct,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    @staticmethod
    def _safe_filename(name: str) -> str:
        name = re.sub(r'[<>:"/\\|?*]', "_", name)
        name = name.replace("..", "_")
        name = name.strip(". ")
        _RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
            f"{d}{n}" for d in ("COM", "LPT") for n in range(1, 10)
        }
        stem = Path(name).stem.upper()
        if stem in _RESERVED:
            name = f"_{name}"
        if len(name) > 200:
            base, ext = os.path.splitext(name)
            name = base[:200] + ext
        return name or "_unnamed"


# ===================================================================
#  CLI entry point
# ===================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="harvester",
        description="EpsteinAnalyzer Document Harvester -- acquisition engine for "
                    "publicly released Epstein case documents.",
    )
    parser.add_argument(
        "--dataset", "-d",
        type=int,
        metavar="N",
        help="Download DOJ dataset number N (1-12).",
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Download from all enabled sources.",
    )
    parser.add_argument(
        "--scan-removed", "-r",
        action="store_true",
        help="Scan for files removed from DOJ (CRITICAL PRIORITY).",
    )
    parser.add_argument(
        "--recover-removed",
        action="store_true",
        help="Attempt to recover removed files from mirrors.",
    )
    parser.add_argument(
        "--discover-sources", "-s",
        action="store_true",
        help="Search for new mirrors, repos, and document sources.",
    )
    parser.add_argument(
        "--inventory", "-i",
        action="store_true",
        help="List available files from all sources (no download).",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print current harvest status.",
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to settings.yaml (default: config/settings.yaml).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging.",
    )

    args = parser.parse_args()

    if args.verbose:
        _console.setLevel(logging.DEBUG)

    # Progress callback for CLI: just print
    def cli_progress(event: dict):
        msg = event.get("message", "")
        pct = event.get("percent")
        if pct is not None:
            print(f"  [{pct:.0f}%] {msg}")
        else:
            print(f"  {msg}")

    engine = HarvesterEngine(config_path=args.config, progress_cb=cli_progress)

    if args.dataset:
        if not 1 <= args.dataset <= 12:
            print("Error: dataset number must be between 1 and 12.")
            sys.exit(1)
        paths = engine.download_dataset(args.dataset)
        print(f"\nDataset {args.dataset}: downloaded {len(paths)} files.")

    elif args.all:
        results = engine.download_all()
        for src, paths in results.items():
            print(f"  {src}: {len(paths)} files")
        total = sum(len(v) for v in results.values())
        print(f"\nTotal: {total} files from {len(results)} sources.")

    elif args.scan_removed:
        removed = engine.removed_file_scan()
        if removed:
            print(f"\n{'=' * 60}")
            print(f"ALERT: {len(removed)} files REMOVED from DOJ")
            print(f"{'=' * 60}")
            for rec in removed:
                snap_info = ""
                if rec.get("wayback_snapshots"):
                    snap_info = f" [{rec['wayback_snapshots']} Wayback snapshots]"
                print(f"  REMOVED -- CRITICAL: {rec['filename']}{snap_info}")
                print(f"    URL: {rec['original_url']}")
            print(f"{'=' * 60}")
        else:
            print("\nNo removed files detected.")

    elif args.recover_removed:
        recovered = engine.recover_removed_files()
        print(f"\nRecovered {len(recovered)} files.")
        for p in recovered:
            print(f"  {p}")

    elif args.discover_sources:
        discovered = engine.discover_new_sources()
        for category, urls in discovered.items():
            if urls:
                print(f"\n{category} ({len(urls)}):")
                for u in urls[:20]:
                    print(f"  {u}")
                if len(urls) > 20:
                    print(f"  ... and {len(urls) - 20} more")

    elif args.inventory:
        inv = engine.full_inventory()
        for src, items in inv.items():
            print(f"\n{src}: {len(items)} files")
            for item in items[:5]:
                print(f"  {item.get('filename', 'unknown')} -- {item.get('url', '')[:80]}")
            if len(items) > 5:
                print(f"  ... and {len(items) - 5} more")

    elif args.status:
        status = engine.get_harvest_status()
        print(f"\nHarvest Status ({status['timestamp']})")
        print(f"  Total documents: {status['total_documents']}")
        print(f"  By source:")
        for src, cnt in status["by_source"].items():
            print(f"    {src}: {cnt}")
        print(f"  Removed files detected: {status['removed_files']}")
        print(f"  Removed files recovered: {status['removed_recovered']}")
        print(f"  Enabled sources: {', '.join(status['enabled_sources'])}")
        print(f"\n  Datasets:")
        for ds in status["datasets"]:
            print(f"    Dataset {ds['dataset_number']}: {ds['status']} ({ds['total_files']} files)")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
