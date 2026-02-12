"""
EpsteinAnalyzer - Harvester Package
Document acquisition engine for publicly released Epstein case files.
"""

from harvester.harvester import (
    HarvesterEngine,
    DOJScraper,
    GitHubMirror,
    ArchiveOrgFetcher,
    ZenodoPuller,
    RedditCrawler,
    FOIAScanner,
    CourtListenerFetcher,
    TorrentEngine,
    StateCourtScraper,
)

__all__ = [
    "HarvesterEngine",
    "DOJScraper",
    "GitHubMirror",
    "ArchiveOrgFetcher",
    "ZenodoPuller",
    "RedditCrawler",
    "FOIAScanner",
    "CourtListenerFetcher",
    "TorrentEngine",
    "StateCourtScraper",
]
