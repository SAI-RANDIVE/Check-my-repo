"""Central configuration for CodeSentinel.

Every tunable (limits, TTLs, thresholds, feed URLs) lives here and can be
overridden with an environment variable prefixed ``CS_`` or a ``.env`` file.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_NAME = "CodeSentinel"
APP_VERSION = "1.0.0"


class Settings(BaseSettings):
    """Runtime settings, populated from ``CS_*`` environment variables."""

    model_config = SettingsConfigDict(env_prefix="CS_", env_file=PROJECT_ROOT / ".env", extra="ignore")

    # Storage
    data_dir: Path = PROJECT_ROOT / "data"
    database_url: str = ""

    # Web
    allow_local_paths: bool = True
    rate_limit_per_minute: int = 5
    log_level: str = "INFO"
    worker_threads: int = 2

    # Ingestion limits
    clone_timeout_seconds: int = 120
    max_repo_mb: int = 200
    max_upload_mb: int = 50
    max_zip_files: int = 20_000
    history_max_commits: int = 500
    max_file_bytes: int = 1_000_000

    # Threat intelligence
    osv_querybatch_url: str = "https://api.osv.dev/v1/querybatch"
    osv_vuln_url: str = "https://api.osv.dev/v1/vulns/{id}"
    epss_url: str = "https://api.first.org/data/v1/epss"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    github_api_url: str = "https://api.github.com"
    github_token: str = ""
    http_timeout_seconds: float = 30.0
    http_retries: int = 3
    http_concurrency: int = 16
    osv_batch_size: int = 500
    epss_batch_size: int = 100
    ttl_osv_query_hours: float = 12
    ttl_osv_vuln_hours: float = 24
    ttl_epss_hours: float = 24
    ttl_kev_hours: float = 24

    # Secret detection
    entropy_min_length: int = 20
    entropy_base64_threshold: float = 4.3
    entropy_hex_threshold: float = 3.0

    # Scoring
    score_normaliser: float = 10.0
    default_fail_on: str = "p0"

    @property
    def resolved_database_url(self) -> str:
        """SQLAlchemy URL, defaulting to a SQLite file inside ``data_dir``."""
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'codesentinel.db').as_posix()}"

    @property
    def scans_dir(self) -> Path:
        """Directory where per-scan export files are written."""
        return self.data_dir / "scans"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.scans_dir.mkdir(parents=True, exist_ok=True)
    return settings


def configure_logging(level: str | None = None) -> None:
    """Configure root logging once with a compact, grep-friendly format."""
    lvl = (level or get_settings().log_level).upper()
    logging.basicConfig(
        level=getattr(logging, lvl, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    for noisy in ("httpx", "httpcore", "git", "matplotlib", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
