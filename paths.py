"""Shared filesystem paths for the phishing detector application.

All paths are resolved from the repository/application directory so the app can be
started from any working directory on a Linux server.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_DIR = BASE_DIR / "DB"
INITIALISERS_DIR = DB_DIR / "initialisators"

CREDS_ENV_PATH = BASE_DIR / "creds.env"
USERS_DB_PATH = DB_DIR / "users.db"
SUSPICIOUS_KEYWORDS_DB_PATH = DB_DIR / "sus_keywords.db"
CERTIFIED_DOMAINS_PATH = INITIALISERS_DIR / "domain.txt"
OPENPHISH_FEED_PATH = INITIALISERS_DIR / "phis_url.txt"
