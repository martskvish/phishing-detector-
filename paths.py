"""Shared filesystem paths for the phishing detector application.

The application code lives in this repository, but database/state files are kept
outside the repository by default so local SQLite databases and feed files do not
get committed. On Linux, an app checked out at::

    /home/phishing_detector/phishing-detector-

will use::

    /home/phishing_detector/db/DB

You can override that location with the ``PHISHING_DETECTOR_DB_DIR`` environment
variable if a deployment needs a different external database directory.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Keep mutable database files outside the source tree. The default mirrors the
# user's Linux layout: a sibling ``db/DB`` directory next to this repository.
_DEFAULT_EXTERNAL_DB_DIR = BASE_DIR.parent / "db" / "DB"
DB_DIR = Path(os.environ.get("PHISHING_DETECTOR_DB_DIR", _DEFAULT_EXTERNAL_DB_DIR)).expanduser().resolve()
INITIALISERS_DIR = DB_DIR / "initialisators"

CREDS_ENV_PATH = BASE_DIR / "creds.env"
USERS_DB_PATH = DB_DIR / "users.db"
SUSPICIOUS_KEYWORDS_DB_PATH = DB_DIR / "sus_keywords.db"
CERTIFIED_DOMAINS_PATH = INITIALISERS_DIR / "domain.txt"
OPENPHISH_FEED_PATH = INITIALISERS_DIR / "phis_url.txt"
