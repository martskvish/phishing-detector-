#used AI to generate setup code to load the database with the data for the phishing detection

import sqlite3
import os

DB_PATH = "DB/sus_keywords.db"

# ── Data ────────────────────────────────────────────────────────────────────

URL_CHARACTERS = [
    ('@',   'High',   15),  # hides real domain e.g. google.com@evil.com
    ('%',   'High',   10),  # URL encoding used to hide malicious content
    ('..',  'High',   10),  # directory traversal
    ('//',  'Medium',  6),  # double slash after protocol
    (';',   'Medium',  6),  # uncommon in URLs
    ('|',   'High',   10),  # very suspicious
    ('`',   'High',   10),  # very suspicious
    ('~',   'Medium',  5),  # uncommon
    ('$',   'Medium',  5),  # uncommon
    ('!',   'Medium',  5),  # uncommon in URLs
    ('*',   'High',    8),  # wildcard, suspicious
    (',',   'Medium',  5),  # uncommon in URLs
]

SUBDOMAIN_KEYWORDS = [
    ('login',        'High',   10),
    ('signin',       'High',   10),
    ('sign-in',      'High',   10),
    ('secure',       'High',    8),
    ('verify',       'High',    9),
    ('account',      'Medium',  6),
    ('update',       'High',    8),
    ('confirm',      'High',    8),
    ('banking',      'High',   10),
    ('support',      'Medium',  6),
    ('authenticate', 'High',   10),
    ('portal',       'Medium',  6),
    ('admin',        'High',    9),
    ('mail',         'Medium',  5),
    ('webmail',      'High',    8),
    ('safe',         'Medium',  6),
    ('security',     'High',    8),
    ('helpdesk',     'Medium',  6),
    ('alerts',       'High',    8),
    ('paypal',       'High',   15),
    ('apple',        'High',   12),
    ('amazon',       'High',   12),
    ('microsoft',    'High',   12),
    ('google',       'High',   12),
    ('ebay',         'High',   10),
    ('netflix',      'High',   10),
    ('facebook',     'High',   10),
    ('finance',      'High',   10),
]

PATH_KEYWORDS = [
    # Account related
    ('login',        'High',   10),
    ('signin',       'High',   10),
    ('sign-in',      'High',   10),
    ('verify',       'High',    9),
    ('confirm',      'High',    8),
    ('reset',        'High',    8),
    ('password',     'High',   12),
    ('credential',   'High',   12),
    ('update',       'High',    8),
    ('recover',      'High',    8),
    ('unlock',       'High',    8),

    # Financial
    ('checkout',     'High',    8),
    ('payment',      'High',    8),
    ('billing',      'High',    8),
    ('invoice',      'High',    8),
    ('refund',       'High',    8),
    ('wallet',       'High',    8),

    # Technical suspicious
    ('webscr',       'High',   12),
    ('wp-admin',     'High',   12),
    ('admin',        'High',    9),
    ('redirect',     'High',    9),
    ('token',        'Medium',  6),
    ('session',      'Medium',  5),
    ('suspended',    'High',   10),
    ('alert',        'High',    8),
    ('support',      'Medium',  6),
    ('portal',       'Medium',  6),
    ('submit',       'Medium',  5),
    ('authenticate', 'High',   10),
]

HTML_PHRASES = [
    ('urgent action required',  'Critical', 20),
    ('verify your account',     'Critical', 20),
    ('confirm your identity',   'Critical', 18),
    ('account suspended',       'Critical', 18),
    ('update your details',     'High',     15),
    ('confirm your password',   'Critical', 20),
    ('security alert',          'High',     12),
    ('your account will be',    'High',     12),
    ('click here immediately',  'High',     10),
    ('limited time offer',      'Medium',    7),
    ('you have been selected',  'Medium',    6),
    ('congratulations',         'Medium',    6),
    ('sign in to continue',     'High',     10),
    ('enter your details',      'High',     10),
    ('re-enter your password',  'Critical', 18),
    ('we have detected',        'High',     10),
    ('your account has been',   'High',     10),
    ('reset your password',     'High',      9),
    ('one-time password',       'High',     10),
    ('bank details',            'Critical', 20),
    ('credit card',             'Critical', 18),
    ('social security',         'Critical', 20),
    ('date of birth',           'High',     10),
    ('billing information',     'Critical', 18),
    ('act now',                 'Medium',    6),
    ('expires in',              'Medium',    6),
    ('free gift',               'Low',       4),
    ('unsubscribe',             'Low',       3),
    ('privacy policy',          'Low',       2),
    ('24 hours',                'Medium',    6),
    ('limited offer',           'Medium',    6),
    ('phishing',                'Critical', 20),
    ('free',                    'Low',       4),
    # Added
    ('verify your identity',    'Critical', 20),
    ('enter your password',     'Critical', 18),
    ('your card has been',      'Critical', 18),
    ('unusual activity',        'High',     12),
    ('suspicious activity',     'High',     12),
    ('click the link below',    'High',     10),
    ('your account expires',    'High',     10),
    ('winner',                  'Medium',    6),
    ('prize',                   'High',      8),
    ('you have won',            'High',      8),
]

# ── Setup ────────────────────────────────────────────────────────────────────

def create_tables(cursor):
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS url_suspicious_characters (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword  TEXT    NOT NULL,
            severity TEXT    NOT NULL,
            weight   INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS url_subdomain_keywords (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword  TEXT    NOT NULL,
            severity TEXT    NOT NULL,
            weight   INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS url_path_keywords (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword  TEXT    NOT NULL,
            severity TEXT    NOT NULL,
            weight   INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS html_suspicious_phrases (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword  TEXT    NOT NULL,
            severity TEXT    NOT NULL,
            weight   INTEGER NOT NULL
        );
    """)


def insert_data(cursor):
    cursor.executemany(
        "INSERT INTO url_suspicious_characters (keyword, severity, weight) VALUES (?, ?, ?)",
        URL_CHARACTERS
    )
    cursor.executemany(
        "INSERT INTO url_subdomain_keywords (keyword, severity, weight) VALUES (?, ?, ?)",
        SUBDOMAIN_KEYWORDS
    )
    cursor.executemany(
        "INSERT INTO url_path_keywords (keyword, severity, weight) VALUES (?, ?, ?)",
        PATH_KEYWORDS
    )
    cursor.executemany(
        "INSERT INTO html_suspicious_phrases (keyword, severity, weight) VALUES (?, ?, ?)",
        HTML_PHRASES
    )


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"Existing '{DB_PATH}' removed.")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    create_tables(cursor)
    insert_data(cursor)
    conn.commit()

    print(f"Database '{DB_PATH}' created successfully.")
    print_summary(cursor)

    conn.close()


if __name__ == "__main__":
    main()