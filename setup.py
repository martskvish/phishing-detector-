
#used AI to generate setup code to load the database with the data for the phishing detection

import sqlite3
import os

DB_PATH = "sus_keywords.db"

# ── Data ────────────────────────────────────────────────────────────────────

URL_CHARACTERS = [
    ('@',  'High',   15),
    ('-',  'Medium',  8),
    ('..', 'Medium',  5),
    ('%',  'Medium',  8),
    ('//', 'High',   12),
    ('?',  'Low',     3),
    ('=',  'Low',     2),
    ('&',  'Low',     2),
    ('#',  'Low',     3),
    ('~',  'Low',     4),
    ('_',  'Medium',  6),
    (';',  'Medium',  6),
    ('!',  'Low',     3),
    ('$',  'Low',     4),
    ('*',  'Low',     3),
    ('+',  'Low',     2),
]

URL_KEYWORDS = [
    ('secure',    'Medium',  6),
    ('login',     'High',   10),
    ('verify',    'High',   10),
    ('update',    'High',    8),
    ('account',   'Medium',  7),
    ('confirm',   'High',    8),
    ('signin',    'High',   10),
    ('bank',      'High',   10),
    ('paypal',    'High',   15),
    ('apple',     'High',   12),
    ('amazon',    'High',   12),
    ('microsoft', 'High',   12),
    ('google',    'High',   12),
    ('ebay',      'High',   10),
    ('support',   'Medium',  6),
    ('password',  'High',   10),
    ('reset',     'High',    8),
    ('alert',     'Medium',  5),
    ('suspended', 'High',    9),
    ('limited',   'Medium',  6),
    ('expire',    'Medium',  6),
    ('free',      'Low',     3),
    ('prize',     'Medium',  5),
    ('winner',    'Medium',  5),
    ('click',     'Low',     3),
    ('redirect',  'Medium',  7),
    ('token',     'Medium',  6),
    ('session',   'Medium',  5),
    ('checkout',  'High',    8),
    ('webscr',    'High',   12),
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

        CREATE TABLE IF NOT EXISTS url_suspicious_keywords (
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
        "INSERT INTO url_suspicious_keywords (keyword, severity, weight) VALUES (?, ?, ?)",
        URL_KEYWORDS
    )
    cursor.executemany(
        "INSERT INTO html_suspicious_phrases (keyword, severity, weight) VALUES (?, ?, ?)",
        HTML_PHRASES
    )


def print_summary(cursor):
    tables = [
        "url_suspicious_characters",
        "url_suspicious_keywords",
        "html_suspicious_phrases",
    ]
    print("\n--- Database Summary ---")
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"  {table}: {count} rows")
    print("------------------------\n")


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