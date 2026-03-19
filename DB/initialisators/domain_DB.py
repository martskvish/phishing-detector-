import sqlite3

# Read domains from text file
with open("DB/domain.txt", "r") as f:
    lines = [line.strip() for line in f.readlines()]

# Connect to database
conn = sqlite3.connect("DB/cert_domain.db")
cursor = conn.cursor()

# Create table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY,
        domain TEXT NOT NULL
    )
""")

# Insert all domains
for line in lines:
    # Split on tab to get id and domain
    parts = line.split("\t")
    id = int(parts[0])
    domain = parts[1]
    cursor.execute("INSERT INTO domains VALUES (?, ?)", (id, domain))

conn.commit()
conn.close()
print(f"Done! Loaded {len(lines)} domains into database.")