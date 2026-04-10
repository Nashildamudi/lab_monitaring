import sqlite3
import os

db_path = 'server/labmon.db'
if not os.path.exists(db_path):
    print(f"DB not found at {db_path}")
    exit(1)

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cur = conn.execute("SELECT id, command_type, status, ts FROM commands ORDER BY id DESC LIMIT 20")
rows = cur.fetchall()

print(f"{'ID':<5} | {'Type':<20} | {'Status':<10} | {'Timestamp'}")
print("-" * 60)
for r in rows:
    print(f"{r['id']:<5} | {r['command_type']:<20} | {r['status']:<10} | {r['ts']}")
