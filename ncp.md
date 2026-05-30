# Notebook Converter Pro

Este challenge de HTB da como descripcion "Welcome to NotebookConverter Pro, a tool for converting Jupyter notebooks into different formats with ease. While it appears simple and efficient, there may be more happening behind the scenes than meets the eye."

Primero se inicia el target host para ver de que trata el challenge.

![alt text](images/ncp1.png)

Despues de crea un usuario y hacer login se puede ver una pagina simple de conversion de cuadernos de jupiter a HTML o markdown.

Se descargo el codigo fuente para revisar mas cosas. Que se analizara:

```bash
$ ls
app  config  data  docker-compose.yml  Dockerfile  flag.txt  readflag.c
```

En `convert_job.py` la función encargada de convertir notebooks a HTML utiliza la opción embed_images de nbconvert:

```python
def convert_html(input_path, output_dir):
    exporter = nbconvert.HTMLExporter()
    exporter.embed_images = True
    body, _resources = exporter.from_filename(str(input_path))
    output_path = output_dir / f"{input_path.stem}.html"
    output_path.write_text(body, encoding="utf-8")
    return output_path
```
Cuando embed_images está habilitado, nbconvert busca cada imagen referenciada dentro del notebook, la lee desde el sistema de archivos y la incorpora al documento HTML mediante codificación Base64.

El problema es que no existe ninguna validación sobre las rutas especificadas en las referencias de imágenes. Como resultado, un atacante puede utilizar rutas relativas que apunten fuera del directorio esperado, por ejemplo:

`../../../../data/app.db`

Durante el proceso de conversión, nbconvert intentará leer dicho archivo y lo incrustará dentro del HTML generado. Esto permite acceder al contenido de archivos arbitrarios presentes en el servidor, constituyendo una vulnerabilidad de Arbitrary File Read (AFR). Este bug representa el primer paso de la explotación, ya que permite obtener información sensible almacenada en archivos internos de la aplicación.

Durante la inicialización de la aplicación, en `db.py`, se crea una cuenta administrativa con una contraseña generada aleatoriamente:

```python
ef reset_runtime_state():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if DB_PATH.exists():
        DB_PATH.unlink()

    if JOBS_DIR.exists():
        shutil.rmtree(JOBS_DIR)
    JOBS_DIR.mkdir(parents=True, exist_ok=True)

    admin_password = secrets.token_urlsafe(14)

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", admin_password, "admin"),
        )
        conn.executemany(
            "INSERT INTO settings (key, value) VALUES (?, ?)",
            [
                ("asset_storage_enabled", "0"),
            ],
        )
        conn.commit()

    return admin_password
```

Aunque la contraseña es generada utilizando un mecanismo criptográficamente seguro, esta se almacena directamente en la base de datos sin aplicar ningún algoritmo de hashing.

Como consecuencia, cualquier persona que obtenga acceso a la base de datos puede visualizar la contraseña administrativa en texto plano.

Este problema se vuelve especialmente crítico al combinarse con el problema anterior. Una vez que se logra leer el archivo de base de datos mediante la vulnerabilidad de lectura arbitraria, puede recuperar inmediatamente las credenciales del administrador y autenticarse con privilegios elevados.

La aplicación determina el método de almacenamiento de archivos generados mediante la siguiente función en `conversions.py`:

```python
def determine_storage_mode(output_format):
    if output_format == "markdown":
        return "saved_assets" if setting_enabled("asset_storage_enabled") else "single_file"
    return "single_file"
```
Cuando la opción `asset_storage_enabled` se encuentra habilitada, la aplicación utiliza el modo `saved_assets`, el cual emplea internamente la clase `FilesWriter` para almacenar archivos adjuntos. El acceso a esta funcionalidad está restringido a usuarios con privilegios administrativos. Por esta razón, primero se necesita tomar una cuenta de administrador antes de poder interactuar con este mecanismo.

Una vez obtenidos privilegios administrativos, se puede aprovechar una vulnerabilidad presente en el componente `FilesWriter`.Durante el almacenamiento de archivos adjuntos, `FilesWriter` construye la ruta de destino concatenando el directorio base con el nombre del archivo proporcionado por el usuario. Sin embargo, no realiza validaciones para detectar secuencias de path traversal como `../`.

Debido a ello, es posible crear archivos como: 

`../../../../app/converter/convert_job.py`

En lugar de almacenarse dentro del directorio previsto, el archivo termina sobrescribiendo componentes legítimos de la aplicación. En este caso, el atacante puede reemplazar el archivo `convert_job.py`, responsable de ejecutar tareas de conversión. Dado que dicho archivo será ejecutado por la aplicación en futuras conversiones, cualquier código introducido por el atacante será ejecutado automáticamente en el servidor.

Esto transforma la vulnerabilidad de Path Traversal en una vulnerabilidad de Remote Code Execution (RCE), permitiendo la ejecución arbitraria de comandos con los privilegios del proceso de la aplicación.