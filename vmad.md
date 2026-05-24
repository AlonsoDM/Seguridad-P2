
## Virtually mad

```bash
file virtually.mad
```

![alt text](<images/vmad1.png>)

```
virtually.mad: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=27b0820aa0b06b1dd720035f2e736a1a623d4450,
for GNU/Linux 4.4.0, stripped
```

El binario corresponde a un ejecutable ELF de 64 bits para Linux, compilado como PIE y además stripped.

![alt text](<images/vmad2.png>)

Correr el binario: Pide un codigo.

Utilizando Ghidra confirmamos información anterior. Una vez analizado, lo primero que hago es encontrar el `main` para entender qué hace exactamente este binario. `Entry` parece ser el que llama al "main" del programa.

![alt text](<images/vmad3.png>)

`Entry` es la función que inicia todo y llama a `FUN_00101754` que parece ser el corazón del programa.

![alt text](<images/vmad4.png>)

El main es `FUN_00101754`, y al analizarlo me di cuenta que el binario puede ser una VM debido a que un print dice "opcodes". Además, `UVar7` y `UVar3` hacen input parsing, y `strtol()` convierte un string a entero.

![alt text](<images/vmad5.png>)

La lógica general es:

- Leer una cadena ingresada por el usuario.
- Dividirla en bloques de 8 caracteres.
- Interpretar cada bloque como un opcode hexadecimal.
- Validar cada opcode según su posición.
- Ejecutar las instrucciones sobre un estado interno.
- Verificar si la VM termina en un estado específico.

El programa utiliza `__isoc99_scanf("%s", local_118);` y verifica que la longitud del input sea múltiplo de 8:

```c
if ((sVar5 & 7) == 0)
```

Cada bloque de 8 caracteres se convierte a hexadecimal usando `strtol()`. Por ejemplo:

```
02100001 -> 0x02100001
```

La cantidad de instrucciones se calcula como:

```
cantidad_opcodes = longitud / 8
```

![alt text](images/vmad8.png)

Cada opcode es validado dependiendo de su índice mediante un `switch`. En cada case hay una condicion: `if (((uVar3 & 0xf000000) != 0x2000000) || ((uVar3 & 0xff0000) != 0x100000))`

Este if valida que la instrucción (uVar3) tenga un formato específico usando máscaras de bits. La expresión (uVar3 & 0xf000000) extrae los bits [27:24], que normalmente representan el opcode principal, y verifica que su valor sea 0x2. Luego, (uVar3 & 0xff0000) extrae los bits [23:16] y comprueba que ese campo sea igual a 0x10. Como ambas condiciones están unidas con ||, el if se ejecuta si cualquiera de las dos validaciones falla; es decir, si el opcode no es 2 o si el campo [23:16] no contiene 0x10.

Los formatos esperados son:

| **Opcode** | **Formato** |
| --- | --- |
| #0 | `0210XXXX` |
| #1 | `02????100` |
| #2 | `0311XXXX` |
| #3 | `0112XXXX` |
| #4 | `0413XXXX` |

Además, los últimos 12 bits deben ser menores a `0x101`, o la instrucción es ignorada.

Los opcodes válidos se ejecutan mediante:

```c
FUN_001016aa(piVar4, opcode);
```

Esta función parece ser el núcleo de la VM y probablemente modifica registros o memoria interna.

![alt text](<images/vmad6.png>)

Después de ejecutar las instrucciones, el programa valida el estado final de la VM:

```
*piVar4      == 0x200
piVar4[1]    == -1
piVar4[2]    == -1
piVar4[3]    == 0
piVar4[0xc]  == 0x10000000
```

Además, el programa requiere exactamente 5 instrucciones.

Si todo se cumple, imprime:

```
This is the right answer! Validate the challenge with HTB{input}
```

El reto consiste en construir una secuencia válida de 5 opcodes que lleve la VM al estado esperado.

El siguiente paso del análisis es estudiar la función `FUN_001016aa`, ya que contiene la lógica real de ejecución de la máquina virtual. `FUN_001016aa` implementa un dispatch table: usa los bits `[27:24]` del opcode como índice en un array de function pointers para llamar la instrucción correcta.

![alt text](images/vmad9.png)

| Bits `[27:24]` | Función        | Operación |
| -------------- | -------------- | --------- |
| `1`            | `FUN_00101322` | `MOV`     |
| `2`            | `FUN_001013e9` | `ADD`     |
| `3`            | `FUN_001014c6` | `SUB`     |
| `4`            | `FUN_001015bd` | `CMP`     |

En `(*apcStack_68[(int)(param_2 >> 0x18)])(param_1, param_2);`

0x18 = 24, entonces el índice de la operación está en los bits [31:24]. Pero los checks del switch en main muestran que solo los bits [27:24] importan (& 0xf000000), así que el nibble alto efectivo es [27:24].

![alt text](images/vmad10.png)
![alt text](images/vmad11.png)
![alt text](images/vmad12.png)
![alt text](images/vmad13.png)

Analizando las sub-funciones se puede extraer el layout completo de un opcode de 32 bits. Por ejemplo en `FUN_001013e9`:

```c
if (((int)param_2 >> 0x14 & 0xfU) != 1)   // bits [23:20]
uVar1 = (int)param_2 >> 0x10 & 0xf;       // bits [19:16]
uVar2 = (int)param_2 >> 0xc  & 0xf;       // bits [15:12]
local_1c = param_2 & 0xfff;               // bits [11:0]
```

Este es el layout completo del opcode:

```
bits [27:24]
bits [23:20] 
bits [19:16]
bits [15:12]
bits [11:0]
```

### Solución

Del main tenemos que:

![alt text](images/vmad14.png)

Hay que asignar a los registros valores para que el estado objetivo tras 5 instrucciones sea:

```
a = 0x200,  b = -1,  c = -1,  d = 0,  flags = 0x10000000
```

Todo parte en cero. Los constraints del `switch` fijan casi completamente cada instrucción, solo hay que rellenar los campos libres para alcanzar el estado objetivo:

| # | Constraint del `switch`              | Instrucción elegida    | Efecto              |
|---|--------------------------------------|------------------------|---------------------|
| 0 | `one=2`, `three=0`                  | `ADD a, 0x100`         | `a = 0x100`         |
| 1 | `one=2`, `five=0x100`              | `ADD a, 0x100`         | `a = 0x200`        |
| 2 | `one=3`, `three=1`                  | `SUB b, 1`             | `b = -1`           |
| 3 | `one=1`, `three=2`, `four=1`                  | `MOV c, b` (irflag=1)  | `c = -1`           |
| 4 | `one=4`, `three=3`                  | `CMP d, 0`             | `flags = 0x10000000` |

---

### Script Python

```python
def encode(one, two, three, four, five):
    return (one << 24) | (two << 20) | (three << 16) | (four << 12) | (five & 0xfff)

instrs = [
    encode(2, 1, 0, 0, 0x100),  # a = 0x100
    encode(2, 1, 0, 0, 0x100),  # a = 0x200
    encode(3, 1, 1, 0, 0x001),  # b = -1
    encode(1, 1, 2, 1, 0x100),  # c = -1 
    encode(4, 1, 3, 0, 0x000),  # flags = 0x10000000
]

bytecode = "".join(f"{i:08x}" for i in instrs)
print(f"Flag: HTB{{{bytecode}}}")
```

![alt text](images/vmad15.png)

Output:

```
Flag: HTB{0210010002100100031100010112110004130000}
```

Puntos: 30 pts
![alt text](images/vmad16.png)