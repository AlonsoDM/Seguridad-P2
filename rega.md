# Reversing

## Rega's Place

- Correr el binario:

![alt text](<images/rega1.png>)

- Ghidra:

![alt text](<images/rega2.png>)

En Rust, el patrón típico para leer input es algo así:

```rust
let mut user_input = String::new();
stdin().read_line(&mut user_input);
let trimmed = user_input.trim_end();
let result = filter_input(trimmed);
```

Entonces es probable que `local_168` sea el input del usuario que es pasado a `filter_input()`.

![alt text](<images/rega3.png>)

Ahora vemos la función `filter_input()` en Ghidra, se puede ver que es una función de validación sintáctica del input usando regex:

![alt text](<images/rega4.png>)
![alt text](<images/rega5.png>)



Aquí se puede ver que se está verificando el input string del usuario con un regex:

```
^.{33}$
(?:^[\x48][\x54][\x42]).*
^.{3}(\x7b).*(\x7d)$
^[[:upper:]]{3}.[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{4}[[:upper:]].{2}[[:upper:]].{3}[[:upper:]].{4}$(?:.*\x5f.*)
(?:.[^0-9]*\d.*){5}
.{24}\x54.\x65.\x54.*
^.{4}[X-Z]\d._[A]\D\d.................[[:upper:]][n-x]{2}[n|c].$
.{11}_T[h|7]\d_[[:upper:]]\dn[a-h]_[O]\d_[[:alpha:]]{3}_.{5}
```

Esto dice que:

- El passphrase debe tener longitud 33
- `\x48` = `'H'`, `\x54` = `'T'` y `\x42` = `'B'`: el string empieza con `"HTB"`

Continuando en Ghidra, se revisa la función `check_input()` que realiza una validación semántica usando productos ASCII. Pero no muestra todo porque Ghidra no pudo resolver esos valores. 


![alt text](<images/rega6.png>)

Sin embargo, podemos ver el código assembly. Además, Ghidra pone que `corr_values` literalmente dice "los valores correctos", entonces mirando el assembly corresponde a esto:

![alt text](<images/rega7.png>)

```
Valores = [0x7a070, 0x5c436, 0x6cc60, 0x27b5776, 0x10f9, 0xd76a0, 0x7465a58]
```

Los valores que se ven en el assembly son lo que se carga justo antes de que empiece la comparación. Por ejemplo `0x7a070 = 499824` en decimal, que corresponde a la primera palabra. Entonces se puede hacer un script que pruebe combinaciones hasta que dé estos valores. Ghidra está mostrando exactamente los valores contra los que se multiplican los ASCII de cada palabra. Cada target es el producto esperado de los caracteres de ese segmento:

```python
import re
import string
import itertools

def ascii_product(word, target):
    product = 1
    for char in word:
        product *= ord(char)
    return product == target

def matches_pattern(word, pattern):
    return re.fullmatch(pattern, word)

candidates = string.ascii_letters + string.digits

segment_targets = [
    0x7a070,    # segmento 1: chars [4..7]
    0x5c436,    # segmento 2: chars [8..11]
    0x6cc60,    # segmento 3: chars [12..15]
    0x27b5776,  # segmento 4: chars [16..20]
    0x10f9,     # segmento 5: chars [21..23]
    0xd76a0,    # segmento 6: chars [24..27]
    0x7465a58,  # segmento 7: chars [28..32]
]

segment_patterns = [
    r"[X-Z]\d.",        # segmento 1: letra X-Z, digito, cualquier cosa
    r"[A]\D\d",         # segmento 2: 'A', no-digito, digito
    r"T[h|7]\d",        # segmento 3: 'T', h o 7, digito
    r"[A-Z]\dn[a-h]",   # segmento 4: mayuscula, digito, 'n', letra a-h
    r"[O]\d",           # segmento 5: 'O', digito
    r"T[A-Za-z0-9$]{2}",# segmento 6: 'T', dos alfanumericos
    r"[A-Z][n-x]{2}[n|c]", # segmento 7: mayuscula, dos letras n-x, n o c
]

segment_lengths = [3, 3, 3, 4, 2, 3, 4]

print("Buscando segmentos validos...\n")

for target, pattern, length in zip(segment_targets, segment_patterns, segment_lengths):
    for combo in itertools.product(candidates, repeat=length):
        word = "".join(combo)
        if ascii_product(word, target) and matches_pattern(word, pattern):
            print(f"  {word}")
    # El separador indica el fin de un segmento (equivale al '_' en el flag)
    print(" ---")
```

**Resultado:**

```
alonso@alonso-Inspiron-7391:~/segu-p2$ python3 rega_town.py
Buscando segmentos validos...

  Y0u
  Y4l
  Y6h
  _
  Af9
  Ar3
  _
  Th3
  _
  K1ng
  _
  O7
  _
  Teh
  The
  _
  Town
  Twon
  _
```

**Flag:** `HTB{Y0u_Ar3_Th3_K1ng_O7_The_Town}`

![alt text](images/rega8.png)





