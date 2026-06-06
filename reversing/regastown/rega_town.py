import re
import string
import itertools


"""

^.{33}$
(?:^[\\x48][\\x54][\\x42]).*
^.{3}(\\x7b).*(\\x7d)$
^[[:upper:]]{3}.[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{4}[[:upper:]].{2}[[:upper:]].{3}[[:upper:]].{4}$(?:.*\\x5f.*)
(?:.[^0-9]*\\d.*){5}
.{24}\\x54.\\x65.\\x54.*
^.{4}[X-Z]\\d._[A]\\D\\d.................[[:upper:]][n-x]{2}[n|c].$
.{11}_T[h|7]\\d_[[:upper:]]\\dn[a-h]_[O]\\d_[[:alpha:]]{3}_.{5}

"""

# Producto acumulado de los valores ASCII de cada caracter.r"[X-Z]\d."
# Si el resultado coincide con el target, el segmento es valido.
def ascii_product(word, target):
    product = 1
    for char in word:
        product *= ord(char)
    return product == target

def matches_pattern(word, pattern):
    return re.fullmatch(pattern, word)

# Caracteres candidatos: letras + digitos (alfanumericos).
candidates = string.ascii_letters + string.digits

# Targets extraidos del assembly de check_input en Ghidra.
# Cada valor es el producto ASCII esperado del segmento correspondiente.
segment_targets = [
    0x7a070,    # segmento 1
    0x5c436,    # segmento 2
    0x6cc60,    # segmento 3
    0x27b5776,  # segmento 4
    0x10f9,     # segmento 5
    0xd76a0,    # segmento 6
    0x7465a58,  # segmento 7
]

# Patrones extraidos del regex de filter_input, uno por segmento.
# Cada regex restringe que caracteres son validos en esa posicion.
segment_patterns = [
    r"[X-Z]\d.",        # segmento 1: letra X-Z, digito, cualquier cosa
    r"[A]\D\d",         # segmento 2: 'A', no-digito, digito
    r"T[h|7]\d",        # segmento 3: 'T', h o 7, digito
    r"[A-Z]\dn[a-h]",   # segmento 4: mayuscula, digito, 'n', letra a-h
    r"[O]\d",           # segmento 5: 'O', digito
    r"T[A-Za-z0-9$]{2}",# segmento 6: 'T', dos alfanumericos
    r"[A-Z][n-x]{2}[n|c]", # segmento 7: mayuscula, dos letras n-x, n o c
]

# Longitudes de cada segmento segun los rangos de slices en Ghidra.
segment_lengths = [3, 3, 3, 4, 2, 3, 4]

# Para cada segmento, se prueban todas las combinaciones posibles
# el producto ASCII y el patron regex.
for target, pattern, length in zip(segment_targets, segment_patterns, segment_lengths):
    for combo in itertools.product(candidates, repeat=length):
        word = "".join(combo)
        if ascii_product(word, target) and matches_pattern(word, pattern):
            print(f"  {word}")
