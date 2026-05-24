def encode(one, two, three, four, five):
# one   → bits [27:24]  Operación: 1=MOV, 2=ADD, 3=SUB, 4=CMP
# two   → bits [23:20]  Siempre es 1 (validación interna de la VM)
# three → bits [19:16]  Registro destino: 0=a, 1=b, 2=c, 3=d
# four  → bits [15:12]  Tipo de operando: 0=inmediato, 1=registro
# five  → bits [11:0]   Si four=0: valor numérico directo, si four=1: registro fuente (en bits [11:8], ej: 0x100 = registro b)
    # se pone five & 0xfff para que no ocupe más de 12 bits y pise los bits de four
    return (one << 24) | (two << 20) | (three << 16) | (four << 12) | (five & 0xfff)

def verify(instrs): # Esto es el switch que se obtuvo de ghidra
    checks = [
        lambda x: (x & 0xf000000) == 0x2000000 and (x & 0xff0000) == 0x100000,
        lambda x: (x & 0xf000000) == 0x2000000 and (x & 0xfff) == 0x100,
        lambda x: (x & 0xf000000) == 0x3000000 and (x & 0xff0000) == 0x110000,
        lambda x: (x & 0xf000000) == 0x1000000 and (x & 0xff0000) == 0x120000,
        lambda x: (x & 0xf000000) == 0x4000000 and (x & 0xff0000) == 0x130000,
    ]
    for i, (instr, check) in enumerate(zip(instrs, checks)):
        ok = check(instr)
        print(f"  instr[{i}] = 0x{instr:08x}  → check {'SUCCESS' if ok else 'FAIL'}")

instrs = [
    encode(2, 1, 0, 0, 0x100),  # a = 0x100
    encode(2, 1, 0, 0, 0x100),  # a = 0x200
    encode(3, 1, 1, 0, 0x001),  # b = -1
    encode(1, 1, 2, 1, 0x100),  # c = -1 
    encode(4, 1, 3, 0, 0x000),  # flags = 0x10000000
]

print("Verificando checks de Ghidra:")
verify(instrs)

bytecode = "".join(f"{i:08x}" for i in instrs)
print(f"\nBytecode: {bytecode}")
print(f"Flag: HTB{{{bytecode}}}")