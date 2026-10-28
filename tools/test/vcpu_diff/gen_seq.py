# Sequences of 1-4 allowed instructions, optionally followed by "jcc +1; inc bx". Record: 64B code | 8 u16 regs | u16 flags | u16 len
import random, struct, sys, capstone
random.seed(int(sys.argv[2])); N = int(sys.argv[1])
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
ALLOW = set("""add or adc sbb and sub xor cmp test inc dec neg not mul imul shl shr sar sal rol ror rcl rcr
mov lea xchg cbw cwd clc stc cmc cld std push pop movsb movsw stosb stosw lodsb lodsw cmpsb cmpsw scasb scasw
div idiv sahf""".split())
STR = {"movsb","movsw","stosb","stosw","lodsb","lodsw","cmpsb","cmpsw","scasb","scasw"}
def one():
    while True:
        raw = bytes(random.getrandbits(8) for _ in range(8))
        ins = list(md.disasm(raw, 0, 1))
        if not ins: continue
        i = ins[0]; mn = i.mnemonic.split()[-1]; b = i.bytes
        if mn not in ALLOW: continue
        if 0x66 in b[:3] or 0x67 in b[:3] or 0xF0 in b[:2]: continue
        if "fs:" in i.op_str or "gs:" in i.op_str: continue
        if mn in ("push","pop") and any(s in i.op_str for s in ("cs","ds","es","ss","fs","gs")): continue
        if mn == "pop" and i.op_str.strip() == "sp": continue
        if mn == "mov" and any(s in i.op_str for s in ("cs","ds","es","ss","fs","gs","cr","dr")): continue
        if b[0] in (0xF2,0xF3) and mn not in STR: continue
        if mn in ("div","idiv"):                 # operand must be a register or word memory; made safe by the runner's setup
            continue
        return bytes(b), b[0] in (0xF2,0xF3)
out = open("seq.bin","wb"); names = open("seq.txt","w")
for _ in range(N):
    code = b""; rep = False; desc = []
    for _k in range(random.randint(1,4)):
        b, r = one(); code += b; rep |= r; desc.append(b.hex())
    if random.random() < 0.8:
        cc = random.randrange(16); code += bytes([0x70 + cc, 0x01, 0x43]); desc.append("j%x+inc" % cc)
    regs = [random.getrandbits(16) for _ in range(8)]
    if rep: regs[2] = random.randint(0, 40); regs[4] = random.randint(0, 0xF000); regs[5] = random.randint(0, 0xF000)
    regs[7] = random.randrange(0x2000, 0xF000, 2)
    fl = 0x202 | (random.getrandbits(16) & 0x8D5)
    out.write(code.ljust(64, b"\x90") + struct.pack("<8HHH", *regs, fl, len(code)))
    names.write(" ".join(desc) + "\n")
