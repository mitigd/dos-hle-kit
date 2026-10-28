# Generates real-mode single-instruction test cases: cases.bin
# record = 16 bytes insn | u16 ax bx cx dx si di bp sp | u16 flags | u16 len  (little endian)
import random, struct, sys, capstone
random.seed(int(sys.argv[2]) if len(sys.argv) > 2 else 1)
N = int(sys.argv[1])
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16); md.detail = True
ALLOW = set("""add or adc sbb and sub xor cmp test inc dec neg not mul imul shl shr sar sal rol ror rcl rcr
mov lea xchg cbw cwd lahf sahf clc stc cmc cld std push pop pushf pusha popa movsb movsw stosb stosw lodsb lodsw
cmpsb cmpsw scasb scasw xlatb daa das aaa aas aam aad leave div idiv""".split())
STR = {"movsb","movsw","stosb","stosw","lodsb","lodsw","cmpsb","cmpsw","scasb","scasw"}
out = open("cases.bin", "wb"); names = open("cases.txt", "w")
stats = {}
n = 0
while n < N:
    raw = bytes(random.getrandbits(8) for _ in range(8))
    # bias the first byte toward valid-looking ALU/shift/mov opcodes
    insns = list(md.disasm(raw, 0, 1))
    if not insns: continue
    i = insns[0]
    mn = i.mnemonic.split()[-1]
    if mn not in ALLOW: continue
    b = i.bytes
    if any(p in (0x66, 0x67, 0xF0) for p in b[:i.prefix.count(0) + 4] if False): pass
    if 0x66 in b[:3] or 0x67 in b[:3] or 0xF0 in b[:2]: continue
    if any(x in ("fs","gs") for x in i.op_str.split(":")[:1]): continue
    if "fs:" in i.op_str or "gs:" in i.op_str: continue
    if mn in ("push","pop") and any(s in i.op_str for s in ("cs","ds","es","ss","fs","gs")): continue
    if "cs:" in i.op_str: pass
    if mn in ("pop",) and i.op_str.strip() in ("sp",): continue
    if mn in ("aam",) and b[-1] == 0: continue
    if mn in ("div","idiv"): continue                      # #DE possibilities: tested separately
    if mn == "mov" and any(s in i.op_str for s in ("cs","ds","es","ss","fs","gs","cr","dr")): continue
    if mn == "xchg" and "sp" in i.op_str: pass
    # rep prefix only on string ops
    if b[0] in (0xF2, 0xF3) and mn not in STR: continue
    rep = b[0] in (0xF2, 0xF3)
    regs = [random.getrandbits(16) for _ in range(8)]
    if rep: regs[2] = random.randint(0, 40)               # cx
    if mn in STR or rep:                                  # keep si/di away from the wrap for rep
        regs[4] = random.randint(0, 0xF000); regs[5] = random.randint(0, 0xF000)
    regs[7] = random.randrange(0x2000, 0xF000, 2)         # sp
    fl = 0x202 | (random.getrandbits(16) & 0x8D5)
    if mn in STR and random.random() < 0.5: fl &= ~0x400
    if "sp" in i.op_str.replace("sp", "sp ") and mn in ("push","pop"): pass
    rec = b.ljust(16, b"\x90") + struct.pack("<8HHH", *regs, fl, len(b))
    out.write(rec); n += 1; names.write(i.mnemonic + " " + i.op_str + "\n")
    stats[mn] = stats.get(mn, 0) + 1
print(len(stats), "mnemonics", file=sys.stderr)
