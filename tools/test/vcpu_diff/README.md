# vcpu_diff: real-mode differential test for the JIT

Runs random real-mode (16-bit) code on `kvm` (the reference CPU) and on `jit` from identical state
and compares registers, defined flags and 192 KB of memory. It exists because the JIT's real-mode
path was never exercised by a game until `gr-hle`; it found `lea`, `std`, `leave`, `push sp` and
string-op segment-override bugs that no unit-sized check would have.

```bash
cd tools/test/vcpu_diff
pip install capstone
python3 gen_single.py 60000 11        # one instruction per case  -> cases.bin / cases.txt
python3 gen_seq.py 40000 5            # 1-4 instructions, often ending in jcc -> seq.bin / seq.txt
g++ -std=c++20 -O1 -I../../../include run_single.cpp ../../../build/libhlekit.a \
    ../../../build/libhlekit_cpu_deps.a -lpthread -o run_single
g++ -std=c++20 -O1 -I../../../include run_seq.cpp ../../../build/libhlekit.a \
    ../../../build/libhlekit_cpu_deps.a -lpthread -o run_seq
./run_single 30      # prints the first 30 mismatches and a per-mnemonic summary
./run_seq 30
```

Needs `/dev/kvm`. Flags undefined by the architecture (shift OF, mul SF/ZF, BCD) are masked.

Known gaps (reported, not hidden): `daa`, `das`, `aaa`, `aas` are not implemented by the JIT, and
`xlat` does not wrap `BX + AL` at 64 KB. `div`/`idiv` and control flow other than `jcc` are not covered.
