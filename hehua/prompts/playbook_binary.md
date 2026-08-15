# Binary playbook (weight 15% — baseline)

1. `file`, `strings`, `checksec` (pwntools), `objdump -d` / gdb for basics.
2. Classify: format string / bof / UAF / integer / logic.
3. pwn: pwntools templates — leak libc via GOT/puts, ret2libc/ROP; canary leak
   via format string; one-gadget when libc given.
4. Reverse: trace input transforms in gdb/python; solve with z3-solver;
   extract flag from transformed output.
5. Timebox hard: if no primitive in 60% budget, notes(failure) + finish.

## z3 is BAKED IN — encode the transform, don't hand-guess (f2-05 lesson)

Once you have reversed a keygen / XOR-stream / custom-VM transform, STOP trying
periods and byte guesses by eye — model it as constraints and let z3 solve:

```python
from z3 import *
s = Solver()
N = 40                                   # recovered flag length
f = [BitVec(f"f{i}", 8) for i in range(N)]
for i, c in enumerate(b"flag{"): s.add(f[i] == c)   # known plaintext
s.add(f[-1] == ord("}"))
# ...encode each transform step over f[] (XOR key bytes, S-box lookups,
#    add/mul/rotate, VM opcode effects) as constraints...
if s.check() == sat:
    m = s.model()
    print(bytes(m[f[i]].as_long() for i in range(N)))
```

- Byte-wise XOR/stream cipher: known-plaintext (`flag{` prefix, `}` suffix)
  usually recovers the keystream directly — no solver needed once you have it.
- Custom opcode VM: execute the dispatcher SYMBOLICALLY over a BitVec input
  buffer, then assert the final check; z3 inverts the whole program.
- If z3 can't model a step within ~20% budget, fall back to brute-forcing only
  the REDUCED keyspace you derived (never the full raw space).
6. MANDATORY fuzz pattern for TCP services: ONE python script that loops a
   length/byte matrix (boundaries ±32 around every observed threshold,
   negative/0xFFFF/oversize, format specifiers, unicode lengths), diffs
   responses (status/len/leaked bytes) and prints anomalies as a table.
   Interactive one-off probes are for understanding the protocol ONLY;
   the exploit hunt itself must be script-driven.
7. Length sweeps go SMALL FIRST: 8/16/32/64/128/256/512/1024 BEFORE 4096+.
   Off-by-one and heap bugs live at small struct/buffer sizes (run-6661
   f1-01: the bug was a 64-byte token buffer; the hunt fixated on the 4096
   line buffer and died). For every N where behavior changes, also test
   exactly N, N-1, N+1 with a trailing NUL/newline variant.
8. Never explore the agent workspace for challenge content: in the hosted
   sandbox `/app` is YOUR OWN install (hehua code/state/logs) — it contains
   zero challenge material. Challenge files live only on the remote target.

## Cross-challenge binary comparison (f2-05 lesson — Cairn_X used 83 sessions)

When stuck on a binary challenge (f2-*), consider that sibling challenges in
the same family often share the same protection scheme with different keys:

1. **Check NOTES.md for sibling patterns**: if you solved f2-08 and this is
   f2-05, look for "password", "XTEA", "key", "rodata" in prior notes.
2. **Systematic binary comparison workflow**:
   ```bash
   # Extract key material regions
   readelf -S <binary> | grep -E '\.rodata|\.data'
   objdump -s -j .rodata <binary> | head -20
   objdump -s -j .data <binary> | head -20
   # Look for embedded passwords/keys (often at rodata ^ offset)
   strings <binary> | grep -iE 'pass|key|admin|flag|secret'
   # Check for crypto constants (XTEA delta=0x9E3779B9, TEA, AES s-box)
   objdump -d <binary> | grep -E '0x9e3779b9|ror|rol|xor' | head -10
   ```
3. **Common f2-* pattern**: password stored in `.rodata` at offset ^ 0x4b,
   XTEA/TEA key extracted from LE32 constants in `.data` (e.g., 0x4048-0x4057),
   flag encrypted at a fixed offset. Write a decrypt script:
   ```python
   import struct
   def rol(x, n): return ((x << (n&31)) | (x >> (32-(n&31)))) & 0xFFFFFFFF
   def xtea_decrypt(v0, v1, key):
       delta=0x9E3779B9; s=delta*32
       for _ in range(32):
           v1 -= ((v0<<4)+key[2]) ^ (v0+s) ^ ((v0>>5)+key[3])
           v0 -= ((v1<<4)+key[0]) ^ (v1+s) ^ ((v1>>5)+key[1])
           s -= delta
       return v0, v1
   ```

## Automated reversing workflow (don't hand-read disassembly line by line)

1. **Check for debug symbols first**: `readelf -sW <binary> | grep -v UND` —
   if symbols exist, jump straight to the validation function.
2. **Find the check/validation logic**: look for the function that reads stdin
   or compares output:
   ```bash
   objdump -d <binary> | grep -B5 -A20 'cmp\|test\|jne\|je ' | head -60
   # Or search for specific crypto patterns
   objdump -d <binary> | grep -c 'xor\|rol\|ror\|shl\|shr'  # crypto indicator
   ```
3. **Ltrace/strace if available**: `ltrace ./binary` or `strace ./binary` to
   see library calls (malloc/free/strcmp etc.)
4. **Python emulation**: don't just READ the disassembly — write a Python script
   that emulates the transform, then invert it or z3 it.
5. **Use pwntools' disasm**: `from pwn import *; print(disasm(open('bin','rb').read()))`
6. **Radare2 (if installed)**: much faster for navigation:
   ```bash
   r2 -q -c 'aaa; afl' <binary>       # analyze + list functions
   r2 -q -c 'aaa; pdf @ main' <binary> # decompile main
   r2 -q -c 'aaa; iz~flag' <binary>    # find flag in strings
   r2 -q -c 'aaa; /a xor' <binary>     # find XOR patterns
   ```
7. **ltrace/strace (if installed)**: see what the binary actually does:
   ```bash
   ltrace ./binary                    # library calls (strcmp, malloc)
   strace ./binary                    # syscalls (open, read, write)
   ```
