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
