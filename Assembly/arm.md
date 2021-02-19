# ARM & MIPS

A company named Acorn Computers developed a 32-bit RISC architecture named
the Acorn RISC Machine (later renamed to Advanced RISC Machine) in the late
1980s. This architecture proved to be useful beyond their limited product line,
so a company named ARM Holdings was formed to license the architecture for
use in a wide variety of products. It is commonly found in embedded devices
such as cell phones, automobile electronics, MP3 players, televisions, and so on.



**<u>ARM:</u>** Because ARM is a RISC architecture, there are a few basic differences between
ARM and CISC architectures (x86/x64).

Return address not saved on stack, saved in link register (LR), BX LR causes execution to jump to that address

ARM uses a loadstore model for memory access. This means data must be moved from memory into registers before being operated on, and only load/store instructions can access memory. On ARM, this translates to the LDR and STR instructions. If you want to increment a 32-bit value at a particular memory address, you must fi rst load the value at that address to a register, increment it, and store it back. In contrast with x86, which allows most instructions to directly operate on data in memory, such a simple operation on ARM would require three instructions (one load, one increment, one store). This may imply that there is more code to read for the reverse engineer, but in practice it does not really matter much once you are used to it.

In ARM, privileges are defined
by eight different modes:
■ User (USR)
■ Fast interrupt request (FIQ)
■ Interrupt request (IRQ)
■ Supervisor (SVC)
■ Monitor (MON)
■ Abort (ABT)
■ Undefined (UND)
■ System (SYS)

**<u>MIPS:</u>** $0 to $31 or $V0, $A0, to $RA 

- The $2 (or $V0) register is used to store the function’s return value. LI stands for “Load Immediate” and is the MIPS equivalent to MOV.
- We must simply keep in mind that in MIPS, the instruction following a jump or branch instruction is executed before the jump/branch instruction itself.



**<u>ARM and MIPS are RISC architectures (mobile, saves power)</u>**:

ARM uses R0 for returning results of functions, MOV copies, does not move

Return 0 = XOR EAX, EAX

In Intel-syntax: <instruction> <destination operand> <source operand>.

In AT&T syntax: <instruction> <source operand> <destination operand>.

There are no Thumb and Thumb-2 modes in ARM64, only ARM, so there are 32-bit instructions only. The Register count is doubled: .2.4 on page 1337. 64-bit register have X- prefixes, while its 32-bit parts—W-.

ARM programs also use the stack for saving return addresses, but differently. As mentioned in “Hello, world!” ( 1.5.3 on page 24), the RA is saved to the LR (link register). If one needs, however, to call another function and use the LR register one more time, its value has to be saved. Usually it is saved in the function prologue.



