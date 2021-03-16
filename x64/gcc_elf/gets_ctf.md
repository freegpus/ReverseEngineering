## Parsons CTF Day 23: x64 BOF

A vulnerable application is hosted over a specific port and address. We just need to make it print a flag. We aren't trying to get a shell. Which is honestly easier, but I go over my attempt to try and get a shell as well. I say my attempt, because even though I'm unsuccessful, I believe it has something to do with how the file is hosted over AWS...

Anyways we are given the binary:

```bash
#file
day23_original: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=188533bbad38a2880c4edb46db3aa281375d30ca, not stripped
```

![checksec_day23](../screenshots/checksec_day23.png)



Giving it a test run we get:

![trial_day23](../screenshots\trial_day23.png)



So here's what we know:

1. NX is enabled = can't store/run shellcode in bufferspace
2. It's an elf, 64bit, not stripped
3. This means this is ripe for a ROP chain/gadget to point to the flag



### Disassembling in Ghidra

