# Reverse Engineering

**<u>Downloading Ghidra for Linux:</u>** 

```bash
wget https://ghidra-sre.org/ghidra_9.1.2_PUBLIC_20200212.zip
unzip ghidra_9.1.2_PUBLIC_20200212.zip
sudo apt install openjdk-11-jdk
cd ghidra_9.1.2_PUBLIC/
./ghidraRun
```



## C, ROP, RTOS Concepts

Everything related to C reverse engineering [here](./C_Concepts/c.md)

Return Oriented Programming (ROP) [here](./ROP/rop.md)

RTOS [here](./RTOS/rtos.md)

## Tools & Techniques

**Quick Commands:**

```bash
#for anything embedded
foremost [file]
binwalk -dd ".*" [file]
binwalk -e [file]
#architecture
binwalk -A 

#more RE commands
checksec [file]
strings [file]
rabin2 -zzq [file]
strace [file]
#for tracing library calls
ltrace [file]
objdump [file]
```

![inetsim](./screenshots/inetsim.png)

![inetsim2](./screenshots/inetsim2.png)



## CPU, Memory, Architectures & Assembly Instructions

For indepth Assembly instruction breakdown [here](./Assembly/assembly.md)

ARM & MIPS [**<u>here</u>**](./Assembly/arm.md)

x86 Concepts [here](./x86/x86.md)

x64 Concepts [here](./x64/x64.md)

<u>X86</u> – 8 general purpose registers. x86 supports the concept of privilege separation through an abstraction called ring level. The processor supports four ring levels, numbered from 0 to 3. (Rings 1 and 2 are not commonly used so they are not discussed here.) Ring 0 is the highest privilege level and can modify all system settings. Ring 3 is the lowest privileged level and can only read/modify a subset of system settings.

<u>X86-64</u> – 16 general purpose registers

<u>Arm</u> – 16 registers 32-bit general-purpose registers, numbered
R0, R1, R2, . . . , R15. While all of them are available to the application programmer,
in practice the first 12 registers are for general-purpose usage (such as
EAX, EBX, etc., in x86) and the last three have special meaning in the architecture, RISC CPU, encoded in 4 bytes

<u>Hex</u> = 0..9 + A..F, each hex digit is 4 bits, prepended with 0x, or h added to end

<u>Binary</u> = prepended with 0b, or b added to end

<u>Octal</u> = 0..7 mapped to 3 bits, think chmod

<u>thunk function</u>: Tiny function with a single role: call another function.

<u>Heap</u>: global variables, free floating memory

![packing](./screenshots/packing.png)

![main_mem](./screenshots/main_mem.png)

## Windows Specific RE

Windows specific RE [here](./Windows/windows.md)



## Example Walkthroughs

RTOS: [Belkin F9K1001](https://github.com/a-rey/reverse_engineering/blob/master/F9K1001/F9K1001_v5_03.21.md)