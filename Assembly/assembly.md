# Assembly



![mov](./screenshots/mov.png)



![lea](./screenshots/lea.png)



#### Shifting Instructions

![shifting](./screenshots/shifting.png)



#### Conditional Jumps

![jumps](./screenshots/jumps.png)

<u>LEA (Load Effective Address) instruction</u> is a way of obtaining the address which arises from any of the Intel processor's memory addressing modes. it moves the contents of the designated memory location into the target register.



### Function Prologues/Epilogues

A function prologue is a sequence of instructions at the start of a function. It often
looks something like the following code fragment:

```assembly
push ebp
mov ebp, esp
sub esp, X
```

What these instruction do: save the value of the EBP register on the stack, set the
value of the EBP register to the value of the ESP and then allocate space on the stack
for local variables of `X` bytes.

The value in the EBP stays the same over the period of the function execution and is
to be used for local variables and arguments access. For the same purpose one can
use ESP, but since it changes over time this approach is not too convenient.

The function epilogue frees the allocated space in the stack, returns the value in the
EBP register back to its initial state and returns the control flow to the caller:

```assembly
mov esp, ebp
pop ebp
ret 0
```



### What Hello World Looks Like

**<u>C/C++ code:</u>**

```c
#include <stdio.h>
int main()
{
printf("hello, world\n");
return 0;
}
```

**<u>GCC x86 compiler on linux:</u>**

```assembly
main proc near
        var_10 = dword ptr -10h
        push ebp
        mov ebp, esp
        and esp, 0FFFFFFF0h
        sub esp, 10h
        mov eax, offset aHelloWorld ; "hello, world\n"
        mov [esp+10h+var_10], eax
        call _printf
        mov eax, 0
        leave
        retn
main endp
```

The address of the hello, world string (stored in the data segment) is loaded in the EAX register first, and then saved onto the stack.

In addition, the function prologue has AND ESP, 0FFFFFFF0h —this instruction aligns
the ESP register value on a 16-byte boundary. This results in all values in the stack
being aligned the same way (The CPU performs better if the values it is dealing with
are located in memory at addresses aligned on a 4-byte or 16-byte boundary).
SUB ESP, 10h allocates 16 bytes on the stack. Although, as we can see hereafter,
only 4 are necessary here. This is because the size of the allocated stack is also aligned on a 16-byte boundary.

The string address (or a pointer to the string) is then stored directly onto the stack
without using the PUSH instruction. var_10 —is a local variable and is also an argument
for printf().

**<u>GCC x86-64 on Linux:</u>**

```assembly
.string "hello, world\n"
main:
        sub rsp, 8
        mov edi, OFFSET FLAT:.LC0 ; "hello, world\n"
        xor eax, eax ; number of vector registers passed
        call printf
        xor eax, eax
        add rsp, 8
        ret
```

The first 6 arguments are passed in the RDI, RSI, RDX, RCX, R8, and R9 registers, and
the rest—via the stack.

So the pointer to the string is passed in EDI (the 32-bit part of the register). Why
doesn’t it use the 64-bit part, RDI?

It is important to keep in mind that all MOV instructions in 64-bit mode that write
something into the lower 32-bit register part also clear the higher 32-bits



**<u>GCC ARM64:</u>**

```assembly
0000000000400590 <main>:
    400590: a9bf7bfd stp x29, x30, [sp,#-16]!
    400594: 910003fd mov x29, sp
    400598: 90000000 adrp x0, 400000 <_init-0x3b8>
    40059c: 91192000 add x0, x0, #0x648
    4005a0: 97ffffa0 bl 400420 <puts@plt>
    4005a4: 52800000 mov w0, #0x0 // #0
    4005a8: a8c17bfd ldp x29, x30, [sp],#16
    4005ac: d65f03c0 ret
 ...
Contents of section .rodata:
	400640 01000200 00000000 48656c6c 6f210a00 ........Hello!..
```

There are no Thumb and Thumb-2 modes in ARM64, only ARM, so there are 32-bit
instructions only.

The STP instruction (Store Pair) saves two registers in the stack simultaneously: X29
and X30. The exclamation mark (“!”) after the operand means that 16 is to be subtracted from SP first, and only then are values from register pair to be written into the stack. This is also called pre-index.

The second instruction copies SP in X29 (or FP). This is made so to set up the function
stack frame. ADRP and ADD instructions are used to fill the address of the string “Hello!” into the X0 register, because the first function argument is passed in this register.