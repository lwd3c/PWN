#!/usr/bin/env python3

from pwn import *

context.binary = exe = ELF("./chal", checksec = False)
p = process(exe.path)

while True:
    p.sendlineafter(b"email: \n", b'D')
    line = p.recvline()
    print(f"{line=}")

    if b"Congrats" in line:
        p.interactive()
        exit(0)

