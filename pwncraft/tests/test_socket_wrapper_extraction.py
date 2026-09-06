from pwncraft.features.audit.extract import extract_exploit_ir


def test_class_socket_wrapper_exposes_sendall_and_recv() -> None:
    source = r'''
class Conn:
    def recv_line(self):
        chunk = self.s.recv(4096)
        return chunk

    def send_cmd(self, cmd):
        self.s.sendall((cmd + "\\n").encode())
        return self.recv_line()


def exploit(c):
    return c.send_cmd("SNAP")


def main():
    return exploit(Conn())
'''
    ir, error = extract_exploit_ir(source)
    assert error is None

    sends = [i for i in ir.interactions if i.action == "SEND"]
    recvs = [i for i in ir.interactions if i.action == "RECV"]
    assert sends
    assert any("SNAP" in i.value for i in sends)
    assert recvs
    assert any(i.length == 4096 for i in recvs)


def test_sendall_is_not_promoted_to_sendline() -> None:
    source = "sock.sendall(b'ABC')\n"
    ir, error = extract_exploit_ir(source)
    assert error is None
    assert [(i.action, i.value) for i in ir.interactions] == [("SEND", "b'ABC'")]
