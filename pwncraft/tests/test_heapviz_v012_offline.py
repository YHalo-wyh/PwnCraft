from __future__ import annotations


def test_offline_semantic_closure_never_touches_network(monkeypatch) -> None:
    import socket
    import urllib.request

    from pwncraft.features.heapviz.contracts import HelperContractResolver, lower_source_calls
    from pwncraft.features.heapviz.semantics import evaluate_value

    def forbidden(*_args, **_kwargs):
        raise AssertionError("network access forbidden in offline semantic closure")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    try:
        import requests

        monkeypatch.setattr(requests.sessions.Session, "request", forbidden)
    except ImportError:
        pass
    try:
        import httpx

        monkeypatch.setattr(httpx.Client, "request", forbidden)
        monkeypatch.setattr(httpx.AsyncClient, "request", forbidden)
    except ImportError:
        pass

    source = """
# pwncraft: op=edit index=idx offset=off data=data
def rewrite(idx, off, data):
    io.sendline(b"2")
rewrite(1, 7, b"X")
"""
    resolution = HelperContractResolver().resolve(source)
    operations = lower_source_calls(source, resolution)
    assert operations[0].offset.value == 7
    assert evaluate_value("len(b'A' * 9 + p64(x))").value == 17
