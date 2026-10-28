"""Fail tests that attempt connections or address resolution. Fixtures are local."""

import socket

import pytest


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def explode(*_args, **_kwargs):
        raise AssertionError("a test tried to use the network")

    monkeypatch.setattr(socket, "getaddrinfo", explode)
    monkeypatch.setattr(socket, "create_connection", explode)
    monkeypatch.setattr(socket.socket, "connect", explode)
    monkeypatch.setattr(socket.socket, "connect_ex", explode)
