import socket

import pytest


@pytest.mark.parametrize("entrypoint", ["create_connection", "connect", "connect_ex"])
def test_network_guard_blocks_connection_entry_points(entrypoint):
    address = ("127.0.0.1", 9)
    with pytest.raises(AssertionError, match="^a test tried to use the network$"):
        if entrypoint == "create_connection":
            socket.create_connection(address)
        else:
            with socket.socket() as connection:
                getattr(connection, entrypoint)(address)
