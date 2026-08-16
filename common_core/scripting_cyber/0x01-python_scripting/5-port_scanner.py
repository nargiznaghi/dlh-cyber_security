#!/usr/bin/env python3
import socket


def check_port(host, port):
    """
    Check if a TCP port is open on a host.

    Returns:
        True if port is open
        False if closed or unreachable
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        result = sock.connect_ex((host, port))
        sock.close()

        return result == 0

    except Exception:
        return False
