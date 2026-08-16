#!/usr/bin/env python3
import socket


def resolve_domain_to_ipv4(domain_name):
    """
    Resolve a domain name to its IPv4 address.

    Returns:
        - IPv4 address as string if successful
        - None if domain cannot be resolved (socket.gaierror)
        - Error message string for any other exception
    """
    try:
        return socket.gethostbyname(domain_name)
    except socket.gaierror:
        return None
    except Exception as e:
        return str(e)
