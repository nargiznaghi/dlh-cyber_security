#!/usr/bin/env python3
import requests


def get_http_headers(url):
    """
    Retrieve HTTP response headers from a website.

    Returns:
        - {'status_code': int, 'headers': dict} if successful
        - None if the request fails
    """
    try:
        response = requests.get(url)
        response.raise_for_status()

        return {
            'status_code': response.status_code,
            'headers': dict(response.headers)
        }

    except requests.exceptions.RequestException:
        return None
