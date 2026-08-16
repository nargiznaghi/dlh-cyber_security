#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup


def download_page(url):
    """
    Download a web page and return its formatted HTML content.

    Returns:
        - Formatted HTML content as string if successful
        - Error message string if download fails
    """
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise error for HTTP errors

        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.prettify()

    except requests.exceptions.RequestException as e:
        return str(e)
