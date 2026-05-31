#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl_website(start_url, max_depth=2, visited=None, current_depth=0):
    """
    Recursively crawl a website and return a set of visited internal URLs.
    """

    if visited is None:
        visited = set()

    # Stop if depth exceeded
    if current_depth > max_depth:
        return visited

    try:
        response = requests.get(start_url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException:
        return visited  # unreachable → return what we have

    print(f"Crawling: {start_url}")
    visited.add(start_url)

    # Parse domain of starting URL
    start_domain = urlparse(start_url).netloc

    soup = BeautifulSoup(response.text, "html.parser")

    # Extract all <a href="..."> links
    for link in soup.find_all("a", href=True):
        href = link.get("href")

        # Convert relative → absolute
        absolute_url = urljoin(start_url, href)

        # Check domain match
        if urlparse(absolute_url).netloc != start_domain:
            continue

        # Avoid revisiting
        if absolute_url not in visited:
            crawl_website(
                absolute_url,
                max_depth,
                visited,
                current_depth + 1
            )

    return visited
