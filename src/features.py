"""
Lexical URL Feature Extractor for Phishing Detection
Implements the 9 URL lexical features utilized in the Diskominfo Prabumulih study:
1. NumDots
2. UrlLength
3. NumDash
4. AtSymbol
5. IpAddress
6. HttpsInHostname
7. PathLevel
8. PathLength
9. NumNumericChars
"""

import re
import urllib.parse
from typing import Dict, Any, List

# Regex patterns
IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)
IPV6_REGEX = re.compile(r'^\[?[0-9a-fA-F:]+\]?$')

FEATURE_COLUMNS = [
    'NumDots',
    'UrlLength',
    'NumDash',
    'AtSymbol',
    'IpAddress',
    'HttpsInHostname',
    'PathLevel',
    'PathLength',
    'NumNumericChars'
]


def normalize_url(url: str) -> str:
    """Normalizes URL input, prepending http:// if scheme is absent."""
    url = url.strip()
    if not url:
        return ""
    if not (url.startswith("http://") or url.startswith("https://") or url.startswith("//")):
        url = "http://" + url
    return url


def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Extracts 9 lexical URL features from a given URL string.
    Returns a dictionary of feature values.
    """
    url = raw_url.strip()
    if not url:
        raise ValueError("URL cannot be empty")

    # Add scheme if missing for accurate urlparse parsing
    parsed_candidate = url if ("://" in url or url.startswith("//")) else ("http://" + url)
    parsed = urllib.parse.urlsplit(parsed_candidate)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""

    # 1. NumDots: Number of '.' in full URL
    num_dots = url.count('.')

    # 2. UrlLength: Total character length
    url_length = len(url)

    # 3. NumDash: Number of '-' in full URL
    num_dash = url.count('-')

    # 4. AtSymbol: Presence of '@' in URL
    at_symbol = 1 if '@' in url else 0

    # 5. IpAddress: Check if hostname is an IPv4 or IPv6 address
    clean_host = hostname.strip("[]")
    is_ip = 1 if (IPV4_REGEX.match(clean_host) or (":" in clean_host and IPV6_REGEX.match(clean_host))) else 0

    # 6. HttpsInHostname: Check if 'https' appears as a deceptive token in hostname
    https_in_host = 1 if 'https' in hostname else 0

    # 7. PathLevel: Directory depth in URL path (count of non-empty '/' segments)
    path_clean = path.strip('/')
    path_level = len([p for p in path_clean.split('/') if p]) if path_clean else 0

    # 8. PathLength: Length of the path string
    path_length = len(path)

    # 9. NumNumericChars: Count of numeric digits in entire URL
    num_numeric = sum(c.isdigit() for c in url)

    return {
        'NumDots': int(num_dots),
        'UrlLength': int(url_length),
        'NumDash': int(num_dash),
        'AtSymbol': int(at_symbol),
        'IpAddress': int(is_ip),
        'HttpsInHostname': int(https_in_host),
        'PathLevel': int(path_level),
        'PathLength': int(path_length),
        'NumNumericChars': int(num_numeric)
    }


def to_feature_vector(feature_dict: Dict[str, Any]) -> List[float]:
    """Converts feature dictionary into ordered list matching model training columns."""
    return [float(feature_dict[col]) for col in FEATURE_COLUMNS]
