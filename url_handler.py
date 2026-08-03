from urllib.parse import urlparse
import requests


def parse_url(user_input):
    user_input = user_input.strip()

    if not user_input:
        return None, None

    if not user_input.startswith(("http://", "https://")):
        user_input = "https://" + user_input

    parsed = urlparse(user_input)

    if not parsed.hostname:
        return None, None

    return parsed, parsed.hostname


def is_valid_hostname(hostname):
    if not hostname:
        return False

    if "." not in hostname:
        return False

    if hostname.startswith(".") or hostname.endswith("."):
        return False

    if " " in hostname:
        return False

    return True


def check_url_accessibility(hostname):
    https_url = f"https://{hostname}"
    http_url = f"http://{hostname}"

    try:
        response = requests.get(
            https_url,
            timeout=5,
            allow_redirects=True
        )

        return response.url, True

    except requests.RequestException:
        pass

    try:
        response = requests.get(
            http_url,
            timeout=5,
            allow_redirects=True
        )

        return response.url, False

    except requests.RequestException:
        return None, False
