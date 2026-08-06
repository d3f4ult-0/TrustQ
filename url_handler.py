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


def check_url_accessibility(url):
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True
        )

        redirect_chain = [
            r.url for r in response.history
        ]

        redirect_chain.append(response.url)

        return (
            response.url,
            url.startswith("https://"),
            redirect_chain
        )

    except requests.RequestException:
        pass

    if url.startswith("https://"):
        http_url = "http://" + url[8:]

        try:
            response = requests.get(
                http_url,
                timeout=5,
                allow_redirects=True
            )

            redirect_chain = [
                r.url for r in response.history
            ]

            redirect_chain.append(response.url)

            return (
                response.url,
                False,
                redirect_chain
            )

        except requests.RequestException:
            return None, False, []

    return None, False, []

def analyze_url_structure(parsed_url):
    signals = []

    hostname = parsed_url.hostname
    path = parsed_url.path
    query = parsed_url.query
    full_url = parsed_url.geturl()

    # Long URL
    if len(full_url) > 200:
        signals.append({
            "type": "long_url",
            "severity": "low",
            "message": "URL is unusually long."
        })

    # Excessive subdomains
    if hostname and hostname.count(".") >= 3:
        signals.append({
            "type": "many_subdomains",
            "severity": "low",
            "message": "URL contains multiple subdomains."
        })

    # IP address used as hostname
    if hostname:
        parts = hostname.split(".")

        if len(parts) == 4 and all(part.isdigit() for part in parts):
            signals.append({
                "type": "ip_hostname",
                "severity": "medium",
                "message": "URL uses an IP address instead of a domain name."
            })

    # Percent encoding
    if "%" in path or "%" in query:
        signals.append({
            "type": "encoded_url",
            "severity": "low",
            "message": "URL contains percent-encoded characters."
        })

    # Archive/executable extension
    suspicious_extensions = (
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".msi",
        ".apk",
        ".jar",
        ".zip",
        ".rar"
    )

    if path.lower().endswith(suspicious_extensions):
        signals.append({
            "type": "file_download",
            "severity": "low",
            "message": (
                "URL points directly to an executable "
                "or archive file."
            )
        })

    # Embedded username
    if parsed_url.username:
        signals.append({
            "type": "embedded_username",
            "severity": "high",
            "message": "URL contains an embedded username."
        })

    # Non-default port
    if parsed_url.port:
        signals.append({
            "type": "nonstandard_port",
            "severity": "medium",
            "message": (
                f"URL uses a non-default port "
                f"({parsed_url.port})."
            )
        })

    # Deep path
    path_parts = [part for part in path.split("/") if part]

    if len(path_parts) >= 6:
        signals.append({
            "type": "deep_path",
            "severity": "low",
            "message": "URL contains a deeply nested path."
        })

    # Sensitive keywords
    suspicious_keywords = (
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "password",
        "signin",
        "update",
        "confirm"
    )

    path_lower = path.lower()

    matched_keywords = [
        keyword
        for keyword in suspicious_keywords
        if keyword in path_lower
    ]

    if matched_keywords:
        signals.append({
            "type": "sensitive_keywords",
            "severity": "medium",
            "message": (
                "URL path contains sensitive-action keywords: "
                + ", ".join(matched_keywords)
            )
        })

    # Large query
    if len(query) > 300:
        signals.append({
            "type": "large_query",
            "severity": "low",
            "message": "URL contains an unusually large query string."
        })

    return signals

def analyze_redirect_chain(redirect_chain):
    signals = []

    if not redirect_chain:
        return signals

    # Number of redirects
    redirect_count = max(0, len(redirect_chain) - 1)

    if redirect_count == 0:
        return signals

    # Multiple redirects
    if redirect_count == 1:
        signals.append({
            "type": "redirect",
            "severity": "low",
            "message": "URL redirects once before reaching its destination."
        })

    elif redirect_count <= 3:
        signals.append({
            "type": "multiple_redirects",
            "severity": "medium",
            "message": (
                f"URL passes through {redirect_count} redirects "
                "before reaching its destination."
            )
        })

    else:
        signals.append({
            "type": "excessive_redirects",
            "severity": "high",
            "message": (
                f"URL passes through {redirect_count} redirects "
                "before reaching its destination."
            )
        })

    # Domain changes
    domains = []

    for url in redirect_chain:
        parsed = urlparse(url)

        if parsed.hostname:
            domains.append(parsed.hostname.lower())

    unique_domains = set(domains)

    if len(unique_domains) > 1:
        signals.append({
            "type": "cross_domain_redirect",
            "severity": "medium",
            "message": (
                f"Redirect chain crosses {len(unique_domains)} "
                "different domains."
            )
        })

    return signals