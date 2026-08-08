from urllib.parse import urlparse
import requests


def parse_url(user_input):
    user_input = user_input.strip()

    if not user_input:
        return None, None

    if not user_input.startswith(("http://", "https://")):
        user_input = "https://" + user_input

    try:
        parsed = urlparse(user_input)

        if not parsed.hostname:
            return None, None

        # Validate the port.
        # Accessing parsed.port raises ValueError
        # when the port is invalid, e.g. 99999.
        port = parsed.port

    except ValueError:
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
    """
    Try to access the exact URL supplied by the user.

    If HTTPS fails, fall back to HTTP.
    Returns:
        final_url,
        https_worked,
        redirect_chain
    """

    def try_url(target_url):
        try:
            response = requests.get(
                target_url,
                timeout=5,
                allow_redirects=True
            )

            redirect_chain = [
                r.url for r in response.history
            ]

            redirect_chain.append(response.url)

            return (
                response.url,
                response.url.startswith("https://"),
                redirect_chain
            )

        except requests.RequestException:
            return None

    # ---------------------------------------------------------
    # TRY THE USER'S ORIGINAL URL
    # ---------------------------------------------------------

    result = try_url(url)

    if result:
        return result

    # ---------------------------------------------------------
    # HTTPS FAILED → TRY HTTP
    # ---------------------------------------------------------

    if url.startswith("https://"):

        http_url = "http://" + url[8:]

        result = try_url(http_url)

        if result:
            return result

    return None, False, []


def analyze_url_structure(parsed_url):
    signals = []

    hostname = parsed_url.hostname
    path = parsed_url.path
    query = parsed_url.query
    full_url = parsed_url.geturl()

    # ---------------------------------------------------------
    # LONG URL
    # ---------------------------------------------------------

    if len(full_url) > 200:
        signals.append({
            "type": "long_url",
            "severity": "low",
            "message": "URL is unusually long."
        })

    # ---------------------------------------------------------
    # EXCESSIVE SUBDOMAINS
    # ---------------------------------------------------------

    if hostname and hostname.count(".") >= 3:
        signals.append({
            "type": "many_subdomains",
            "severity": "low",
            "message": "URL contains multiple subdomains."
        })

    # ---------------------------------------------------------
    # IP ADDRESS AS HOSTNAME
    # ---------------------------------------------------------

    if hostname:
        parts = hostname.split(".")

        if (
            len(parts) == 4
            and all(part.isdigit() for part in parts)
        ):
            signals.append({
                "type": "ip_hostname",
                "severity": "medium",
                "message": (
                    "URL uses an IP address instead of a domain name."
                )
            })

    # ---------------------------------------------------------
    # PERCENT ENCODING
    # ---------------------------------------------------------

    if "%" in path or "%" in query:
        signals.append({
            "type": "encoded_url",
            "severity": "low",
            "message": "URL contains percent-encoded characters."
        })

    # ---------------------------------------------------------
    # SUSPICIOUS FILE EXTENSIONS
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # EMBEDDED USERNAME
    # ---------------------------------------------------------

    if parsed_url.username:
        signals.append({
            "type": "embedded_username",
            "severity": "high",
            "message": "URL contains an embedded username."
        })

    # ---------------------------------------------------------
    # NON-STANDARD PORT
    # ---------------------------------------------------------

    try:
        port = parsed_url.port
    except ValueError:
        port = None

    if port:
        signals.append({
            "type": "nonstandard_port",
            "severity": "medium",
            "message": (
                f"URL uses a non-default port ({port})."
            )
        })

    # ---------------------------------------------------------
    # DEEP PATH
    # ---------------------------------------------------------

    path_parts = [
        part for part in path.split("/")
        if part
    ]

    if len(path_parts) >= 6:
        signals.append({
            "type": "deep_path",
            "severity": "low",
            "message": "URL contains a deeply nested path."
        })

    # ---------------------------------------------------------
    # SENSITIVE KEYWORDS
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # LARGE QUERY STRING
    # ---------------------------------------------------------

    if len(query) > 300:
        signals.append({
            "type": "large_query",
            "severity": "low",
            "message": (
                "URL contains an unusually large query string."
            )
        })

    return signals


def analyze_redirect_chain(redirect_chain):
    signals = []

    if not redirect_chain:
        return signals

    # ---------------------------------------------------------
    # REDIRECT COUNT
    # ---------------------------------------------------------

    redirect_count = max(
        0,
        len(redirect_chain) - 1
    )

    if redirect_count == 0:
        return signals

    # ---------------------------------------------------------
    # NUMBER OF REDIRECTS
    # ---------------------------------------------------------

    if redirect_count == 1:

        signals.append({
            "type": "redirect",
            "severity": "low",
            "message": (
                "URL redirects once before reaching "
                "its destination."
            )
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

    # ---------------------------------------------------------
    # CROSS-DOMAIN REDIRECT
    # ---------------------------------------------------------

    domains = []

    for url in redirect_chain:

        parsed = urlparse(url)

        if parsed.hostname:
            domains.append(
                parsed.hostname.lower()
            )

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